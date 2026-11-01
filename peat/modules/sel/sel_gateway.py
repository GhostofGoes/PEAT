"""
Pull SEL relays that are behind a SEL RTAC, through the RTAC's engineering
access tunnels (refer to "RTAC engineering tunnels" in the SEL documentation,
``docs/sel.rst``). This is off by default.

The paths to the relays come from:

- ``sel.rtac_tunnels``: a list of paths, in the global ``device_options``, or
  in the ``options`` of the RTAC's host (where ``rtac_ip`` is the host's IP
  address by default). Each is an engineering access entry
  (refer to :meth:`~peat.modules.sel.sel_tunnel.RTACTunnel.from_dict`), or a
  string in the format of ``--rtac-tunnel``
  (:meth:`~peat.modules.sel.sel_tunnel.RTACTunnel.from_spec`).
- The ``--rtac-tunnel`` command line argument, which adds to ``sel.rtac_tunnels``.
- The RTACs that were pulled, if ``sel.rtac_pull_downstream`` is enabled for
  them: the paths their module returns from ``downstream_targets()``
  (refer to :func:`peat.api.pull_api.pull_downstream`).

:func:`pull_downstream` pulls each relay once, one at a time, with
:func:`pull_through_tunnel`. It's what
:meth:`SELRelay.pull_downstream() <peat.modules.sel.sel_relay.SELRelay.pull_downstream>`
runs for the pull's pass over the gateways.

Safety:

- An access point with a direct route (``<Device>_SEL_AP``), or a route that
  isn't known, is only used with ``sel.allow_direct_tunnels``: a direct route
  stops the RTAC's polling of the relay (SCADA has no data from it) while PEAT is
  connected. SEL server connections are interleaved.
- One session per relay: paths are pulled one at a time, a path is only used
  once, a relay that's known by name in the RTAC is only pulled through one path,
  and a relay whose serial number was already seen in the pass isn't pulled again.
- One attempt per RTAC login: if the RTAC rejects the login of the RTAC user or
  the SEL server's ``ACC`` password, the other paths to that RTAC that would use
  it aren't opened in the pass, so the RTAC doesn't lock the account.
- The configured paths (``sel.rtac_tunnels``, ``--rtac-tunnel``) are only pulled
  if the SELRelay module is selected for the pull (``-d``, all modules by default).
- Only read-only commands: the ``ID`` of the relay, then the commands of
  :class:`GatewayCommands` at access level 1 (or all of
  :class:`~peat.modules.sel.sel_more_commands.MoreCommands`, with ``2AC``, if
  ``sel.attempt_more_commands`` is enabled). No FTP or HTTP. Files are only
  downloaded (``FILE SHOW``) with ``sel.tunnel_file_transfer``.

Each relay is a new device (the "child" of the RTAC): its ID is its serial number,
IED name, or device ID, or the path (e.g. ``192.0.2.10_3254_p1``), and its files are
in the directory of that ID. It doesn't have an IP address (it's reached through
the RTAC), so it isn't merged with the RTAC. ``extra.gateway`` says how it was
reached, ``related.ip`` has the RTAC's IP address, and the RTAC's
``related.hosts`` lists the relay.
"""

from __future__ import annotations

from collections import deque
from copy import deepcopy
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from peat import CommError, DeviceData, config, datastore, log
from peat.protocols.addresses import address_to_pathname

from .sel_ascii import SELAscii
from .sel_commands import COMMANDS, SELCommandRefused
from .sel_default_creds import FAMILY_2030, configured_option
from .sel_more_commands import MoreCommands
from .sel_tunnel import RTACTunnel, SELTunnel, is_device_row, safe_id

if TYPE_CHECKING:
    from .sel_relay import SELRelay

#: Commands :class:`GatewayCommands` runs after ``ID``, ``HELP``, and ``CAS``, at
#: access level 1, followed by the ``SHO`` commands (``sel.show_settings``)
GATEWAY_COMMANDS: Final = ("sta", "ser", "his", "device_time", "active_group", "ver")

#: Options in the ``sel`` section of a RTAC's host that are about the RTAC, not
#: the relays behind it, so the relays' devices don't get them
GATEWAY_ONLY_OPTIONS: Final = ("rtac_tunnels", "rtac_pull_downstream", "rtac_tunnel_creds")


class GatewayCommands(MoreCommands):
    """
    The read-only commands PEAT runs on a relay behind a RTAC by default
    (:data:`GATEWAY_COMMANDS`, then the ``SHO`` commands), all at access level 1,
    so PEAT doesn't log in at level 2 (``2AC``, which pulses the relay's alarm)
    through the tunnel. The settings come from ``SHO``, since files aren't
    downloaded through tunnels by default.
    """

    def run(self) -> dict[str, dict]:
        if self.family == FAMILY_2030:
            # The SEL-2030/2032 command set is unchanged (it doesn't log in to level 2)
            return super().run()

        self._discover()
        for name in GATEWAY_COMMANDS:
            if self.comms.halted or self.stopped:
                break
            if name == "ser":
                self._run_events("cse", "ser")
            elif name == "his":
                self._run_history()
            else:
                self._run(COMMANDS[name])

        if not self.comms.halted and not self.stopped:
            self._run_show_settings()
        return self.outputs


@dataclass
class GatewayJob:
    """A relay to pull through a tunnel."""

    tunnel: RTACTunnel
    #: The RTAC's device, if it's known
    gateway: DeviceData | None
    #: Configured by the user (``sel.rtac_tunnels`` or ``--rtac-tunnel``)
    explicit: bool


def _safe_entry(entry: Any) -> Any:
    """An entry for messages, without its passwords."""
    if isinstance(entry, dict) and "creds" in entry:
        return {**entry, "creds": "<redacted>"}
    return entry


def _configured_entries() -> list[tuple[Any, DeviceData | None]]:
    """The entries of ``sel.rtac_tunnels``, with the host they're configured for."""
    entries: list[tuple[Any, DeviceData | None]] = []

    def _listed(value: Any) -> list:
        # A single path (e.g. a string) is a list of one path
        if not value:
            return []
        return list(value) if isinstance(value, list | tuple) else [value]

    global_sel = datastore.global_options.get("sel") or {}
    for entry in _listed(global_sel.get("rtac_tunnels")):
        entries.append((entry, None))

    for dev in datastore.objects:
        if "gateway" in dev.extra:
            # A relay behind a RTAC (refer to new_child), not a host of the configuration
            continue
        host_sel = dev._host_option_overrides.get("sel") or {}
        for entry in _listed(host_sel.get("rtac_tunnels")):
            entries.append((entry, dev))

    return entries


def configured_tunnels() -> list[tuple[RTACTunnel, DeviceData | None]]:
    """
    The paths in ``sel.rtac_tunnels`` (and from ``--rtac-tunnel``): from the global
    options, and from the options of hosts in the configuration file, where
    ``rtac_ip`` is the host's IP address by default.

    Returns:
        The paths, and the RTAC's device, if it's known
    """
    tunnels = []
    for entry, host in _configured_entries():
        try:
            tunnel = RTACTunnel.coerce(
                entry, default_rtac_ip=host.ip if host is not None else "", source="config"
            )
        except (ValueError, TypeError) as ex:
            log.error(f"Invalid 'sel.rtac_tunnels' entry {_safe_entry(entry)!r}: {ex}")
            continue

        gateway = host
        if gateway is None or (gateway.ip and gateway.ip != tunnel.rtac_ip):
            gateway = datastore.search(tunnel.rtac_ip, "ip")
        tunnels.append((tunnel, gateway))

    return tunnels


def _gateway_option(gateway: DeviceData | None, key: str) -> Any:
    options = gateway.options if gateway is not None else datastore.device_options
    return options["sel"][key]


def plan_jobs(
    gateway_targets: list[tuple[DeviceData, list[dict]]],
    include_configured: bool = True,
) -> list[GatewayJob]:
    """
    The relays to pull: the configured paths (:func:`configured_tunnels`), and
    the paths of the gateways that were pulled (``downstream_targets()``) whose
    ``sel.rtac_pull_downstream`` option is enabled. Each path is used once, and
    each relay that's known by name in the RTAC only through one path:
    configured paths first, then paths that aren't direct.

    Args:
        gateway_targets: The devices that were pulled, with their ``downstream_targets()``
        include_configured: Use the configured paths. They're only used if the
            module of SEL relays was selected for the pull (refer to
            :func:`peat.api.pull_api.pull_downstream`).
    """
    jobs = []
    if include_configured:
        jobs = [GatewayJob(t, gw, explicit=True) for t, gw in configured_tunnels()]
    elif configured := _configured_entries():
        log.info(
            f"Not pulling the {len(configured)} paths in 'sel.rtac_tunnels' (or "
            f"--rtac-tunnel): the SELRelay module isn't selected for this pull "
            f"(add 'selrelay' to -d)"
        )

    for gateway, targets in gateway_targets:
        if not targets:
            continue
        if not _gateway_option(gateway, "rtac_pull_downstream"):
            log.info(
                f"{gateway.get_id()} has {len(targets)} engineering access paths to "
                f"other devices. Enable 'sel.rtac_pull_downstream' to pull the relays "
                f"behind it (refer to 'RTAC engineering tunnels' in the SEL docs)."
            )
            continue
        for target in targets:
            try:
                tunnel = RTACTunnel.coerce(
                    target, default_rtac_ip=gateway.ip or "", source="discovered"
                )
            except (ValueError, TypeError) as ex:
                log.warning(
                    f"Ignoring a path of {gateway.get_id()} ({_safe_entry(target)!r}): {ex}"
                )
                continue
            jobs.append(GatewayJob(tunnel, gateway, explicit=False))

    # Prefer what the user configured, then paths that aren't direct (stable sort)
    jobs.sort(key=lambda job: (not job.explicit, job.tunnel.may_be_direct))

    planned: list[GatewayJob] = []
    paths: set[tuple] = set()
    devices: set[tuple[str, str]] = set()
    for job in jobs:
        tunnel = job.tunnel
        if tunnel.path_key in paths:
            continue
        device_key = None
        if tunnel.device_name:
            device_key = (tunnel.rtac_ip.lower(), tunnel.device_name.lower())
            if device_key in devices:
                log.info(
                    f"'{tunnel.device_name}' is already pulled through another path, "
                    f"not through {tunnel.describe()} (one session per device)"
                )
                continue
        paths.add(tunnel.path_key)
        if device_key:
            devices.add(device_key)
        planned.append(job)

    return planned


def new_child(
    module: type[SELRelay], tunnel: RTACTunnel, gateway: DeviceData | None
) -> DeviceData:
    """
    The device of a relay behind a RTAC (not added to the datastore yet). It
    uses the options of the RTAC's host (e.g. ``sel.creds`` or ``telnet.timeout``),
    without the ones that are about the RTAC (:data:`GATEWAY_ONLY_OPTIONS`, and
    the RTAC's ``web`` login), and the path's passwords (``creds``).
    """
    child = DeviceData(id=tunnel.target_id)
    child._module = module
    if gateway is not None and gateway._host_option_overrides:
        overrides = deepcopy(gateway._host_option_overrides)
        overrides.pop("web", None)
        if isinstance(overrides.get("sel"), dict):
            for key in GATEWAY_ONLY_OPTIONS:
                overrides["sel"].pop(key, None)
        child._host_option_overrides.update(overrides)
    if tunnel.creds:
        child._runtime_options.setdefault("sel", {})["creds"] = dict(tunnel.creds)
    if config.DEVICE_DIR:
        child._out_dir = config.DEVICE_DIR / address_to_pathname(tunnel.target_id)
    return child


def rtac_credentials(gateway: DeviceData | None) -> dict[str, str]:
    """
    The RTAC user's name and password (``user``, ``pass``) and the SEL server's
    ``ACC`` password (``acc``): ``sel.rtac_tunnel_creds`` (of the RTAC's device,
    or the global options), or the ``web.user`` and ``web.pass`` of the RTAC's
    host options (RTAC users are the same for the web interface and engineering
    access). Nothing is guessed.
    """
    options_dev = gateway if gateway is not None else DeviceData()
    creds = dict(configured_option(options_dev, "sel", "rtac_tunnel_creds") or {})
    if gateway is not None and not (creds.get("user") and creds.get("pass")):
        web = gateway._host_option_overrides.get("web") or {}
        if web.get("user") and web.get("pass"):
            creds["user"], creds["pass"] = web["user"], web["pass"]
    return {k: str(v) for k, v in creds.items() if k in ("user", "pass", "acc") and v}


def _tunnel_refusal(tunnel: RTACTunnel, child: DeviceData) -> str:
    if tunnel.may_be_direct and not child.options["sel"]["allow_direct_tunnels"]:
        route = "is direct" if tunnel.route == "direct" else "isn't known, so it may be direct"
        return (
            f"its route {route}. A direct route (<Device>_SEL_AP) stops the RTAC's "
            f"polling of the device (SCADA has no data from it) while PEAT is "
            f"connected. Set the route to 'interleaved' if it's a _TAP route, or "
            f"enable 'sel.allow_direct_tunnels'"
        )
    return ""


def _session_options(
    module: type[SELRelay], child: DeviceData, gateway: DeviceData | None
) -> dict:
    return {
        "timeout": float(child.options["telnet"]["timeout"]),
        "rtac_creds": rtac_credentials(gateway),
        "allow_file_transfer": bool(child.options["sel"]["tunnel_file_transfer"]),
        **module._ascii_options(child),
    }


def _rejected_login(tunnel: RTACTunnel, options: dict) -> bool:
    """If the RTAC rejected a login this path would use (refer to SELTunnel.rejected_login)."""
    rejected = SELTunnel.rejected_login(tunnel, options["rtac_creds"])
    if rejected:
        log.warning(
            f"Not connecting to {tunnel.describe()}: the RTAC rejected {rejected} "
            f"through another path, and PEAT doesn't try it again (a RTAC may lock "
            f"the account after failed logins). Fix sel.rtac_tunnel_creds."
        )
    return bool(rejected)


def expand_sel_server(module: type[SELRelay], job: GatewayJob) -> list[GatewayJob]:
    """
    The devices of a SEL server path without a port (``PORT n``), from ``WHO``
    (only devices, not servers). If the path has a ``device_name``, only that device.
    """
    tunnel = job.tunnel
    child = new_child(module, tunnel, job.gateway)
    options = _session_options(module, child, job.gateway)
    if _rejected_login(tunnel, options):
        return []
    log.info(f"Listing the devices of {tunnel.describe()} (WHO)")
    try:
        with SELTunnel(tunnel, enter_device=False, **options) as session:
            session.connect()
            rows = session.who_rows
    except (CommError, SELCommandRefused, OSError, EOFError) as ex:
        log.error(f"Failed to list the devices of {tunnel.describe()}: {ex}")
        return []

    rows = [row for row in rows if is_device_row(row)]
    if tunnel.device_name:
        rows = [row for row in rows if row["device"].lower() == tunnel.device_name.lower()]
    if not rows:
        log.warning(f"WHO on {tunnel.describe()} doesn't list any devices to pull")

    return [
        GatewayJob(tunnel.with_port(row["port"], row["device"]), job.gateway, job.explicit)
        for row in rows
    ]


def child_id(child: DeviceData, tunnel: RTACTunnel, taken: set[str]) -> str:
    """
    ID of a relay behind a RTAC: its serial number, IEC 61850 IED name (``iedName``),
    or device ID (``DEVID``), if it isn't used by another device, otherwise the path
    (e.g. ``192.0.2.10_3254_p1``). It has no ``:``.
    """
    for value in (child.serial_number, child.extra.get("iedName"), child.extra.get("DEVID")):
        ident = safe_id(str(value)) if value else ""
        if ident and ident not in taken and datastore.search(ident, "id") is None:
            return ident
    return tunnel.target_id


def _register_child(
    module: type[SELRelay],
    child: DeviceData,
    child_ident: str,
    tunnel: RTACTunnel,
    gateway: DeviceData | None,
    session: SELTunnel,
    status: str,
) -> None:
    # The relay's settings can have its own IP address (e.g. IPADDR of an
    # Ethernet port, from SHO P), which DeviceData uses as the address of the
    # device, and as its ID. PEAT doesn't reach the relay at that address, and
    # relays behind different RTACs often have the same addresses, so it's only
    # kept in the relay's interfaces and related.ip (and the device isn't merged
    # with other devices that have that address).
    if child.ip:
        log.debug(
            f"'{child_ident}' has the IP address {child.ip} in its settings, which "
            f"isn't used as its address (it's reached through the RTAC)"
        )
        child.ip = ""
    child.id = child_ident

    gateway_info = tunnel.gateway_info()
    gateway_info["pull_status"] = status
    if session.session_info:
        gateway_info["session"] = deepcopy(session.session_info)
    child.extra["gateway"] = gateway_info

    child._is_active = True
    child._is_verified = True
    child._module = module
    if tunnel.rtac_ip_is_ip:
        child.related.ip.add(tunnel.rtac_ip)
    if gateway is not None:
        gateway.related.hosts.add(child.id)
        if child.name:
            gateway.related.hosts.add(child.name)

    module.update_dev(child)
    child.purge_duplicates(force=True)
    if not any(obj is child for obj in datastore.objects):
        datastore.objects.append(child)


def pull_through_tunnel(
    module: type[SELRelay],
    tunnel: RTACTunnel,
    gateway: DeviceData | None = None,
    seen: dict[str, str] | None = None,
) -> DeviceData | None:
    """
    Pull a relay through one tunnel (refer to the module docstring).

    Args:
        module: :class:`~peat.modules.sel.sel_relay.SELRelay`
        tunnel: The path
        gateway: The RTAC's device, if it's known
        seen: Serial numbers of the relays pulled before in this pass (and their IDs)

    Returns:
        The relay's device (added to the datastore), or :obj:`None` if the relay
        wasn't pulled (it isn't allowed, the RTAC rejected the login before, the
        tunnel or ``ID`` failed, or the relay was already pulled through another path)
    """
    if seen is None:
        seen = {}

    child = new_child(module, tunnel, gateway)
    refusal = _tunnel_refusal(tunnel, child)
    if refusal:
        log.warning(f"Not pulling through {tunnel.describe()}: {refusal}")
        return None
    options = _session_options(module, child, gateway)
    if _rejected_login(tunnel, options):
        return None

    # As at the start of other pulls (refer to SELRelay._forget_ascii_passwords)
    SELAscii.forget_passwords(tunnel.target_id)
    SELAscii.forget_unsupported_commands(tunnel.target_id)

    identified = False
    status = "failed"
    child_ident = tunnel.target_id
    session: SELTunnel | None = None
    try:
        # The output is saved to the child once it's identified (refer to SELTunnel)
        with SELTunnel(tunnel, **options) as session:
            session.connect()

            module._prepare_ascii(child, session)
            if not module._selascii_get_id(child, session):
                log.error(f"No SEL relay found through {tunnel.describe()} (no FID from 'ID')")
            elif child.serial_number and str(child.serial_number) in seen:
                log.warning(
                    f"{tunnel.describe()} reaches {seen[str(child.serial_number)]} again "
                    f"(the same serial number), not pulling it twice"
                )
            else:
                child_ident = child_id(child, tunnel, set(seen.values()))
                child.id = child_ident
                if config.DEVICE_DIR:
                    child._out_dir = config.DEVICE_DIR / address_to_pathname(child.id)
                seen[str(child.serial_number or f"path:{tunnel.target_id}")] = child.id
                session.output_dev = child
                identified = True
                log.info(
                    f"Found {child.description.model or 'a SEL device'} '{child.id}' "
                    f"through {tunnel.describe()}"
                )
                status = _collect(module, child, session, tunnel)
    except (CommError, SELCommandRefused, OSError, EOFError) as ex:
        log.error(f"Failed to pull through {tunnel.describe()}: {ex}")
        if identified:
            status = "incomplete"

    if not identified or session is None:
        return None

    _register_child(module, child, child_ident, tunnel, gateway, session, status)
    if status != "successful":
        log.error(f"The pull of '{child.id}' through {tunnel.describe()} was {status}")
    return child


def _collect(
    module: type[SELRelay], child: DeviceData, session: SELTunnel, tunnel: RTACTunnel
) -> str:
    """
    Log in to level 1 and run the commands (and download files, if allowed).

    Returns:
        ``successful``, ``incomplete``, or ``login failed``
    """
    module._prepare_ascii(child, session)
    if not session.elevate(1, module._configured_ascii_creds(child)):
        log.error(f"Failed to log in to '{child.id}' through {tunnel.describe()}")
        return "login failed"
    child.related.user.update(session.successful_usernames)

    collector = MoreCommands if child.options["sel"]["attempt_more_commands"] else GatewayCommands
    successful = module.pull_more_commands(child, session, collector_cls=collector)

    if session.allow_file_transfer and not session.halted:
        if not module.pull_configs(child, session):
            log.warning(f"There were issues downloading files from '{child.id}'")
            successful = False

    module._use_show_settings(child)
    return "successful" if successful else "incomplete"


def pull_downstream(
    module: type[SELRelay],
    gateway_targets: list[tuple[DeviceData, list[dict]]],
    include_configured: bool = True,
) -> list[DeviceData]:
    """
    Pull the relays behind RTACs (refer to the module docstring and
    :func:`peat.api.pull_api.pull_downstream`).

    A login that a RTAC rejects (the RTAC user, or the SEL server's ``ACC``
    password) isn't tried again during the pass: the other paths to that RTAC
    that would use it are skipped
    (:meth:`~peat.modules.sel.sel_tunnel.SELTunnel.rejected_login`).

    Args:
        module: :class:`~peat.modules.sel.sel_relay.SELRelay`
        gateway_targets: The devices that were pulled, with their
            ``downstream_targets()`` (the devices behind them)
        include_configured: Pull the configured paths (``sel.rtac_tunnels`` and
            ``--rtac-tunnel``), refer to :func:`plan_jobs`

    Returns:
        The devices of the relays that were pulled
    """
    queue = deque(plan_jobs(gateway_targets, include_configured=include_configured))
    if not queue:
        return []

    # One attempt per login and RTAC in each pass
    SELTunnel.forget_rejected_logins()

    log.info(f"Pulling relays through {len(queue)} RTAC engineering access paths")
    planned = {job.tunnel.path_key for job in queue}
    seen: dict[str, str] = {}
    children: list[DeviceData] = []

    while queue:
        job = queue.popleft()
        tunnel = job.tunnel

        if tunnel.kind == "sel_server" and tunnel.sel_port is None:
            expanded = []
            for new in expand_sel_server(module, job):
                if new.tunnel.path_key not in planned:
                    planned.add(new.tunnel.path_key)
                    expanded.append(new)
            queue.extendleft(reversed(expanded))
            continue

        try:
            child = pull_through_tunnel(module, tunnel, job.gateway, seen)
        except Exception:
            log.exception(f"Unexpected error while pulling through {tunnel.describe()}")
            child = None
        if child is not None:
            children.append(child)

    log.info(f"Pulled {len(children)} relays through RTAC engineering access tunnels")
    return children


__all__ = [
    "GATEWAY_COMMANDS",
    "GATEWAY_ONLY_OPTIONS",
    "GatewayCommands",
    "GatewayJob",
    "child_id",
    "configured_tunnels",
    "expand_sel_server",
    "new_child",
    "plan_jobs",
    "pull_downstream",
    "pull_through_tunnel",
    "rtac_credentials",
]
