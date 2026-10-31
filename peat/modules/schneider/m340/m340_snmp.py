"""
SNMP data collection for Modicon M340 PLCs, using Schneider Electric's
Transparent Ready private :term:`MIB` (``TFPRIVATE-MIB``).

The M340 CPU Ethernet ports and the BMX NOE/NOC Ethernet modules run a
SNMP agent implementing the standard ``SNMPv2-MIB`` (``system``) and
``IF-MIB`` (``ifTable``) MIBs, and Schneider's "Transparent Factory Ethernet"
private MIB, under ``1.3.6.1.4.1.3833.1`` (``schneiderelectric``,
IANA Private Enterprise Number 3833). PEAT walks these subtrees, resolves
the responses using the MIBs (proper data types, enumeration labels and
decoded table indices) and structures them into scalars and table rows.

**MIB provenance**

``peat/modules/schneider/mibs/TFPRIVATE-MIB.py`` was compiled with ``pysmi``
from Schneider Electric's ``SchneiderTFE_V03.01.mib`` ("Transparent Ready
PRIVATE MIB Release 03.01"), which is in the "MIB Files" archive Schneider
publishes on se.com (document reference ``MIB_Modicon_Switch``). It was compiled
without the MIB's DESCRIPTION texts, so it only contains the object names, OIDs,
types and enumerations. The ``.mib`` file itself is not included with PEAT.
Release 03.01 is a superset of release 01.04 (``SchneiderTFE-V01-04.mib``),
which is the version M340 agents report in ``tfeMibVersionNumber``, for the
groups used by PEAT. The ``tfProducts`` subtree (``sysObjectID`` values) was
moved out of the MIB in release 03.00, those values are in :data:`TF_PRODUCTS`.

**Data collected**

- ``SNMPv2-MIB::system``, ``IF-MIB::ifTable`` and ``RFC1213-MIB::ipAddrTable``
- TFE ``equipmentProfile`` (product, version, slot, IP configuration, MAC,
  LED table, trap receivers table), and ``tfeMibVersion``
- TFE service groups, if the agent advertises them in
  ``profileCommunicationServices``: ``port502Messaging`` (incl. the connection
  and IP security tables), ``ioScanning`` (incl. the scanned devices table),
  ``globalData`` (publication and subscription tables), ``web``,
  ``addressServer``, ``timeManagement`` (NTP) and ``email`` (SMTP)

**Where the data goes**

- ``sysUpTime``, ``sysContact``, ``sysName``, ``sysLocation`` and ``sysDescr``
  => ``uptime``, ``description.contact_info``, ``name``, ``geo.name`` and
  ``description.description`` (name and descriptions only if not already set)
- ``profileSlot``, ``profileProductName``, ``profileVersion``,
  ``profileMacAddress``, ``profileIpAddress``, ``profileGlobalStatus`` and the
  LED table => the ``module`` in that slot (``description.product``,
  ``firmware.version``, ``mac``, ``ip``, ``status`` and ``extra.leds``)
- ``ifTable``, ``ipAddrTable`` and ``profileIpGateway`` => ``interface``
  (one per ``ifTable`` row, with ``id`` set to the ``ifIndex``: name, type,
  MTU, speed in Mbps, MAC, enabled, connected, uptime, IP, subnet mask and
  gateway). Loopback interfaces are not stored.
- ``port502Status``, ``webStatus``, ``addressServerStatus``, ``ntpStatus``
  and ``smtpStatus`` => ``service``: ``modbus_tcp`` (502), ``http`` (80),
  ``dhcp`` (67, role ``server``), ``ntp`` (role ``client``) and ``smtp``
  (role ``client``). Services are only stored if the agent reports them.
  A ``snmp`` service (status ``verified``) is also stored.
- Remote addresses in the I/O scanning, Port 502 connection and IP security,
  Global Data and trap receiver tables, ``ntpSrvAddr`` and ``smtpSrvAddr``
  => ``related.ip``
- Everything => ``extra.snmp`` (structured, using MIB object names),
  ``extra.module_<slot>`` (legacy format) and ``raw-snmp-output.json``
  (every SNMP response)

.. warning::
   The SNMP agent of M340 CPUs with firmware older than V3.40 and of BMX NOE
   modules is affected by CVE-2022-0222 (SEVD-2022-102-02), a denial of
   service of the Ethernet interface triggered by a specific SNMP request.
   PEAT only sends standard read-only Get/GetNext requests, but walking the
   MIBs sends a few hundred requests. Set the ``m340.use_snmp`` device option to
   ``false`` to not send any SNMP requests to M340 devices (neither the SNMP
   identification method of scans nor the SNMP pull), and
   ``m340.snmp_max_varbinds`` to limit the number of requests per walked
   subtree. If the agent stops responding part way through, the remaining
   subtrees aren't walked.

.. note::
   ``profileTrapTable.trapCommunityName`` is a SNMP community string (a
   credential), which will be included in the results.

Authors

- Christopher Goes
"""

import ipaddress
from datetime import timedelta
from pathlib import Path
from typing import Any, Final

from peat import CommError, DeviceData, Interface, PeatError, Service
from peat import log as peat_logger
from peat.data.validators import validate_ip, validate_mac
from peat.protocols.snmp import SNMP, group_table_rows, normalize_iftype

#: Directory with the compiled vendor MIB modules (``TFPRIVATE-MIB.py``)
SCHNEIDER_MIBS_DIR: Final[Path] = (Path(__file__).parent.parent / "mibs").resolve()

#: Name of the Schneider Transparent Factory Ethernet private MIB module
TFE_MIB: Final[str] = "TFPRIVATE-MIB"

#: OID of ``transparentFactoryEthernet``
TFE_ROOT: Final[str] = "1.3.6.1.4.1.3833.1"

#: Standard MIBs used, from PySNMP or ``peat/protocols/mibs``.
#: ``RFC1213-MIB`` (from PySNMP) is only needed for ``ipAddrTable``: the objects it
#: shares with ``SNMPv2-MIB`` and ``IF-MIB`` resolve to those newer MIBs.
STANDARD_MIBS: Final[tuple[str, ...]] = ("SNMPv2-MIB", "IF-MIB", "RFC1213-MIB")

#: Default maximum number of GetNext requests per walked subtree
DEFAULT_MAX_VARBINDS: Final[int] = 1000

#: TFE groups that are walked: (output key, OID arc under :data:`TFE_ROOT`,
#: bit in ``profileCommunicationServices``, or :obj:`None` to always walk).
#: The MIB defines the bits as "b0=1 if Port502Messaging ... b6=1 if email".
TFE_GROUPS: Final[tuple[tuple[str, str, int | None], ...]] = (
    ("equipment_profile", "7", None),
    ("port502_messaging", "2", 0),
    ("io_scanning", "3", 1),
    ("global_data", "4", 2),
    ("web", "5", 3),
    ("address_server", "6", 4),
    ("time_management", "8", 5),
    ("email", "9", 6),
    ("tfe_mib_version", "255", None),
)

#: ``sysObjectID`` values under ``equipmentProfile.tfProducts``
#: (``1.3.6.1.4.1.3833.1.7.255``). From the TFE MIB OID tree in the
#: Control Expert online help and the TFE MIB revision history.
TF_PRODUCTS: Final[dict[int, str]] = {
    1: "ety",
    2: "noe",
    3: "etz",
    4: "momentumIo",
    5: "momentumM1e",
    6: "altivar",
    7: "stbNip",
    8: "tsxntp",
    9: "nwm",
    10: "wmy",
    11: "quantumPLC",
    12: "premiumPLC",
    13: "etg",
    14: "egx",
    15: "ecc",
    16: "cev",
    17: "inducteIXGKS",
    18: "ositrackTAP",
    19: "twidoPLC",
    20: "modiconM340PLC",
    21: "modiconM340DPLC",
    22: "modiconM340CPLC",
    23: "modiconM340NOE",
    30: "lexiumIntegrated",
    31: "lexium32",
    32: "prm",
    33: "ace",
    34: "eci",
    35: "m340NOC",
}
TF_PRODUCTS_OID: Final[str] = f"{TFE_ROOT}.7.255"

SYSTEM_OID: Final[str] = "1.3.6.1.2.1.1"  # SNMPv2-MIB::system
IF_TABLE_OID: Final[str] = "1.3.6.1.2.1.2.2"  # IF-MIB::ifTable
IP_ADDR_TABLE_OID: Final[str] = "1.3.6.1.2.1.4.20"  # RFC1213-MIB::ipAddrTable

# TFE status labels meaning a service is running
_RUNNING: Final[str] = "operationnal"  # NOTE: Schneider's spelling


class TfeMibUnavailableError(PeatError):
    """
    ``TFPRIVATE-MIB`` couldn't be loaded, so use the raw-OID fallback instead.
    """


def decode_comm_services(bitmask: int) -> dict[str, bool]:
    """
    Decode ``profileCommunicationServices``, a bitmask of the services
    the agent supports. Bit 0 (the least significant bit) is
    ``port502Messaging``, and so on to bit 6, ``email``.

    .. code-block:: python

       >>> services = decode_comm_services(0b1000001)
       >>> [name for name, supported in services.items() if supported]
       ['port502_messaging', 'email']
    """
    return {key: bool(bitmask >> bit & 1) for key, _, bit in TFE_GROUPS if bit is not None}


def structure_scalars_and_tables(values: list[dict]) -> dict:
    """
    Structure MIB-resolved values from a walk.

    Returns:
        :class:`dict` with scalars as ``{object_name: value}``, tables as
        ``{table_name: [rows]}`` (refer to :func:`~peat.protocols.snmp.group_table_rows`)
        and values that couldn't be resolved using a MIB as ``{"unknown": {oid: value}}``.
    """
    out: dict = {}

    for val in values:
        if val.get("node_type") == "MibScalar" and val.get("object_name"):
            out[val["object_name"]] = val.get("value")
        elif val.get("node_type") != "MibTableColumn":
            out.setdefault("unknown", {})[val["oid"]] = val.get("value")

    out.update(group_table_rows(values))

    return out


def _advertised(services: Any, bit: int | None) -> bool:
    """If the agent's ``profileCommunicationServices`` doesn't rule out a TFE group."""
    return bit is None or not isinstance(services, int) or bool(services >> bit & 1)


def pull_snmp(
    ip: str,
    port: int = 161,
    timeout: float = 1.0,
    community: str = "public",
    max_varbinds: int = DEFAULT_MAX_VARBINDS,
) -> dict:
    """
    Walk the standard and Schneider TFE MIB subtrees of a M340 SNMP agent.

    Args:
        ip: IPv4 address of the device
        port: UDP port of the SNMP agent
        timeout: SNMP timeout, in seconds
        community: SNMP community string to use
        max_varbinds: Maximum number of GetNext requests per walked subtree

    If the agent stops responding part way through (e.g. its SNMP stack hangs),
    the remaining subtrees aren't walked, to avoid waiting for a timeout for each
    of them. The data retrieved before the timeout is returned, with the
    ``incomplete`` key set.

    Returns:
        The structured SNMP data. Keys: ``port``, ``mibs_loaded``,
        ``system``, ``product`` (if known), ``tfe`` (by group, refer to
        :data:`TFE_GROUPS`), ``interfaces`` (``ifTable`` rows),
        ``ip_addresses`` (``ipAddrTable`` rows) and, if the agent stopped
        responding, ``incomplete`` (``timed_out_walking``: the subtree being
        walked, ``skipped``: the subtrees that weren't walked).

    Raises:
        TfeMibUnavailableError: ``TFPRIVATE-MIB`` couldn't be loaded
        CommError: The SNMP agent didn't respond
    """
    log = peat_logger.bind(target=f"{ip}:{port}")
    max_varbinds = max(1, int(max_varbinds))

    snmp = SNMP(
        ip=ip,
        port=port,
        timeout=timeout,
        community=community,
        mib_paths=[SCHNEIDER_MIBS_DIR],
    )

    loaded = snmp.load_mibs(*STANDARD_MIBS, TFE_MIB)
    if TFE_MIB not in loaded:
        raise TfeMibUnavailableError(f"{TFE_MIB} couldn't be loaded from {SCHNEIDER_MIBS_DIR}")

    log.info(f"Pulling SNMP data from {ip}:{port} using {', '.join(loaded)}")

    # Fail fast if the agent doesn't respond (SNMP disabled or wrong community)
    system_values = snmp.walk(SYSTEM_OID, max_varbinds=min(max_varbinds, 64))
    if not system_values:
        raise CommError(f"No SNMP response from {ip}:{port}")

    data: dict[str, Any] = {
        "port": port,
        "mibs_loaded": loaded,
        "system": structure_scalars_and_tables(system_values),
        "tfe": {},
    }

    sys_oid = str(data["system"].get("sysObjectID") or "")
    if sys_oid.startswith(f"{TF_PRODUCTS_OID}."):
        product_id = sys_oid[len(TF_PRODUCTS_OID) + 1 :]
        if product_id.isdigit() and int(product_id) in TF_PRODUCTS:
            data["product"] = TF_PRODUCTS[int(product_id)]

    data["interfaces"] = []
    data["ip_addresses"] = []

    # Subtrees to walk after "system": (key, OID, profileCommunicationServices bit)
    subtrees: list[tuple[str, str, int | None]] = [
        (key, f"{TFE_ROOT}.{arc}", bit) for key, arc, bit in TFE_GROUPS
    ]
    subtrees += [("interfaces", IF_TABLE_OID, None), ("ip_addresses", IP_ADDR_TABLE_OID, None)]

    services = None  # profileCommunicationServices
    timed_out_walking = "system" if snmp.timed_out else ""
    skipped: list[str] = []
    for position, (key, oid, bit) in enumerate(subtrees):
        if timed_out_walking:
            # Don't wait for a timeout for each of the remaining subtrees
            skipped = [name for name, _, b in subtrees[position:] if _advertised(services, b)]
            break

        if not _advertised(services, bit):
            log.trace(f"Skipping TFE group '{key}' (not in profileCommunicationServices)")
            continue

        if key in ("interfaces", "ip_addresses"):
            data[key] = snmp.get_table(oid, max_varbinds=max_varbinds)
        elif walked := snmp.walk(oid, max_varbinds=max_varbinds):
            data["tfe"][key] = structure_scalars_and_tables(walked)

            if key == "equipment_profile":
                services = data["tfe"][key].get("profileCommunicationServices")
                if isinstance(services, int):
                    data["tfe"][key]["communication_services"] = decode_comm_services(services)

        if snmp.timed_out:
            timed_out_walking = key

    if timed_out_walking:
        log.warning(
            f"SNMP agent at {ip}:{port} stopped responding while walking "
            f"'{timed_out_walking}', the SNMP data is incomplete "
            f"(not walked: {', '.join(skipped) or 'none'})"
        )
        data["incomplete"] = {"timed_out_walking": timed_out_walking, "skipped": skipped}

    log.debug(f"Finished pulling SNMP data from {ip}:{port} (groups: {list(data['tfe'])})")

    return data


def apply_to_dev(dev: DeviceData, data: dict) -> None:
    """
    Populate a :class:`~peat.data.models.DeviceData` with the data from :func:`pull_snmp`.

    Refer to the table in the module documentation for what goes where.
    The full data is saved in ``dev.extra["snmp"]``.
    """
    system = data.get("system", {})
    tfe = data.get("tfe", {})
    profile = tfe.get("equipment_profile", {})

    # SNMPv2-MIB::system
    sys_uptime = system.get("sysUpTime")
    if isinstance(sys_uptime, int) and sys_uptime >= 0:
        dev.uptime = timedelta(seconds=sys_uptime / 100)  # TimeTicks = 1/100th second
    if _text(system.get("sysContact")) and not dev.description.contact_info:
        dev.description.contact_info = _text(system["sysContact"])
    if _text(system.get("sysName")) and not dev.name:
        dev.name = _text(system["sysName"])
    if _text(system.get("sysLocation")):
        dev.geo.name = _text(system["sysLocation"])
    if _text(system.get("sysDescr")) and not dev.description.description:
        dev.description.description = _text(system["sysDescr"])

    # Module hosting the SNMP agent (CPU Ethernet port or BMX NOE/NOC module)
    # This is merged by slot with the modules parsed from the project file.
    if isinstance(profile.get("profileSlot"), int):
        _store_module(dev, profile)

    profile_mac = _mac(profile.get("profileMacAddress"))
    if profile_mac:
        dev.related.mac.add(profile_mac)

    _store_interfaces(dev, data, profile)

    # Services
    iface_lookup = {"ip": dev.ip} if dev.ip else None
    dev.store(
        "service",
        Service(
            protocol="snmp",
            port=data["port"] if isinstance(data.get("port"), int) else 161,
            transport="udp",
            status="verified",
            enabled=True,
        ),
        interface_lookup=iface_lookup,
    )
    for key, status_key, svc in [
        ("port502_messaging", "port502Status", Service(protocol="modbus_tcp", port=502)),
        ("web", "webStatus", Service(protocol="http", port=80)),
        (
            "address_server",
            "addressServerStatus",
            Service(protocol="dhcp", port=67, transport="udp", role="server"),
        ),
        ("time_management", "ntpStatus", Service(protocol="ntp", transport="udp", role="client")),
    ]:
        group = tfe.get(key)
        if not group or status_key not in group:
            continue  # Don't report services the agent didn't tell us about
        svc.enabled = bool(group[status_key] == _RUNNING)
        svc.extra = _scalars(group)
        dev.store("service", svc, interface_lookup=iface_lookup)

    email_rows = tfe.get("email", {}).get("emailTable", [])
    if email_rows and "smtpStatus" in email_rows[0]:
        svc = Service(
            protocol="smtp",
            role="client",
            enabled=bool(email_rows[0]["smtpStatus"] == _RUNNING),
            extra=_scalars(email_rows[0]),
        )
        dev.store("service", svc, interface_lookup=iface_lookup)

    for peer_ip in _peer_ips(tfe, own_ip=dev.ip):
        dev.related.ip.add(peer_ip)

    dev.extra["snmp"] = data


def to_legacy(data: dict) -> tuple[dict, dict]:
    """
    Convert data from :func:`pull_snmp` to the format of the data returned by
    :func:`~peat.modules.schneider.m340.m340_pull._get_snmp_metadata`, which
    is stored in ``dev.extra`` (``module_<slot>`` and top-level keys) and
    used to merge with the module information pulled via FTP.

    Values that weren't retrieved are omitted.

    Returns:
        Info for the module hosting SNMP and the overall system, respectively
    """
    system = data.get("system", {})
    tfe = data.get("tfe", {})
    profile = tfe.get("equipment_profile", {})
    module_info: dict[str, Any] = {}
    system_info: dict[str, Any] = {}

    def _put(dest: dict, key: str, value: Any) -> None:
        if value is not None and value != "":
            dest[key] = value

    _put(module_info, "slot", profile.get("profileSlot"))
    _put(module_info, "model_name", _text(profile.get("profileProductName")))
    _put(module_info, "module_description", _text(system.get("sysDescr")))
    _put(module_info, "module_status", profile.get("profileGlobalStatus"))
    _put(module_info, "mac_address", _mac(profile.get("profileMacAddress")))
    _put(module_info, "configured_ipv4_address", profile.get("profileIpAddress"))
    _put(module_info, "configured_ipv4_netmask", profile.get("profileIpNetMask"))
    _put(module_info, "configured_ipv4_gateway", profile.get("profileIpGateway"))
    _put(module_info, "ip_config_mode", profile.get("profileIpConfigMode"))
    if data.get("interfaces"):
        module_info["num_network_interfaces"] = len(data["interfaces"])
    _put(module_info, "bandwidth_management", profile.get("profileBandwidthMgt"))
    if profile.get("communication_services"):
        module_info["communication_services"] = {
            key: "supported" if supported else "unsupported"
            for key, supported in profile["communication_services"].items()
        }
        # Legacy name for port502Messaging
        module_info["communication_services"]["port_502_messaging"] = module_info[
            "communication_services"
        ].pop("port502_messaging")

    p502 = tfe.get("port502_messaging", {})
    port_502: dict[str, Any] = {}
    _put(port_502, "supported_protocol", p502.get("port502SupportedProtocol"))
    if "port502Status" in p502:
        port_502["service_status"] = _legacy_status(p502["port502Status"])
    _put(port_502, "port_security", p502.get("port502IpSecurity"))
    _put(port_502, "max_connections", p502.get("port502MaxConn"))
    _put(port_502, "total_messages_received", p502.get("port502MsgIn"))
    _put(port_502, "total_messages_sent", p502.get("port502MsgOut"))
    _put(port_502, "total_errors_sent", p502.get("port502MsgOutErr"))
    if port_502:
        module_info["port_502"] = port_502

    web = tfe.get("web", {})
    web_server: dict[str, Any] = {}
    if "webStatus" in web:
        web_server["service_status"] = _legacy_status(web["webStatus"])
    _put(web_server, "password_status", web.get("webPassword"))
    _put(web_server, "successful_attempts", web.get("webSuccessfullAccess"))
    _put(web_server, "failed_attempts", web.get("webFailedAttempts"))
    if web_server:
        module_info["web_server"] = web_server

    email_rows = tfe.get("email", {}).get("emailTable", [])
    if email_rows:
        email = email_rows[0]
        smtp_server: dict[str, Any] = {}
        if "smtpStatus" in email:
            smtp_server["service_status"] = {
                "idle": "no configuration",
                _RUNNING: "operational and running",
            }.get(email["smtpStatus"], "stopped")
        _put(smtp_server, "ipv4_address", email.get("smtpSrvAddr"))
        _put(smtp_server, "mail_sent_count", email.get("smtpMailSentCnt"))
        _put(smtp_server, "error_count", email.get("smtpErrCnt"))
        _put(smtp_server, "last_error", email.get("smtpLastErr"))
        _put(smtp_server, "last_mail_elapsed_time", email.get("smtpLastMailElapsedTime"))
        if "smtpLnkSrvStatus" in email:
            smtp_server["link_service_status"] = (
                "reachable" if email["smtpLnkSrvStatus"] == "ok" else "unreachable"
            )
        _put(smtp_server, "server_check_fail_count", email.get("smtpSrvChkFailCnt"))
        if smtp_server:
            module_info["smtp_server"] = smtp_server

    led_states = {"on": 1, "off": 2, "blinking": 3}
    for i, led in enumerate(profile.get("profileLedDisplayTable", [])):
        state = led.get("ledState")
        module_info[f"led_{i}"] = {
            "name": _text(led.get("ledName")),
            "description": _text(led.get("ledDescr")),
            "state": led_states.get(state, state),
        }

    _put(system_info, "full_model", _text(profile.get("profileCPUType")))
    _put(system_info, "system_uptime", system.get("sysUpTime"))
    _put(system_info, "implementation_class", _text(profile.get("profileImplementationClass")))
    _put(system_info, "firmware_version", _text(profile.get("profileVersion")))

    return module_info, system_info


def _legacy_status(value: Any) -> str:
    return "operational" if value == _RUNNING else "no configuration"


def _text(value: Any) -> str:
    """Stripped string value, or empty string if it's not a string."""
    return value.strip() if isinstance(value, str) else ""


def _ip(value: Any) -> str:
    """Validated IP address, or empty string if it's invalid or unspecified."""
    if not isinstance(value, str) or not value:
        return ""
    try:
        ip = validate_ip(value)
    except ValueError:
        return ""
    return "" if ipaddress.ip_address(ip).is_unspecified else ip


def _mac(value: Any) -> str:
    """Validated MAC address (uppercase colon-separated), or empty string if invalid."""
    if not isinstance(value, str) or not value:
        return ""
    try:
        mac = validate_mac(value)
    except ValueError:
        return ""
    return "" if mac == "00:00:00:00:00:00" else mac


def _scalars(group: dict) -> dict:
    """Scalar values of a group or table row (no tables or nested structures)."""
    return {
        k: v
        for k, v in group.items()
        if not k.startswith("_") and not isinstance(v, (dict, list)) and v is not None
    }


def _store_module(dev: DeviceData, profile: dict) -> None:
    mod = DeviceData(slot=str(profile["profileSlot"]))

    if _text(profile.get("profileProductName")):
        mod.description.product = _text(profile["profileProductName"])
    if _text(profile.get("profileVersion")):
        mod.firmware.version = _text(profile["profileVersion"])
    if _mac(profile.get("profileMacAddress")):
        mod.mac = _mac(profile["profileMacAddress"])
    if _ip(profile.get("profileIpAddress")):
        mod.ip = _ip(profile["profileIpAddress"])
    if _text(profile.get("profileGlobalStatus")):
        mod.status = _text(profile["profileGlobalStatus"])

    leds = [
        {
            "name": _text(row.get("ledName")),
            "description": _text(row.get("ledDescr")),
            "state": row.get("ledState"),
        }
        for row in profile.get("profileLedDisplayTable", [])
    ]
    if leds:
        mod.extra["leds"] = leds

    dev.store("module", mod, lookup="slot")


def _store_interfaces(dev: DeviceData, data: dict, profile: dict) -> None:
    sys_uptime = data.get("system", {}).get("sysUpTime")
    profile_ip = _ip(profile.get("profileIpAddress"))
    profile_gateway = _ip(profile.get("profileIpGateway"))

    ip_rows: dict[Any, dict] = {}
    for row in data.get("ip_addresses", []):
        if_index = row.get("ipAdEntIfIndex")
        if isinstance(if_index, int) and if_index not in ip_rows:
            ip_rows[if_index] = row

    for row in data.get("interfaces", []):
        iface_type = normalize_iftype(row.get("ifType", ""))
        if iface_type == "loopback":
            continue

        iface = Interface(
            id=str(row.get("ifIndex", row.get("_index", ""))),
            name=_text(row.get("ifDescr")),
            type=iface_type,
        )

        if isinstance(row.get("ifMtu"), int) and row["ifMtu"] > 0:
            iface.mtu = row["ifMtu"]
        if isinstance(row.get("ifSpeed"), int) and row["ifSpeed"] >= 0:
            iface.speed = row["ifSpeed"] // 1_000_000  # bits per second => megabits
        if _mac(row.get("ifPhysAddress")):
            iface.mac = _mac(row["ifPhysAddress"])

        # enabled => ifAdminStatus, connected => ifOperStatus; up(1), down(2), testing(3)
        if row.get("ifAdminStatus") is not None:
            iface.enabled = row["ifAdminStatus"] in ("up", 1)
        if row.get("ifOperStatus") is not None:
            iface.connected = row["ifOperStatus"] in ("up", 1)

        # ifLastChange: value of sysUpTime when the interface entered its current state
        last_change = row.get("ifLastChange")
        if isinstance(sys_uptime, int) and isinstance(last_change, int):
            if 0 <= last_change <= sys_uptime:
                iface.uptime = timedelta(seconds=(sys_uptime - last_change) / 100)

        ip_row = ip_rows.get(row.get("ifIndex"), {})
        if _ip(ip_row.get("ipAdEntAddr")):
            iface.ip = _ip(ip_row["ipAdEntAddr"])
        if _ip(ip_row.get("ipAdEntNetMask")):
            iface.subnet_mask = _ip(ip_row["ipAdEntNetMask"])
        if iface.ip and iface.ip == profile_ip and profile_gateway:
            iface.gateway = profile_gateway

        # Each ifTable row is a distinct interface (ifIndex), even if rows share
        # a MAC or ifDescr (e.g. the ports of a BMX NOC 0401's embedded switch).
        # Interfaces with an IP merge with the interface with the same IP (e.g. from
        # the project file), the others only with a previously stored row.
        if iface.ip:
            dev.store("interface", iface, lookup="ip")
        else:
            row_lookup = {k: v for k, v in [("id", iface.id), ("type", iface.type)] if v}
            dev.store("interface", iface, lookup=row_lookup or None, append=not row_lookup)


def _peer_ips(tfe: dict, own_ip: str = "") -> list[str]:
    """IP addresses of other devices the M340 communicates with."""
    candidates = []

    for group, table, column in [
        ("io_scanning", "ioScanDeviceTable", "ioScanDeviceRemAddress"),
        ("port502_messaging", "port502ConnTable", "port502ConnRemAddress"),
        ("port502_messaging", "port502IpSecurityTable", "ipSourceAddress"),
        ("global_data", "glbDataPubTable", "glbDataPubSourceAddress"),
        ("global_data", "glbDataSubTable", "glbDataSubSourceAddress"),
        ("equipment_profile", "profileTrapTable", "remoteIpAddress"),
    ]:
        for row in tfe.get(group, {}).get(table, []):
            candidates.append(row.get(column))
            # Index columns may be not-accessible, use the decoded index instead
            if column not in row:
                candidates.extend(row.get("_index_parts", []))

    candidates.append(tfe.get("time_management", {}).get("ntpSrvAddr"))
    for row in tfe.get("email", {}).get("emailTable", []):
        candidates.append(row.get("smtpSrvAddr"))

    peers = []
    for candidate in candidates:
        ip = _ip(candidate)
        if ip and ip != own_ip and not ipaddress.ip_address(ip).is_loopback and ip not in peers:
            peers.append(ip)

    return peers


__all__ = [
    "DEFAULT_MAX_VARBINDS",
    "SCHNEIDER_MIBS_DIR",
    "TFE_GROUPS",
    "TFE_MIB",
    "TFE_ROOT",
    "TF_PRODUCTS",
    "TfeMibUnavailableError",
    "apply_to_dev",
    "decode_comm_services",
    "pull_snmp",
    "structure_scalars_and_tables",
    "to_legacy",
]
