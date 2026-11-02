import ast
import copy
import re

from peat import (
    DeviceData,
    Interface,
    Redundancy,
    Relationship,
    RelationshipEndpoint,
    Route,
    Service,
    TimeSource,
    User,
    Vlan,
    consts,
    log,
    utils,
)

from .fortigate_consts import FG_TIMEZONES

# Setting names that may hold secrets. Values of these are never copied
# into the data model (e.g. into "extra").
_SECRET_KEY_RE = re.compile(r"pass|secret|psk|key|community|token|cert", re.IGNORECASE)

# Interface "type" values of FortiOS aggregate interfaces -> Redundancy.protocol
_AGGREGATE_TYPES = {"aggregate": "lag", "redundant": "failover"}

# DNS server settings of "config system dns"
_DNS_SERVER_KEYS = (
    "primary",
    "secondary",
    "alt-primary",
    "alt-secondary",
    "ip6-primary",
    "ip6-secondary",
)

# Unspecified addresses (FortiOS shows them for unset values in "full-configuration")
_UNSET_IPS = ("0.0.0.0", "::")


def _without_secrets(settings: dict) -> dict:
    """Copy of ``settings`` without values of keys that may hold secrets."""
    return {k: v for k, v in settings.items() if not _SECRET_KEY_RE.search(str(k))}


def _split_names(value: str) -> list[str]:
    """FortiOS lists of names, e.g. ``'"port1" "port2"'`` (quotes already stripped)."""
    return [x for x in str(value).replace('"', " ").split() if x]


def _remote_endpoint(address: str, role: str = "", port: int | None = None):
    """
    Remote endpoint for an IP address or a hostname.

    Returns:
        The endpoint, or :obj:`None` if ``address`` is empty or unset
    """
    address = str(address or "").strip()
    if not address or address in _UNSET_IPS:
        return None
    if utils.is_ip(address):
        return RelationshipEndpoint(ip=address, role=role, port=port)
    return RelationshipEndpoint(hostname=address, role=role, port=port)


def _port(value) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 < port <= 65535 else None


# HA: High Availability
# VDOM: Virtual Domain(s)

# TODO: change dev.service to be key'd by port?


def strip_quotes(data: dict):
    if isinstance(data, dict):
        return {strip_quotes(key): strip_quotes(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [strip_quotes(item) for item in data]
    elif isinstance(data, str):
        return data.replace('"', "")
    else:
        return data


def fg_conf_to_dict(raw_data: str) -> dict:
    """
    Converts a raw Fortigate configuration file to a Python
    dictionary using Python's ast library.
    """

    prepared_content = []
    indent_level = 0

    # TODO: extract config-version from first line in file
    # TODO: dev.endian

    for line in raw_data.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):  # Skip empty lines and comments
            continue

        if line.startswith("config") or line.startswith("edit"):
            block_name = line.split(maxsplit=1)[1].strip('"')
            prepared_content.append(" " * indent_level + f"'{block_name}': {{")
            indent_level += 4

        elif line.startswith("set"):
            key, value = line.split(maxsplit=1)[1].split(maxsplit=1)
            if value == "''":  # this breaks how parsing is being done
                value = '""'
            prepared_content.append(" " * indent_level + f"'{key}': '{value}',")

        elif line.startswith("next") or line.startswith("end"):
            indent_level -= 4
            prepared_content.append(" " * indent_level + "},")

    # Wrap in a top-level dictionary
    prepared_content = "{\n" + "\n".join(prepared_content) + "\n}"

    # Parse the Python-like dictionary into a Python object
    try:
        parsed_dict = ast.literal_eval(prepared_content)
    except (SyntaxError, ValueError) as e:
        raise ValueError(f"Failed to parse config: {e}") from None

    # nest the config sections (un-flatten)
    un_flattened = {}
    for key, value in parsed_dict.items():
        if " " in key:
            parts = key.split(" ")
            d = un_flattened
            for part in parts[:-1]:
                if part not in d:
                    d[part] = {}
                d = d[part]
            d[parts[-1]] = value
        else:
            un_flattened[key] = value

    # TODO: strip quotation marks from strings
    un_flattened = strip_quotes(un_flattened)

    return un_flattened


def process_fg_system(system: dict[str, dict], dev: DeviceData) -> None:
    # === global ===
    sys_global = system.get("global", {})
    if sys_global.get("hostname"):
        dev.hostname = sys_global.pop("hostname")
    if sys_global.get("alias"):
        dev.name = sys_global.pop("alias")

    # Parse timezone from integer to standard string
    # The fortigate timezones don't match TZ database names
    # For now, just use the name that was extracted from docs.
    if sys_global.get("timezone"):
        try:
            # TODO: use pytz and levenshtein distance to determine name,
            # since a given offset can have multiple timezones associated.
            # https://stackoverflow.com/a/35086476
            tz_name = FG_TIMEZONES[int(sys_global.pop("timezone"))]["timezone"]
            dev.geo.timezone = tz_name
        except (ValueError, KeyError) as ex:
            log.warning(f"Failed to parse Fortigate timezone: {ex}")

    # === interface ===
    # Network interfaces
    for if_name, si in system.get("interface", {}).items():
        iface = Interface(
            name=if_name,
            id=if_name,
        )

        # TODO: parse "speed", set iface.speed and iface.duplex
        # don't have an example config with this parameter set

        # IP address and subnet mask, space-separated
        if si.get("ip"):
            iface.ip, iface.subnet_mask = si.pop("ip").split(" ")

        # Don't have examples of this, hope it works
        if si.get("macaddr"):
            iface.mac = si.pop("macaddr")

        if si.get("alias"):
            # this can be a human-readable string, e.g. "OUTofBand Mgmt Interface"
            iface.alias = si.pop("alias")
        if si.get("description"):
            iface.description.description = si.pop("description")

        if si.get("type"):
            iface.type = si.pop("type").lower()
            iface.physical = bool(iface.type == "physical")

        # VLAN interface: "set interface <parent>" and "set vlanid <id>"
        if si.get("vlanid"):
            try:
                iface.vlan = Vlan(id=si.pop("vlanid"), tagged=True)
            except ValueError as ex:
                log.warning(f"Invalid VLAN ID for Fortigate interface '{if_name}': {ex}")
            iface.physical = False
        if si.get("interface"):
            iface.parent = si.pop("interface")

        # Aggregate (LACP/static) and redundant interfaces: membership of the ports
        if iface.type in _AGGREGATE_TYPES:
            iface.physical = False
            iface.redundancy = Redundancy(
                protocol=_AGGREGATE_TYPES[iface.type],
                mode=si.pop("lacp-mode", ""),
                members=_split_names(si.pop("member", "")),
            )

        if si.get("snmp-index"):
            si["snmp-index"] = int(si["snmp-index"])

        # Permitted types of management access to this interface
        if si.get("allowaccess"):
            protocols = si["allowaccess"].replace("ping", "icmp").split(" ")
            dev.related.protocols.update(protocols)

            for proto in protocols:
                svc = dev.retrieve("service", {"protocol": proto})
                if svc and not any(s.protocol == proto for s in iface.services):
                    iface.services.append(svc)
                else:
                    svc = Service(protocol=proto)
                    dev.store("service", svc, lookup="protocol")
                    iface.services.append(svc)

        # save remaining parameters in "extra"
        iface.extra = _without_secrets(si)
        dev.store("interface", iface, lookup="id")

    # === accprofile ===
    # Roles and permissions
    if system.get("accprofile"):
        dev.related.roles.update(system["accprofile"].keys())

    # === admin ===
    # Admin users
    for name, sa in system.get("admin", {}).items():
        user = User(name=name)

        # VDOM: Virtual Domain
        if sa.get("accprofile"):
            role = sa.pop("accprofile")
            user.roles.add(role)
            user.permissions.update(system.get("accprofile", {}).keys())

        # exclude excessive/uninteresting data from user.extra
        for key in [
            "gui-dashboard",
            "gui-default-dashboard-template",
            "gui-ignore-release-overview-version",
            "password",
        ]:
            sa.pop(key, None)

        # store remaining values
        user.extra = sa

        dev.store("users", user, lookup="name")

    # DNS configuration
    if system.get("dns"):
        for key in [*_DNS_SERVER_KEYS, "source-ip"]:
            if system["dns"].get(key):
                if utils.is_ip(system["dns"][key]):
                    dev.related.ip.add(system["dns"][key])
                else:
                    log.warning(f"Invalid IP for Fortigate DNS server: {system['dns'][key]}")

        # The device depends on its DNS servers
        for key in _DNS_SERVER_KEYS:
            server = str(system["dns"].get(key, "")).strip()
            if utils.is_ip(server) and server not in _UNSET_IPS:
                dev.store(
                    "relationships",
                    Relationship(
                        type="depends_on",
                        protocol="dns",
                        direction="egress",
                        remote=RelationshipEndpoint(ip=server, role="dns_server"),
                        evidence={"config"},
                        extra={"setting": key},
                    ),
                )

        if system["dns"].get("server-hostname"):
            dev.related.hosts.add(system["dns"]["server-hostname"])

        # cleartext => DNS over UDP/56 or TCP/53
        # dot = DNS over TLS
        # doh = DNS over HTTPS
        if system["dns"].get("protocol"):
            proto = system["dns"]["protocol"]
            if proto == "cleartext":
                proto = "dns"
            dev.related.protocols.add(proto)

    # === snmp sysinfo ===
    if system.get("snmp"):
        svc = dev.retrieve("service", {"protocol": "snmp"})
        if not svc:
            svc = Service(protocol="snmp")
        # this is basic and API needs improvement
        elif isinstance(svc, list):
            svc = svc[0]

        # TODO: assume SNMP port is default for now, our example
        # config didn't have it configured anywhere.
        svc.port = 161
        svc.transport = "udp"  # SNMP is always UDP :)

        if system["snmp"].get("sysinfo"):
            sns = system["snmp"]["sysinfo"]
            if sns.get("description"):
                if not dev.description.description:
                    dev.description.description = sns["description"]
                else:
                    dev.description.description += f"---SNMP description: {sns['description']}"

            if sns.get("status"):
                svc.enabled = consts.str_to_bool(sns.pop("status"))

            if sns.get("location"):
                dev.geo.name = sns.pop("location")

            if sns.get("contact-info"):
                contact = sns.pop("contact-info")
                dev.description.contact_info = contact
                if utils.is_email(contact):
                    dev.related.emails.add(contact)

        dev.store("service", svc, lookup="protocol")

        # SNMP communities: the hosts are the SNMP managers allowed to query
        # the device ("host-type query"), to receive traps ("trap") or both ("any").
        # NOTE: the community name is the community string (a secret), never copy it.
        for comm in system["snmp"].get("community", {}).values():
            if not isinstance(comm, dict):
                continue
            # SNMP managers
            for key in ["hosts", "hosts6"]:
                if not isinstance(comm.get(key), dict):
                    continue
                for host in comm[key].values():
                    raw_ip = str(host.get("ip") or host.get("ipv6") or "").strip()
                    if not raw_ip:
                        continue
                    # IP and subnet mask, e.g. "192.0.2.99 255.255.255.255"
                    ip, _, mask = raw_ip.partition(" ")
                    if "/" in ip:
                        ip, _, mask = ip.partition("/")
                    if not utils.is_ip(ip) or ip in _UNSET_IPS:
                        continue
                    dev.related.ip.add(ip)

                    host_type = str(host.get("host-type", "")).lower()
                    direction = {"query": "ingress", "trap": "egress"}.get(host_type, "")
                    extra = {"host_type": host_type} if host_type else {}
                    if mask.strip() and mask.strip() not in ("255.255.255.255", "32", "128"):
                        extra["netmask"] = mask.strip()

                    dev.store(
                        "relationships",
                        Relationship(
                            protocol="snmp",
                            transport="udp",
                            direction=direction,
                            remote=RelationshipEndpoint(ip=ip, role="snmp_manager"),
                            evidence={"config"},
                            extra=extra,
                        ),
                    )

    # This has a email address
    if system.get("fortiguard"):
        sai = system["fortiguard"].get("service-account-id")
        if sai and utils.is_email(sai):
            dev.related.emails.add(sai)

    # "Configure the email server used by the FortiGate various things.
    # For example, for sending email messages to users to support
    # user authentication features."
    if system.get("email-server"):
        ses = system["email-server"]
        dev.related.protocols.add("smtp")

        if ses.get("server"):
            if not utils.is_ip(ses["server"]):
                dev.related.hosts.add(ses["server"])

        # Extract IP addresses
        for key in ["server", "source-ip", "source-ip6"]:
            if ses.get(key) and utils.is_ip(ses[key]):
                dev.related.ip.add(ses[key])

        if ses.get("port"):
            dev.related.ports.add(int(ses["port"]))

        if ses.get("username"):
            dev.related.user.add(ses["username"])

        # The device depends on the email server (never copy the password)
        remote = _remote_endpoint(ses.get("server", ""), "smtp_server", _port(ses.get("port")))
        if remote is not None:
            local_ip = str(ses.get("source-ip", "")).strip()
            dev.store(
                "relationships",
                Relationship(
                    type="depends_on",
                    protocol="smtp",
                    transport="tcp",
                    direction="egress",
                    local=RelationshipEndpoint(
                        ip=local_ip if utils.is_ip(local_ip) and local_ip not in _UNSET_IPS else ""
                    ),
                    remote=remote,
                    evidence={"config"},
                ),
            )

    # A session helper binds a service to a TCP or UDP port.
    # https://community.fortinet.com/t5/FortiGate/Technical-Tip-Enable-and-disable-FortiGate-system-session/ta-p/191762
    for p_id, p_vals in system.get("session-helper", {}).items():
        # Each of these values should have name, protocol, port
        # "protocol" => IP protocol numbers defined by IANA
        # 6 => TCP, 17 => UDP
        svc = Service(protocol=p_vals["name"])
        svc.port = int(p_vals["port"])
        svc.transport = consts.IANA_IP_PROTOS.get(int(p_vals["protocol"]), "")
        svc.protocol_id = str(p_id)
        dev.store("service", svc, lookup="protocol")

    # DHCP server configuration
    for dh in system.get("dhcp", {}).get("server", {}).values():
        # TODO: add a DHCP service and associate it with relevant interfaces
        # svc = Service(protocol="dhcp")

        if dh.get("default-gateway") and utils.is_ip(dh["default-gateway"]):
            dev.related.ip.add(dh["default-gateway"])

    # NTP servers ("set type custom", "config ntpserver"). With "set type fortiguard"
    # the FortiGuard servers are used instead of the configured servers.
    ntp = system.get("ntp", {})
    if ntp:
        ntp_type = str(ntp.get("type", "")).lower()
        ntp_enabled = None
        if ntp.get("ntpsync"):
            ntp_enabled = str(ntp["ntpsync"]).lower() == "enable"
        if ntp_type == "fortiguard":
            ntp_enabled = False

        for server_id, ntp_server in (ntp.get("ntpserver") or {}).items():
            if not isinstance(ntp_server, dict) or not ntp_server.get("server"):
                continue
            source = TimeSource(
                protocol="ntp",
                address=ntp_server["server"],
                port=_port(ntp_server.get("port")),
                enabled=ntp_enabled,
                extra={"id": str(server_id)},
            )
            if ntp_server.get("authentication"):
                source.extra["authentication"] = ntp_server["authentication"]
            if not any(
                (s.protocol, s.address, s.port) == (source.protocol, source.address, source.port)
                for s in dev.clock.sources
            ):
                dev.clock.sources.append(source)

        if ntp_type:
            dev.clock.extra["ntp_type"] = ntp_type  # "fortiguard" or "custom"
        if ntp.get("ntpsync"):
            dev.clock.extra["ntp_sync"] = str(ntp["ntpsync"]).lower() == "enable"

    # High availability (FGCP). Device-level redundancy isn't modeled yet.
    if system.get("ha"):
        dev.extra["ha"] = _without_secrets(system["ha"])

    # TODO: "system sdwan" => related.urls, related.protocol

    # TODO
    # save remaining parameters in "extra"
    # dev.extra["system"] = system


def process_fg_router(router: dict[str, dict], dev: DeviceData) -> None:
    """
    Process ``config router static`` entries into :class:`~peat.data.models.Route`.

    .. code-block:: text

       config router static
           edit 1
               set dst 192.0.2.0 255.255.255.0
               set gateway 198.51.100.1
               set device "port1"
           next
       end

    A missing ``dst`` is the default route (``0.0.0.0/0``).
    """
    for route_id, rs in (router.get("static") or {}).items():
        if not isinstance(rs, dict):
            continue
        gateway = str(rs.get("gateway", "")).strip()
        route = Route(
            destination=rs.get("dst") or "0.0.0.0/0",
            gateway="" if gateway in _UNSET_IPS else gateway,
            interface=rs.get("device", ""),
            type="blackhole" if str(rs.get("blackhole", "")).lower() == "enable" else "static",
            protocol="static",
            enabled=str(rs.get("status", "enable")).lower() != "disable",
            description=rs.get("comment", ""),
            extra={"id": str(route_id)},
        )
        if rs.get("distance"):
            try:
                route.metric = int(rs["distance"])
            except ValueError:
                pass
        for key in ("priority", "weight", "vrf"):
            if rs.get(key):
                route.extra[key] = rs[key]
        dev.store("routes", route)


def process_fg_vpn(vpn: dict[str, dict], dev: DeviceData) -> None:
    """
    Process ``config vpn ipsec phase1-interface`` tunnels into
    ``Relationship(type="tunnel", protocol="ipsec")``. Pre-shared keys and other
    secrets are never copied.
    """
    phase1 = (vpn.get("ipsec") or {}).get("phase1-interface") or {}
    for name, tunnel in phase1.items():
        if not isinstance(tunnel, dict):
            continue
        remote = _remote_endpoint(tunnel.get("remote-gw", ""), "peer")
        if remote is None:
            remote = _remote_endpoint(tunnel.get("remotegw-ddns", ""), "peer")
        if remote is None:  # dial-up tunnels have no fixed peer
            continue

        extra = {"tunnel_name": name}
        for key in ("ike-version", "mode", "peertype", "type"):
            if tunnel.get(key):
                extra[key.replace("-", "_")] = tunnel[key]

        dev.store(
            "relationships",
            Relationship(
                type="tunnel",
                protocol="ipsec",
                local=RelationshipEndpoint(interface=tunnel.get("interface", "")),
                remote=remote,
                evidence={"config"},
                extra=extra,
            ),
        )


def process_fg_log(log_conf: dict[str, dict], dev: DeviceData) -> None:
    """
    Process the log destinations: FortiAnalyzer (``config log fortianalyzer
    setting``) and syslog servers (``config log syslogd setting``,
    ``syslogd2``, ...) into ``Relationship(type="logs_to")``.
    """
    # TODO: log_conf["tap-device"] => port/service

    # Global FortiAnalyzer settings
    for section in ("fortianalyzer", "fortianalyzer2", "fortianalyzer3"):
        fas = (log_conf.get(section) or {}).get("setting")
        if not isinstance(fas, dict):
            continue

        # Extract IP addresses
        for key in ["server", "source-ip"]:
            if fas.get(key) and utils.is_ip(fas[key]):
                dev.related.ip.add(fas[key])

        remote = _remote_endpoint(fas.get("server", ""), "log_server")
        if remote is None:
            continue

        local_ip = str(fas.get("source-ip", "")).strip()
        extra = {
            k.replace("-", "_"): v
            for k, v in _without_secrets(fas).items()
            if k not in ("server", "source-ip", "status")
        }
        dev.store(
            "relationships",
            Relationship(
                type="logs_to",
                protocol="fortianalyzer",
                direction="egress",
                local=RelationshipEndpoint(
                    ip=local_ip if utils.is_ip(local_ip) and local_ip not in _UNSET_IPS else ""
                ),
                remote=remote,
                enabled=(str(fas["status"]).lower() == "enable") if fas.get("status") else None,
                evidence={"config"},
                extra=extra,
            ),
        )

    # Syslog servers
    for section in ("syslogd", "syslogd2", "syslogd3", "syslogd4"):
        sls = (log_conf.get(section) or {}).get("setting")
        if not isinstance(sls, dict):
            continue

        remote = _remote_endpoint(sls.get("server", ""), "log_server", _port(sls.get("port")))
        if remote is None:
            continue
        if remote.ip:
            dev.related.ip.add(remote.ip)

        mode = str(sls.get("mode", "")).lower()
        transport = "udp" if mode in ("udp", "legacy-reliable") else ""
        if mode == "reliable":
            transport = "tcp"

        extra = {"setting": section}
        for key in ("mode", "facility", "format", "enc-algorithm"):
            if sls.get(key):
                extra[key.replace("-", "_")] = sls[key]

        dev.store(
            "relationships",
            Relationship(
                type="logs_to",
                protocol="syslog",
                transport=transport,
                direction="egress",
                remote=remote,
                enabled=(str(sls["status"]).lower() == "enable") if sls.get("status") else None,
                evidence={"config"},
                extra=extra,
            ),
        )


def process_fg_conf(fg_conf: dict[str, dict], dev: DeviceData):
    # Reference: FortiOS-7.2.9-CLI_Reference.pdf

    # make a copy that can be safely mutated during processing
    conf = copy.deepcopy(fg_conf)

    if conf.get("system"):
        process_fg_system(conf["system"], dev)

    # FortiAnalyzer and syslog servers
    if conf.get("log"):
        process_fg_log(conf["log"], dev)

    # Static routes
    if conf.get("router"):
        process_fg_router(conf["router"], dev)

    # IPsec VPN tunnels
    if conf.get("vpn"):
        process_fg_vpn(conf["vpn"], dev)

    # TODO: verify this in the UI
    if conf.get("web-proxy", {}).get("explicit"):
        wpe = conf["web-proxy"]["explicit"]
        # TODO: add a service for HTTP
        # TODO: there may be HTTP services on multiple ports,
        #   we need to do better lookup than "protocol" (maybe "port"?)
        # if wpe.get("status"):
        #     consts.str_to_bool(wpe["status"])
        if wpe.get("http-incoming-port"):
            dev.related.ports.add(int(wpe["http-incoming-port"]))

    # TODO: "user local" and "user group" => Users

    # TODO: add protocols from conf["router"]
    # TODO: conf["router"]["ospf"]
