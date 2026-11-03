"""
The Siemens SIPROTEC 4 Relay.

Services

- WebMonitor (TCP 80 and TCP 443)
- IEC61850 (TCP 102)
- SNMP (UDP 161)
- Unknown service (UDP 43690)
- DIGSI (UDP 50000)
- WebMonitor comms (UDP 56797)

There is a web interface located at port 80 that uses Java applets for
some features (use Internet Explorer and Java version 6).

Authors

- Christopher Goes
- Michelle Cabahug
"""

import binascii
import functools
import os.path
import re
from datetime import datetime, timedelta
from pprint import pformat
from typing import Any, Final, Literal

from peat import DeviceData, DeviceModule, IPMethod, utils
from peat.data.models import (
    Interface,
    NetworkStatistics,
    NetworkTraffic,
    Package,
    Redundancy,
    Service,
    TimeSource,
)
from peat.protocols import HTTP, SNMP, snmp_walk

from .mlfb import decode_mlfb

# Directory containing SNMP MIBs as 'compiled' PySNMP Python files
# TODO: the mibs path won't work in a pyinstaller exe since it's a directory
#  and importlib.resources doesn't like that. We need to figure
#  out a better way to store and use SNMP MIBs in general.
# SIPROTEC_MIBS_DIR: str = utils.get_resource(__package__, "mibs")
# SIPROTEC_MIBS_DIR = Path(Path(__file__).parent, 'mibs').resolve()
SIPROTEC_MIBS_DIR = os.path.abspath(os.path.join(__file__, "..", "mibs"))

# TODO: add parse method that takes MLFB and/or VER txt files


class Siprotec(DeviceModule):
    """
    Siemens SIPROTEC 4 Relay.
    """

    device_type = "Relay"
    vendor_id = "Siemens"
    vendor_name = "Siemens AG"
    brand = "Siprotec"
    model = "7SJ6x"

    @classmethod
    def _verify_snmp(cls, dev: DeviceData) -> bool:
        """
        Check if a device is a Siprotec by querying SNMP for OID
        ``1.3.6.1.2.1.1.1.0`` (``sysDescr``) and comparing the
        output against the string ``SIPROTEC``.
        """
        # TODO: use dev.options["snmp"]["community"] if it's configured
        for community in dev.options["snmp"]["communities"]:
            # TODO: some siprotecs are returning "Fusion 7.0"
            # 'Fusion 7.0 SNMP for Fusion TCP/IP'
            to_find = ["SIPROTEC"]

            snmp = SNMP(
                dev.ip,
                dev.options["snmp"]["port"],
                dev.options["snmp"]["timeout"],
                community=community,
            )

            if snmp.verify("1.3.6.1.2.1.1.1.0", to_find=to_find):
                # !! TODO: hack to cache the community that worked !!
                dev._options["snmp"]["community"] = community
                return True

        return False

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        successful = True

        # Pull HTTP data
        # TODO: better way of selecting protocol to use (encrypted/unencrypted)
        web_success = False
        cls.log.info(f"Pulling WebMonitor information from {dev.ip}...")
        for protocol in ["http", "https"]:
            if dev.service_status({"protocol": protocol}) == "verified":
                if cls._get_webmonitor_data(dev, protocol):
                    web_success = True
        if not web_success:
            successful = False
        cls.log.info(f"Finished pulling WebMonitor information from {dev.ip}")

        # Pull SNMP data
        try:
            snmp_module, system = cls._get_snmp_data(
                ip=dev.ip,
                timeout=dev.options["snmp"]["timeout"],
                community=dev.options["snmp"]["community"],
            )
            # Uptime, interfaces, statistics, redundancy and time sources
            unmapped = process_snmp_data(dev, snmp_module, system)

            # Add the overall system info straight into the device info
            dev.extra.update(system)

            # Add the information for each module to its corresponding dict
            # TODO: add device modules to dev.module
            modname = str(snmp_module.get("sysName", "")).strip()
            module_name = f"module_{modname.split(' ')[0]}"  # module_<sysName>
            if module_name in dev.extra:
                # If module exists, add the info
                dev.extra[module_name].update(unmapped)
            else:
                # If it doesn't, create it using the info
                dev.extra[module_name] = unmapped
        except Exception as err:
            cls.log.error(f"Could not pull SNMP metadata: {err}")
            successful = False

        return successful

    @classmethod
    def _get_webmonitor_data(cls, dev: DeviceData, protocol: Literal["http", "https"]) -> bool:
        """
        Query Siprotec webmonitor service for particular files via HTTP or HTTPS.
        """
        cls.log.debug(f"Pulling WebMonitor data from {dev.ip} using {protocol}")

        parsers = {
            "mlfb": cls._parse_mlfb_txt,
            "ver": cls._parse_ver_txt,
        }
        data_was_pulled = False

        with HTTP(
            ip=dev.ip,
            port=dev.options[protocol]["port"],
            timeout=dev.options[protocol]["timeout"],
        ) as http:
            for f_type, parser in parsers.items():
                # Check cache to prevent pulling the same file
                # multiple times (e.g. HTTP then HTTPS)
                if not dev._cache.get(f"{f_type}_data_pulled"):
                    filename = f"{f_type}.txt"
                    response = http.get(filename, protocol)
                    # If the first file fails with this protocol,
                    # subsequent ones likely will as well
                    if response is None:
                        break

                    raw_data = response.text
                    if not raw_data:
                        cls.log.debug(f"Empty {filename} data from {dev.ip}")
                        break

                    if "DOCTYPE" in raw_data or "<html" in raw_data:
                        cls.log.debug(
                            f"Failed to pull WebMonitor data from {dev.ip}: bad {filename} data"
                        )
                        return False

                    dev.write_file(raw_data, f"raw-{f_type}.txt")

                    parsed = parser(raw_data)
                    dev.write_file(parsed, f"parsed-{f_type}.json")

                    if parsed.get("firmware_version"):
                        dev.firmware.version = parsed.pop("firmware_version")
                    if parsed.get("model"):
                        dev.description.model = parsed.pop("model")

                    # WebMonitor version -> dev.software
                    process_webmonitor_version(dev, parsed)

                    dev.extra.update(parsed)
                    dev._cache[f"{f_type}_data_pulled"] = True
                    data_was_pulled = True

        cls.log.debug(f"Finished pulling WebMonitor data from {dev.ip} using {protocol}")

        return data_was_pulled

    @classmethod
    def _get_snmp_data(
        cls, ip: str, timeout: float, community: str = "public"
    ) -> tuple[dict, dict]:
        """
        Obtains device metadata via SNMP.

        Args:
            community: SNMP Community string to use

        Returns:
            Info for the module hosting SNMP and the overall system, respectfully
        """
        # TODO: figure out more meaningful OIDs
        # TODO: Fix Siprotec MIBs (They are throwing errors on load)
        cls.log.info(f"Pulling SNMP information from {ip}...")
        module_info = {}
        system_info = {}
        sip_goose_info = {}
        iec_62439_info = {}

        # SNMP OIDs to pull from device
        # Format: "info_returned": "fully-qualified_oid"
        #
        # Since these OIDs are non-mandatory, the requests to make
        # depend on communicationServices results
        #
        # OIDs for information specific to the module running the SNMP server
        # First key in tuple is OID, second is type)
        module_oids = {
            # Module and Module FW version
            # TODO: possible serial number here?
            "sysDescr": ("2.1.1.1.0", str),
            # Address (object identifier) under which the
            # device-specific SNMP variables can be reached
            "sysObjectID": ("2.1.1.2.0", str),
            "sysName": ("2.1.1.5.0", str),
            "mac_address": ("2.1.2.2.1.6.2", str),
            "netmask": ("2.1.4.20.1.3." + ip, str),
            "ifAdminStatus": ("2.1.2.2.1.7.2", int),
            "ifOperStatus": ("2.1.2.2.1.8.2", int),
        }

        # OIDs with snmp statistics (SNMPv2-MIB, RFC 3418)
        snmp_oids = {
            "snmpInBadVersions": ("2.1.11.3.0", int),
            "snmpInBadCommunityNames": ("2.1.11.4.0", int),
            "snmpInBadCommunityUses": ("2.1.11.5.0", int),
        }

        # OIDs with system-wide information
        system_oids = {
            # sysUpTime, TimeTicks (hundredths of a second)
            "system_uptime": ("2.1.1.3.0", int),
        }

        # First key in tuple is OID, second is instance, third is type
        iec_62439_oids = {
            "manufacturerName": ("manufacturerName", 0, str),
            "interfaceCount": ("interfaceCount", 0, int),
            "versionName": ("versionName", 1, str),
            "nodeName": ("nodeName", 1, str),
            "nodeType": ("nodeType", 1, str),
            # TODO: The following are commented out due to pysnmp errors (ValueConstraint)
            # 'macAddressA':                  ('macAddressA', 1, str), #hexstr
            # 'macAddressB':                  ('macAddressB', 1, str), #hexstr
            "adapterActiveA": ("adapterActiveA", 1, str),
            "adapterActiveB": ("adapterActiveB", 1, str),
            "hsrLREMode": ("hsrLREMode", 1, str),
            "switchingEndNode": ("switchingEndNode", 1, str),
            "evaluateSupervision": ("evaluateSupervision", 1, str),
        }

        # Create SNMP object to use for pulling data
        snmp = SNMP(ip=ip, timeout=timeout, community=community, mib_paths=[SIPROTEC_MIBS_DIR])

        cls.log.debug("Pulling SNMP device modules info...")
        fw_ver = 0
        for name, oid_pair in module_oids.items():
            response = snmp.get(f"1.3.6.1.{oid_pair[0]}")
            if not response:
                continue
            data = oid_pair[1](response[0]["value_string"])

            if data != "":
                if name == "mac_address":
                    # Handle MAC address being represented as
                    # raw bytes and not text characters.
                    mac = binascii.b2a_hex(bytes(data, "utf-8")).decode().upper()
                    module_info["mac_address"] = ":".join(
                        a + b for a, b in zip(mac[::2], mac[1::2], strict=False)
                    )
                elif name == "sysDescr":
                    # TODO: some siprotecs are returning "Fusion 7.0"
                    try:
                        fw_ver = data[-11:].replace(".", "")
                        fw_ver = int(fw_ver[: fw_ver.find("_")])
                        module_info["module_firmware_version"] = data[-11:]
                    except Exception:
                        cls.log.debug(f"Bad SNMP sysDescr: {data}")
                elif name == "ifAdminStatus":
                    module_info[name] = IF_ADMIN_STATUS.get(data, str(data))
                elif name == "ifOperStatus":
                    module_info[name] = IF_OPER_STATUS.get(data, str(data))
                else:
                    module_info[name] = data

        # Pull snmp statistics
        snmp_info = {}
        cls.log.debug("Pulling SNMP statistics info...")
        for name, oid_pair in snmp_oids.items():
            response = snmp.get(f"1.3.6.1.{oid_pair[0]}")
            if not response:
                continue
            data = oid_pair[1](response[0]["value_string"])
            snmp_info[name] = data
        module_info["snmp_stats"] = snmp_info

        # Pull information for the overall system
        cls.log.debug("Pulling SNMP overall system info...")
        for name, oid_pair in system_oids.items():
            response = snmp.get(f"1.3.6.1.{oid_pair[0]}")
            if not response:
                continue
            data = oid_pair[1](response[0]["value_string"])
            if data != "":
                system_info[name] = data

        # Pull info from SipEthernet MIB
        cls.log.debug("Pulling SNMP SipEthernet info...")
        sip_eth_info = snmp_walk(
            ip=ip,
            mib_name="SipEthernet",
            mib_src=SIPROTEC_MIBS_DIR,
            timeout=timeout,
            community=community,
        )
        module_info["sip_ethernet"] = sip_eth_info

        # Pull info from SipGoose MIB
        cls.log.debug("Pulling SNMP SipGoose info...")
        try:
            sip_goose_info = snmp_walk(
                ip=ip,
                mib_name="SipGoose",
                mib_src=SIPROTEC_MIBS_DIR,
                timeout=timeout,
                community=community,
            )
        except Exception as err:
            cls.log.exception(f"Failed to pull SNMP SipGoose info: {err}")
        module_info["sip_goose"] = sip_goose_info

        # Pull info from SipOptical MIB
        # TODO: Fix ValueConstraintError with 7SJ61
        # Bandaid fix = compare fw version
        if fw_ver > 41000:
            cls.log.debug("Pulling SNMP SipOptical info...")
            sip_optical_info = snmp_walk(
                ip=ip,
                mib_name="SipOptical",
                mib_src=SIPROTEC_MIBS_DIR,
                timeout=timeout,
                community=community,
            )
            module_info["sip_optical"] = sip_optical_info
        else:
            cls.log.debug("Module firmware version not high enough for SipOptical")

        # If FW > 4.10, pull IEC62439 info
        # TODO: Fix ValueConstraintError when pulling mac addresses
        # Currently targets specific oids because we're getting weird errors
        #   trying to grab mac addresses
        cls.log.debug("Pulling SNMP IEC62439 info...")
        if fw_ver > 41000:
            for name, oid_triplet in iec_62439_oids.items():
                response = snmp.get(("IEC62439", oid_triplet[0], oid_triplet[1]))
                if not response:
                    continue
                data = oid_triplet[2](response[0]["value_string"])
                if data != "":
                    iec_62439_info[name] = data
        else:
            cls.log.debug("Module firmware version not high enough for IEC62439")
        module_info["iec_62439"] = iec_62439_info

        cls.log.info(f"Finished pulling SNMP information from {ip}")
        cls.log.trace2(f"** SNMP system_info **\n{pformat(system_info)}\n")
        cls.log.trace2(f"** SNMP module_info **\n{pformat(module_info)}\n")
        return module_info, system_info

    @staticmethod
    def _parse_mlfb_txt(data: str) -> dict:
        """
        Parse the contents of MLFB.txt.

        Args:
            data: Raw contents to parse

        Returns:
            The components of the file as a dictionary
        """
        parts = [x for x in data.split("\n") if x != ""]

        parsed = {
            "model": parts[0][:6],
            "bf_number": parts[1].strip(),
            "firmware_version": parts[-1][-9:].strip(),
            **decode_mlfb(parts[0][6 : data.index("-")]),
        }

        return parsed

    @classmethod
    def _parse_ver_txt(cls, data: str) -> dict:
        parts = [x.rstrip() for x in data.split("\n") if x != ""]

        if len(parts) != 2:
            cls.log.warning(
                f"Parse may be incorrect, encountered an unexpected VER.txt structure: {parts}"
            )

        parsed = {
            "webmonitor_version": parts[0][1:],
            "webmonitor_build_date": parts[1],
        }

        # TODO: add timezone data and put in elastic-friendly format
        try:
            tstamp = datetime.strptime(parts[1], "%a, %d %b %Y %H:%M:%S %Z")
            parsed["webmonitor_build_timestamp"] = tstamp.isoformat()
        except Exception as err:
            cls.log.debug(f"Failed to parse WebMonitor timestamp '{parts[1]}': {err}")

        return parsed


# IF-MIB (RFC 2863) ifAdminStatus and ifOperStatus values
IF_ADMIN_STATUS: Final[dict[int, str]] = {1: "up", 2: "down", 3: "testing"}
IF_OPER_STATUS: Final[dict[int, str]] = {
    1: "up",
    2: "down",
    3: "testing",
    4: "unknown",
    5: "dormant",
    6: "notPresent",
    7: "lowerLayerDown",
}

# SipEthernet module-wide counters with a NetworkStatistics field. The
# other counters of the MIB go to statistics.extra (snake_case names).
_SIP_ETHERNET_FIELDS: Final[dict[str, tuple[str, str]]] = {
    "nRxBMsg": ("ingress", "broadcast_packets"),
    "nRxMMsg": ("ingress", "multicast_packets"),
    "nRxCRCErrFrm": ("ingress", "crc_errors"),
    "nFrameLoss": ("ingress", "dropped"),
    "nTxTel": ("egress", "packets"),
}
_SIP_ETHERNET_COUNTERS: Final[tuple[str, ...]] = (
    "nRxTelInt",
    "nRxTelTask",
    "nRxBuffDescriptor",
    "nMismatchTel",
    "nRxBMsg",
    "nRxMMsg",
    "nLongTel",
    "nRxNOAlignFrm",
    "nRxCRCErrFrm",
    "nRxTruncMsg",
    "nTxTel",
    "nTxBuffFull",
    "nRxFnsFull",
    "nFrameLoss",
    "nTxDefTel",
    "nTxHeartBeat",
    "nTxLateCollision",
    "nRetransLmtCross",
    "nTxRetry",
    "nTxUnderRun",
    "nTxCSL",
    "overrun",
    "maxRxBDs",
    "rxLoopMax",
    "rxOverload",
    "rxOverloadCnt",
    "maxTxBD",
)
# Per-channel status objects of SipEthernet (-> channel interfaces) and SNTP
_SIP_ETHERNET_MOVED: Final[tuple[str, ...]] = (
    "linkUpChan1",
    "linkUpChan2",
    "activChannel",
    "optLevel1",
    "optLevel2",
    "rstpRoleChannel1",
    "rstpRoleChannel2",
    "rstpStatusChannel1",
    "rstpStatusChannel2",
    "sntpPrimaryServer",
    "sntpSecondaryServer",
    "sntpClockmaster",
)
# SipOptical per-channel table (opticalTransceiverTable, .5.1.*)
_SIP_OPTICAL_TABLE: Final[tuple[str, ...]] = (
    "channel",
    "txPacket",
    "rxPacket",
    "filterSrc",
    "filterDest",
    "filterCrcErrCnt",
    "filterLenErrCnt",
    "filterSymErrCnt",
    "overflowExtCnt",
    "overflowIntCnt",
    "overflowIntTraCnt",
    "optLevel",
    "vendor",
    "partNo",
    "revision",
    "temperature",
    "powerSupply",
    "txBias",
    "txPower",
    "rxPower",
)
_TRANSCEIVER_KEYS: Final[tuple[str, ...]] = (
    "optLevel",
    "revision",
    "temperature",
    "powerSupply",
    "txBias",
    "txPower",
    "rxPower",
)
_RSTP_INACTIVE_ROLES: Final[frozenset[str]] = frozenset({"", "nonstp", "unknown"})


def _int(value: Any) -> int | None:
    try:
        result = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return result if result >= 0 else None


def _mac_from_octets(value: Any) -> str:
    """``0x001122334455`` (prettyPrint of a 6-byte OctetString) -> ``00:11:22:33:44:55``."""
    text = str(value or "").strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    text = text.replace(":", "").replace("-", "")
    if not re.fullmatch(r"[0-9a-f]{12}", text) or text == "0" * 12:
        return ""
    return ":".join(text[i : i + 2] for i in range(0, 12, 2)).upper()


def _sip_ethernet_statistics(sip_eth: dict, timestamp: datetime) -> NetworkStatistics | None:
    stats = NetworkStatistics(timestamp=timestamp)
    found = False
    for name in _SIP_ETHERNET_COUNTERS:
        value = _int(sip_eth.get(name))
        if value is None:
            continue
        found = True
        if name in _SIP_ETHERNET_FIELDS:
            direction, field = _SIP_ETHERNET_FIELDS[name]
            setattr(getattr(stats, direction), field, value)
        else:
            stats.extra[utils.convert_to_snake_case(name)] = value
    return stats if found else None


def _optical_channel(sip_optical: dict) -> int | None:
    """
    Position of the channel (0 = ``Ch1``, 1 = ``Ch2``) of the ``SipOptical``
    table row: the ``channel`` index of the table is 0..1 in the MIB.
    NOTE: snmp_walk() keys values by column name, so only the last row of the
    table (the "channel" column says which) is known.
    """
    chan_num = _int(sip_optical.get("channel"))
    return chan_num if chan_num in (0, 1) else None


def _channel_interfaces(
    sip_eth: dict, sip_optical: dict, iec_62439: dict, timestamp: datetime
) -> tuple[list[Interface], Redundancy | None]:
    """
    The two physical EN100 channels (``Ch1``, ``Ch2``) and the redundancy of the
    IP interface they belong to (PRP/HSR > RSTP > point-to-point failover).
    """
    channels = []
    for num in (1, 2):
        iface = Interface(name=f"Ch{num}", type="ethernet", physical=True)
        link = str(sip_eth.get(f"linkUpChan{num}", "")).strip()
        if link in ("linkUp", "1"):
            iface.connected = True
        elif link in ("linkDown", "0"):
            iface.connected = False
        opt_level = _int(sip_eth.get(f"optLevel{num}"))
        if opt_level is not None:
            # Optical Rx level in millivolts, "should be greater 2100 if LinkUp"
            iface.extra["optical_rx_level_mv"] = opt_level
        channels.append(iface)

    # SipOptical per-channel table
    chan_num = _optical_channel(sip_optical)
    if chan_num is not None:
        iface = channels[chan_num]
        stats = NetworkStatistics(
            timestamp=timestamp,
            ingress=NetworkTraffic(
                packets=_int(sip_optical.get("rxPacket")),
                crc_errors=_int(sip_optical.get("filterCrcErrCnt")),
            ),
            egress=NetworkTraffic(packets=_int(sip_optical.get("txPacket"))),
        )
        for name in _SIP_OPTICAL_TABLE[3:11]:
            if _int(sip_optical.get(name)) is not None and name != "filterCrcErrCnt":
                stats.extra[utils.convert_to_snake_case(name)] = _int(sip_optical[name])
        iface.statistics = stats
        if sip_optical.get("vendor"):
            iface.description.vendor.name = str(sip_optical["vendor"]).strip()
        if sip_optical.get("partNo"):
            iface.description.model = str(sip_optical["partNo"]).strip()
        transceiver = {
            utils.convert_to_snake_case(k): str(sip_optical[k]).strip()
            for k in _TRANSCEIVER_KEYS
            if sip_optical.get(k) not in (None, "")
        }
        if transceiver:
            iface.extra["transceiver"] = transceiver

    redundancy = None
    node_type = str(iec_62439.get("nodeType", "")).strip().lower()
    if node_type in ("prpmode0", "prpmode1", "hsr"):
        protocol = "hsr" if node_type == "hsr" else "prp"
        mode = str(iec_62439.get("hsrLREMode", "")).strip() if protocol == "hsr" else node_type
        redundancy = Redundancy(protocol=protocol, mode=mode, members=["Ch1", "Ch2"])
        for key in ("nodeName", "versionName", "manufacturerName", "switchingEndNode"):
            if iec_62439.get(key) not in (None, ""):
                redundancy.extra[utils.convert_to_snake_case(key)] = iec_62439[key]
        if iec_62439.get("evaluateSupervision") not in (None, ""):
            redundancy.extra["evaluate_supervision"] = iec_62439["evaluateSupervision"]
        for iface, lan in zip(channels, ("A", "B"), strict=True):
            active = str(iec_62439.get(f"adapterActive{lan}", "")).strip()
            iface.redundancy = Redundancy(
                protocol=protocol,
                lan=lan,
                state="active" if active == "active" else "inactive" if active else "",
            )
    else:
        rstp = False
        for num, iface in enumerate(channels, start=1):
            role = str(sip_eth.get(f"rstpRoleChannel{num}", "")).strip()
            if role.lower() in _RSTP_INACTIVE_ROLES:
                continue
            rstp = True
            port = "A" if num == 1 else "B"
            iface.redundancy = Redundancy(
                protocol="rstp",
                role=role,
                state=str(sip_eth.get(f"rstpStatusChannel{num}", "")).strip(),
                partner=_mac_from_octets(sip_optical.get(f"rstpNeighbourPort{port}")),
            )
        active_chan = str(sip_eth.get("activChannel", "")).strip()
        if rstp:
            redundancy = Redundancy(protocol="rstp", members=["Ch1", "Ch2"])
        elif active_chan in ("activChannel1", "activChannel2"):
            # Point-to-point (line) mode: one channel active, the other standby
            redundancy = Redundancy(protocol="failover", members=["Ch1", "Ch2"])
            for num, iface in enumerate(channels, start=1):
                iface.redundancy = Redundancy(
                    protocol="failover",
                    state="active" if active_chan.endswith(str(num)) else "standby",
                )

    # Only keep channels the device reported something about
    channels = [
        iface
        for iface in channels
        if iface.connected is not None
        or iface.extra
        or iface.redundancy.protocol
        or iface.statistics.timestamp
    ]
    return channels, redundancy


def process_snmp_data(
    dev: DeviceData,
    module_info: dict,
    system_info: dict,
    timestamp: datetime | None = None,
) -> dict:
    """
    Process SNMP data (:meth:`Siprotec._get_snmp_data`) into the data model.

    - ``sysUpTime`` (TimeTicks, hundredths of a second) -> ``uptime``, ``start_time``
    - EN100 IP interface (MAC, netmask, status) with the SipEthernet module-wide
      counters as ``statistics`` (counters without a field in ``statistics.extra``)
    - per-channel interfaces ``Ch1``/``Ch2`` (link, optical level, SipOptical table,
      RSTP or PRP/HSR redundancy); the IP interface gets the PRP/HSR/RSTP redundancy
    - SipGoose counters -> ``Service(protocol="goose").statistics``
    - SNMP bad community counters -> ``Service(protocol="snmp").statistics``
    - SNTP servers -> ``clock.sources``

    ``system_uptime`` is removed from ``system_info``.

    Returns:
        The module data that was not mapped (identity keys, resource usage,
        RSTP bridge settings, ...), for ``dev.extra["module_<sysName>"]``
    """
    timestamp = timestamp or utils.utc_now()
    unmapped = {
        k: v
        for k, v in module_info.items()
        if k
        not in [
            "mac_address",
            "netmask",
            "ifAdminStatus",
            "ifOperStatus",
            "snmp_stats",
            "sip_ethernet",
            "sip_goose",
            "sip_optical",
            "iec_62439",
        ]
    }

    # sysUpTime is TimeTicks (1/100 s), not seconds or milliseconds
    ticks = _int(system_info.pop("system_uptime", None))
    if ticks is not None:
        dev.uptime = timedelta(seconds=ticks / 100)
        dev.start_time = timestamp - dev.uptime

    sip_eth = module_info.get("sip_ethernet") or {}
    sip_optical = module_info.get("sip_optical") or {}
    iec_62439 = module_info.get("iec_62439") or {}

    # EN100 IP interface
    ip_iface = Interface(name="EN100", type="ethernet")
    if dev.ip:
        ip_iface.ip = dev.ip
    if module_info.get("mac_address") and utils.is_mac(module_info["mac_address"]):
        ip_iface.mac = module_info["mac_address"]
    if module_info.get("netmask") and utils.is_ip(str(module_info["netmask"])):
        ip_iface.subnet_mask = str(module_info["netmask"])
    admin = module_info.get("ifAdminStatus", "")
    if admin in ("up", "down"):
        ip_iface.enabled = admin == "up"
    elif admin:
        ip_iface.extra["admin_status"] = admin
    oper = module_info.get("ifOperStatus", "")
    if oper == "up":
        ip_iface.connected = True
    elif oper in ("down", "lowerLayerDown", "notPresent", "dormant"):
        ip_iface.connected = False
    if oper and oper not in ("up", "down"):
        ip_iface.extra["oper_status"] = oper

    stats = _sip_ethernet_statistics(sip_eth, timestamp)
    if stats:
        ip_iface.statistics = stats

    channels, redundancy = _channel_interfaces(sip_eth, sip_optical, iec_62439, timestamp)
    if redundancy:
        ip_iface.redundancy = redundancy
    if sip_eth.get("activChannel") not in (None, "") and not redundancy:
        ip_iface.extra["active_channel"] = sip_eth["activChannel"]

    if ip_iface.ip or ip_iface.mac:
        dev.store("interface", ip_iface)
    for iface in channels:
        dev.store("interface", iface, lookup="name")

    # GOOSE: matched telegrams received; mismatched ones are not errors
    goose = module_info.get("sip_goose") or {}
    matched, mismatched = _int(goose.get("nRxMatchedTel")), _int(goose.get("nRxMismatchTel"))
    if matched is not None or mismatched is not None:
        goose_stats = NetworkStatistics(
            timestamp=timestamp, ingress=NetworkTraffic(messages=matched)
        )
        if mismatched is not None:
            goose_stats.extra["mismatched_telegrams"] = mismatched
        dev.store("service", Service(protocol="goose", statistics=goose_stats))

    # SNMP: bad community names = failed authentications (network scans)
    snmp_stats = module_info.get("snmp_stats") or {}
    if snmp_stats:
        svc_stats = NetworkStatistics(timestamp=timestamp)
        svc_stats.connections.authentication_failures = _int(
            snmp_stats.get("snmpInBadCommunityNames")
        )
        for key, extra_key in [
            ("snmpInBadVersions", "bad_versions"),
            ("snmpInBadCommunityUses", "bad_community_uses"),
        ]:
            if _int(snmp_stats.get(key)) is not None:
                svc_stats.extra[extra_key] = _int(snmp_stats[key])
        dev.store(
            "service",
            Service(protocol="snmp", port=161, transport="udp", statistics=svc_stats),
            interface_lookup={"ip": dev.ip} if dev.ip else None,
        )

    # SNTP servers
    master = str(sip_eth.get("sntpClockmaster", "")).strip()
    for priority, (key, name) in enumerate(
        [("sntpPrimaryServer", "primary"), ("sntpSecondaryServer", "secondary")], start=1
    ):
        address = str(sip_eth.get(key, "")).strip()
        if not utils.is_ip(address) or address in ("0.0.0.0", "255.255.255.255"):
            continue
        source = TimeSource(protocol="sntp", address=address, priority=priority)
        if master in ("primary", "secondary"):
            source.selected = master == name
        if not any(
            (s.protocol, s.address) == (source.protocol, source.address) for s in dev.clock.sources
        ):
            dev.clock.sources.append(source)
    if master in ("primary", "secondary") and not dev.clock.source:
        dev.clock.source = "sntp"

    # Unmapped SipEthernet resources and SipOptical RSTP bridge settings stay in
    # extra, and the SipOptical table row if its channel is unknown
    rest_eth = {
        k: v
        for k, v in sip_eth.items()
        if k not in _SIP_ETHERNET_COUNTERS and k not in _SIP_ETHERNET_MOVED
    }
    if rest_eth:
        unmapped["sip_ethernet"] = rest_eth
    optical_mapped = _optical_channel(sip_optical) is not None
    rest_optical = {
        k: v
        for k, v in sip_optical.items()
        if not (optical_mapped and k in _SIP_OPTICAL_TABLE)
        and k not in ("rstpNeighbourPortA", "rstpNeighbourPortB")
    }
    if rest_optical:
        unmapped["sip_optical"] = rest_optical

    return unmapped


def process_webmonitor_version(dev: DeviceData, parsed: dict) -> None:
    """
    Move the WebMonitor version from parsed ``VER.txt`` data
    (:meth:`Siprotec._parse_ver_txt`) to ``dev.software`` (modifies ``parsed``).
    """
    version = parsed.pop("webmonitor_version", "")
    build_date = parsed.pop("webmonitor_build_date", "")
    build_timestamp = parsed.pop("webmonitor_build_timestamp", "")
    if not version:
        return

    pkg = Package(
        name="WebMonitor",
        version=str(version).strip(),
        category="application",
        vendor="Siemens",
        description="Embedded web server of the EN100 Ethernet module",
    )
    if build_date:
        pkg.extra["build_date"] = build_date
    if build_timestamp:
        pkg.extra["build_timestamp"] = build_timestamp
    dev.store("software", pkg)


Siprotec.ip_methods = [
    IPMethod(
        name="Siprotec WebMonitor HTTP",
        description=str(Siprotec._get_webmonitor_data.__doc__).strip(),
        type="unicast_ip",
        identify_function=functools.partial(Siprotec._get_webmonitor_data, protocol="http"),
        reliability=7,
        protocol="http",
        transport="tcp",
        default_port=80,
    ),
    IPMethod(
        name="Siprotec WebMonitor HTTP",
        description=str(Siprotec._get_webmonitor_data.__doc__).strip(),
        type="unicast_ip",
        identify_function=functools.partial(Siprotec._get_webmonitor_data, protocol="https"),
        reliability=7,
        protocol="https",
        transport="tcp",
        default_port=443,
    ),
    IPMethod(
        name="Siprotec SNMP sysDescr",
        description=str(Siprotec._verify_snmp.__doc__).strip(),
        type="unicast_ip",
        identify_function=Siprotec._verify_snmp,
        reliability=8,
        protocol="snmp",
        transport="udp",
        default_port=161,
    ),
    # TODO: Verify IEC61850 (GOOSE) on 102/TCP
    #   See if there are any tags that would fingerprint it
    # TODO: verify DIGSI on port 50000/UDP
]


__all__ = ["Siprotec"]
