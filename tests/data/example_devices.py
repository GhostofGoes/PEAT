"""
Example devices that use the data model additions of issue #48 (relationships,
statistics, indicators, clock, IEC 61850, processes, software, routes, VLANs,
redundancy, service security, asset context).

All values are synthetic (RFC 5737 documentation addresses). These builders are
shared by ``tests/data/test_models.py`` and ``tests/test_es_mappings.py``.
"""

from datetime import UTC, datetime, timedelta
from pathlib import PurePosixPath

from peat.data.models import (
    IEC61850,
    Clock,
    ConnectionStatistics,
    DeviceData,
    Event,
    File,
    HostProcess,
    IEC61850AccessPoint,
    IEC61850Address,
    IEC61850Header,
    IEC61850HistoryItem,
    IEC61850LogicalDevice,
    IEC61850Publication,
    IEC61850ReportControl,
    IEC61850Subscription,
    Indicator,
    Interface,
    LogicTask,
    NetworkStatistics,
    NetworkTraffic,
    Package,
    Redundancy,
    Relationship,
    RelationshipEndpoint,
    Route,
    Service,
    ServiceSecurity,
    TimeSource,
    User,
    Vlan,
)

T0 = datetime(2026, 10, 30, 12, 0, 0, tzinfo=UTC)
T1 = T0 + timedelta(hours=1)

# config.HOSTS entry used by siprotec() (patch it into config["CONFIG"]["HOSTS"])
SIPROTEC_HOSTS = [
    {
        "label": "siprotec-feeder-7",
        "identifiers": {"ip": "192.0.2.70"},
        "asset": {
            "id": "AT-00071",
            "criticality": "high",
            "owner": "Protection Engineering",
            "site": "Substation North",
            "zone": "station-bus",
            "purdue_level": "L1",
            "safety": True,
            "tags": ["protection", "feeder"],
        },
    }
]


def sel_relay() -> DeviceData:
    """SEL-351S-like protection relay."""
    dev = DeviceData(ip="192.0.2.10", name="FEEDER 1", type="Relay")
    dev.description.vendor.id = "SEL"
    dev.description.model = "351S"
    dev.firmware.version = "R516"
    dev.status = "enabled"
    dev.health = "normal"
    dev.store(
        "interface",
        Interface(
            name="Port 5",
            type="ethernet",
            ip="192.0.2.10",
            subnet_mask="255.255.255.0",
            gateway="192.0.2.1",
            statistics=NetworkStatistics(
                timestamp=T0,
                ingress=NetworkTraffic(bytes=1664082074, errors=0),
                egress=NetworkTraffic(bytes=1463657022, errors=0),
                extra={"overflowed": ["ingress.packets", "egress.packets"]},
            ),
            redundancy=Redundancy(protocol="failover", mode="failover", members=["5A", "5B"]),
        ),
    )
    dev.store(
        "interface",
        Interface(
            name="5A",
            type="ethernet",
            physical=True,
            connected=True,
            speed=100,
            duplex="full",
            redundancy=Redundancy(protocol="failover", state="active"),
        ),
    )
    dev.store(
        "interface",
        Interface(
            name="Port 3",
            type="rs_232",
            serial_port="Port 3",
            application="dnp3",
            baudrate=9600,
        ),
    )
    dev.store(
        "service",
        Service(
            protocol="dnp3",
            port=20000,
            transport="tcp",
            protocol_id="10",
            enabled=True,
            status="open",
        ),
    )
    dev.store("service", Service(protocol="mms", port=102, enabled=True))
    dev.store("service", Service(protocol="goose", enabled=True, role="publisher"))
    dev.store(
        "service",
        Service(
            protocol="telnet",
            port=23,
            status="open",
            security=ServiceSecurity(
                authentication_required=True,
                default_credentials=True,
                encrypted=False,
                authentication_methods={"password"},
            ),
        ),
    )
    dev.store(
        "service",
        Service(
            protocol="ftp",
            port=21,
            enabled=False,
            security=ServiceSecurity(anonymous_access=False),
        ),
    )
    # DNP3 master from the configuration, and the same master observed in a
    # socket table (no protocol/interface/addresses/direction, ephemeral client
    # port): ONE relationship.
    dev.store(
        "relationships",
        Relationship(
            protocol="dnp3",
            transport="tcp",
            direction="ingress",
            evidence={"config"},
            enabled=True,
            local=RelationshipEndpoint(
                interface="Port 5", port=20000, role="outstation", protocol_address="10"
            ),
            remote=RelationshipEndpoint(ip="192.0.2.50", role="master", protocol_address="1"),
            extra={"control_operations_enabled": True, "station_num": 1},
        ),
    )
    for client_port, count in ((49152, 3), (49153, 1)):
        dev.store(
            "relationships",
            Relationship(
                transport="tcp",
                evidence={"netstat"},
                local=RelationshipEndpoint(ip="192.0.2.10", port=20000),
                remote=RelationshipEndpoint(ip="192.0.2.50", port=client_port),
                state="established",
                first_seen=T0,
                last_seen=T1,
                count=count,
            ),
        )
    dev.store(
        "indicators",
        Indicator(
            name="TLED12",
            label="TRIP",
            type="led",
            category="target",
            color="red",
            latched=True,
            equation="TRIP",
            position="0.1",
        ),
    )
    dev.store(
        "indicators",
        Indicator(name="TLED12", type="led", state="Lit", timestamp=T0, health="failure"),
    )
    dev.store(
        "indicators",
        Indicator(
            name="EN",
            label="ENABLED",
            type="led",
            state="on",
            color="green",
            position="0.0",
            timestamp=T0,
        ),
    )
    dev.clock = Clock(
        time=T0 + timedelta(seconds=2.5),
        observed=T0,
        utc_offset="-07:00",
        source="irig_b",
        sources=[
            TimeSource(protocol="sntp", address="192.0.2.5", priority=1, enabled=True),
            TimeSource(protocol="sntp", address="192.0.2.6", priority=2, enabled=True),
            TimeSource(protocol="irig_b", address="IRIG-B", selected=True),
        ],
    )
    dev.iec61850 = IEC61850(
        ied_name="FEEDER1",
        manufacturer="SEL",
        ied_type="SEL_351S",
        config_version="1.0",
        scl_file="/SETTINGS/SET_61850.CID",
        header=IEC61850Header(
            file_type="CID",
            scl_version="2007B4",
            id="FEEDER1",
            version="1",
            revision="3",
            tool_id="AcSELerator Architect",
            history=[
                IEC61850HistoryItem(
                    version="1", revision="3", when="2026-01-05", who="eng", what="GOOSE added"
                )
            ],
        ),
        access_points=[
            IEC61850AccessPoint(
                name="S1",
                subnetwork="StationBus",
                subnetwork_type="8-MMS",
                ip="192.0.2.10",
                subnet_mask="255.255.255.0",
                gateway="192.0.2.1",
                mms_port=102,
                server=True,
                authentication={"none"},
                osi={"OSI-TSEL": "0001"},
            )
        ],
        logical_devices=[
            IEC61850LogicalDevice(
                inst="PRO",
                name="FEEDER1PRO",
                access_point="S1",
                logical_nodes=["LLN0", "LPHD1", "PTOC1", "XCBR1"],
            )
        ],
        publications=[
            IEC61850Publication(
                type="GOOSE",
                name="gcbTrip",
                ld_inst="PRO",
                reference="FEEDER1PRO/LLN0$GO$gcbTrip",
                id="TRIP",
                dataset="dsTrip",
                dataset_members_count=4,
                conf_rev=2,
                security="None",
                address=IEC61850Address(
                    mac="01-0c-cd-01-00-10", appid=0x1000, vlan=Vlan.from_hex("064", 4)
                ),
                min_time=4,
                max_time=1000,
                subscribers=["BUS1"],
            ),
        ],
        report_controls=[
            IEC61850ReportControl(
                name="urcbA",
                ld_inst="PRO",
                ln="LLN0",
                report_id="A",
                dataset="dsMeas",
                buffered=False,
                trigger_options={"dchg", "gi"},
                max_clients=2,
                clients=["HMI1"],
            )
        ],
        subscriptions=[
            IEC61850Subscription(
                service_type="GOOSE",
                publisher_ied="BUS1",
                publisher_ld_inst="PRO",
                control_block="gcbBF",
                ext_ref_count=2,
            )
        ],
        datasets_count=3,
        setting_groups=6,
        active_setting_group=1,
        capabilities={"GOOSE": {"max": "8"}},
        extra={"lib61850_id": "0x1234"},
    )
    dev.store(
        "files",
        File(
            path=PurePosixPath("/SETTINGS/SET_1.TXT"),
            type="file",
            category={"settings", "configuration"},
            original=b'RID,"FEEDER 1"',
        ),
    )
    dev.store(
        "files",
        File(
            path=PurePosixPath("/SETTINGS/SET_61850.CID"),
            type="file",
            category={"configuration", "IEC61850"},
        ),
    )
    dev.store(
        "event",
        Event(
            action="trip",
            reason="Trip; targets 51G",
            severity="INFO",
            created=T0,
            sequence=1,
            dataset="history",
            kind={"alert"},
        ),
    )
    dev.store(
        "event",
        Event(
            action="settings-changed",
            reason="Class P 5",
            severity="3",
            created=T1,
            sequence=2,
            dataset="ser",
            code="SETCHG",
        ),
    )
    dev.logic.name = "SET_ALL"
    dev.extra["terminal_id"] = "STATION A"
    return dev


def controllogix() -> DeviceData:
    """ControlLogix-like PLC with a communications module."""
    dev = DeviceData(ip="192.0.2.20", type="PLC", key_switch="remote", run_mode="REMOTE RUN")
    dev.description.vendor.id = "Rockwell"
    dev.description.model = "1756-L83E"
    dev.health = "maintenance_required"
    dev.store(
        "interface",
        Interface(
            name="eth0",
            type="ethernet",
            ip="192.0.2.20",
            mac="00:00:BC:11:22:33",
            statistics=NetworkStatistics(
                timestamp=T0,
                ingress=NetworkTraffic(unicast_packets=10, errors=1),
                egress=NetworkTraffic(unicast_packets=12),
                link_down_count=2,
            ),
        ),
    )
    for transport, kwargs in (
        ("tcp", {"connections": ConnectionStatistics(active=3, total=55, failed=1, resets=2)}),
        ("udp", {"ingress": NetworkTraffic(packets=100, errors=0)}),
        ("icmp", {"ingress": NetworkTraffic(messages=9)}),
    ):
        dev.store(
            "protocol_statistics", NetworkStatistics(timestamp=T0, transport=transport, **kwargs)
        )
    dev.store(
        "protocol_statistics",
        NetworkStatistics(timestamp=T0, type="ipv4", ingress=NetworkTraffic(packets=1000)),
    )
    # newer sample of the same scope: replaces the older one wholesale
    dev.store(
        "protocol_statistics",
        NetworkStatistics(
            timestamp=T1, transport="tcp", connections=ConnectionStatistics(active=4, total=60)
        ),
    )
    dev.store(
        "relationships",
        Relationship(
            type="communicates_with",
            protocol="cip",
            transport="tcp",
            direction="ingress",
            state="established",
            evidence={"netstat"},
            local=RelationshipEndpoint(ip="192.0.2.20", port=44818, role="target"),
            remote=RelationshipEndpoint(ip="192.0.2.99", port=51123, role="originator"),
        ),
    )
    dev.store(
        "relationships",
        Relationship(
            type="neighbor_of",
            evidence={"arp"},
            local=RelationshipEndpoint(interface="eth0"),
            remote=RelationshipEndpoint(ip="192.0.2.99", mac="00:11:22:33:44:55"),
        ),
    )
    dev.store(
        "routes",
        Route(destination="default", gateway="192.0.2.1", interface="eth0", type="static"),
    )
    dev.store(
        "routes",
        Route(destination="192.0.2.0/255.255.255.0", interface="eth0", type="connected"),
    )
    dev.store(
        "indicators",
        Indicator(
            name="key_switch",
            type="switch",
            category="mode",
            value="REMOTE RUN",
            timestamp=T0,
            extra={"status_word": "0x3160"},
        ),
    )
    dev.store(
        "indicators",
        Indicator(
            name="minor_recoverable_fault",
            type="status_flag",
            category="fault",
            state="on",
            timestamp=T0,
            health="maintenance_required",
        ),
    )
    dev.logic.tasks = [
        LogicTask(
            name="MainTask",
            type="continuous",
            priority=10,
            watchdog=0.5,
            programs=["MainProgram"],
            enabled=True,
        ),
        LogicTask(
            name="Periodic10ms",
            type="periodic",
            interval=timedelta(milliseconds=10),
            priority=5,
            programs=["Fast"],
            scan_time_max=timedelta(microseconds=850),
        ),
        LogicTask(name="MainTask", scan_count=123),  # duplicate (merged by name)
    ]
    mod = DeviceData(slot="2", type="Communications Adapter")
    mod.store(
        "indicators", Indicator(name="OK", type="led", state="on", color="green", timestamp=T0)
    )
    mod.store(
        "relationships",
        Relationship(
            type="physical_link",
            medium="backplane",
            remote=RelationshipEndpoint(name="1756-A10", role="parent"),
        ),
    )
    dev.store("module", mod)
    return dev


def sage_rtu() -> DeviceData:
    """Sage-like VxWorks RTU."""
    dev = DeviceData(ip="192.0.2.30", type="RTU")
    dev.description.vendor.id = "Schneider"
    dev.os.name = "VxWorks"
    dev.store(
        "interface",
        Interface(
            name="fei0",
            type="ethernet",
            ip="192.0.2.30",
            statistics=NetworkStatistics(
                ingress=NetworkTraffic(packets=5000, bytes=2**64 - 1),
                egress=NetworkTraffic(packets=4000),
                collisions=0,
            ),
        ),
    )
    for name, tid, prio in (
        ("tNetTask", "0x1d8e4b0", 50),
        ("tTelnetd", "0x1d90000", 55),
        ("tNetTask", "0x1d8e4b0", 50),
    ):
        dev.store(
            "processes",
            HostProcess(
                name=name,
                pid=int(tid, 16),
                type="task",
                priority=prio,
                state="pended",
                extra={"task_id": tid, "stack_margin": 7800},
            ),
        )
    dev.store("software", Package(name="OpenSSL", version="1.0.1k", category="library"))
    dev.store("software", Package(name="ISaGRAF", version="5.2", category="plc_runtime"))
    dev.store(
        "software",
        Package(name="OpenSSL", version="1.0.1k", category="library", vendor="OpenSSL Project"),
    )
    dev.store("service", Service(protocol="telnet", port=23, process_pid=int("0x1d90000", 16)))
    dev.store(
        "routes",
        Route(destination="10.0.0.0/8", gateway="192.0.2.254", interface="fei0", metric=1),
    )
    return dev


def fortigate() -> DeviceData:
    """FortiGate-like firewall with VLAN interfaces and processes."""
    dev = DeviceData(ip="192.0.2.40", type="Firewall")
    dev.description.vendor.id = "Fortinet"
    dev.store(
        "interface",
        Interface(
            name="port1",
            type="ethernet",
            physical=True,
            vlans=[
                Vlan(id=100, tagged=True),
                Vlan(id="200", tagged=True),
                Vlan(id="100", name="scada"),
            ],
        ),
    )
    dev.store(
        "interface",
        Interface(
            name="vlan100",
            type="vlan",
            physical=False,
            parent="port1",
            ip="192.0.2.40",
            vlan=Vlan(id="100", tagged=True),
        ),
    )
    dev.store(
        "processes",
        HostProcess(
            name="miglogd",
            pid=191,
            type="process",
            state="sleeping",
            cpu_percent=0.3,
            memory_percent=6.3,
            extra={"state_code": "S"},
        ),
    )
    dev.store(
        "processes",
        HostProcess(
            executable="/bin/sshd",
            pid=812,
            user=User(name="admin"),
            args=["/bin/sshd", "-D"],
            command_line="/bin/sshd -D",
        ),
    )
    dev.store(
        "event",
        Event(
            action="login",
            outcome="failure",
            reason="passwd_invalid",
            code="0100032002",
            log_level="alert",
            created=T0,
            category={"authentication"},
            type={"start"},
        ),
    )
    dev.store(
        "files",
        File(path=PurePosixPath("/data/config/sys_config"), size=1234, category={"configuration"}),
    )
    return dev


def siprotec() -> DeviceData:
    """
    SIPROTEC-like relay with PRP channels. ``config.HOSTS`` should be
    patched with :data:`SIPROTEC_HOSTS` to get the asset context.
    """
    dev = DeviceData(ip="192.0.2.70", type="Relay")
    dev.description.vendor.id = "Siemens"
    for lan in ("A", "B"):
        dev.store(
            "interface",
            Interface(
                name=f"Ch{1 if lan == 'A' else 2}",
                type="ethernet",
                physical=True,
                connected=lan == "A",
                redundancy=Redundancy(protocol="prp", lan=lan, state="active"),
                statistics=NetworkStatistics(timestamp=T0, ingress=NetworkTraffic(crc_errors=0)),
            ),
        )
    dev.store(
        "service",
        Service(
            protocol="goose",
            role="subscriber",
            statistics=NetworkStatistics(
                timestamp=T0,
                ingress=NetworkTraffic(messages=10000, errors=3),
                extra={"mismatched_telegrams": 3},
            ),
        ),
    )
    dev.store(
        "service",
        Service(
            protocol="snmp",
            port=161,
            statistics=NetworkStatistics(
                timestamp=T0, connections=ConnectionStatistics(authentication_failures=12)
            ),
            security=ServiceSecurity(security_mode="v2c"),
        ),
    )
    dev.clock = Clock(
        sources=[
            TimeSource(protocol="sntp", address="ntp1.example.org", priority=1),
            TimeSource(protocol="sntp", address="ntp2.example.org", priority=2),
        ],
        synchronized=True,
    )
    return dev


ALL_DEVICES = {
    "sel_relay": sel_relay,
    "controllogix": controllogix,
    "sage_rtu": sage_rtu,
    "fortigate": fortigate,
    "siprotec": siprotec,
}
