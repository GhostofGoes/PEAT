**********
Data model
**********
Documentation on PEAT's internal model for structuring and managing data from devices (a.k.a "device data").

Besides identity, hardware, firmware, logic, interfaces, services, files, users and events, the model covers:

- **Relationships** (:class:`~peat.data.models.Relationship`): configured and observed communication peers, ARP/LLDP neighbors, route next hops, time servers, serial links and IEC 61850 GOOSE/SV/report streams. Each relationship aggregates every observation of the same edge (configuration, socket tables, logs) and is exported to its own Elasticsearch index (``ot-device-relationships``).
- **Network statistics** (:class:`~peat.data.models.NetworkStatistics`): cumulative counters per interface, service, device, protocol layer and relationship.
- **VLANs and redundancy** (:class:`~peat.data.models.Vlan`, :class:`~peat.data.models.Redundancy`) on interfaces, plus ``related.vlans``.
- **Front-panel indicators** (:class:`~peat.data.models.Indicator`): LEDs, displays, key switches, pushbuttons, sensors and decoded status flags.
- **Processes, PLC tasks and software** (:class:`~peat.data.models.HostProcess`, :class:`~peat.data.models.LogicTask`, :class:`~peat.data.models.Package`).
- **Routes and time synchronization** (:class:`~peat.data.models.Route`, :class:`~peat.data.models.Clock`, :class:`~peat.data.models.TimeSource`).
- **Device health and mode**: ``DeviceData.health`` (NAMUR NE 107) and ``DeviceData.key_switch``.
- **Service security posture** (:class:`~peat.data.models.ServiceSecurity`): authentication, anonymous access, factory-default credentials, encryption.
- **Asset context** (:class:`~peat.data.models.Asset`): owner-supplied criticality, zone, Purdue level, owner, site and tags, read from the ``asset`` block of a ``hosts`` entry in the PEAT configuration file (see ``examples/peat-config.yaml``).
- **IEC 61850** (:class:`~peat.data.models.IEC61850`): SCL configuration summary (access points, logical devices, GOOSE/SV publications, report control blocks, subscriptions).
- **Baselines** (:class:`~peat.data.models.Baseline`, :class:`~peat.data.models.BaselineFinding`): expected device state (factory defaults, vendor recommendations, first observed state, engineer-provided configurations) and the findings of comparing devices against them, exported to their own index (``ot-device-baseline-findings``).
- **Event details**: ``Event.reason`` (ECS ``event.reason``), ``Event.code`` (ECS ``event.code``) and ``Event.log_level`` (ECS ``log.level``). Textual values of ``Event.severity`` are deprecated. ``annotate()`` keeps ``severity`` and ``log_level`` in sync: an empty ``severity`` is filled from ``log_level``, and an empty ``log_level`` from a textual ``severity``. Only numeric severities are exported as ECS ``event.severity``.

Working with data
=================
There are two ways to store and retrieve data:

- Directly via class attributes: ``dev.os.version = "7"``
- Using :meth:`.DeviceData.store` with a model class instance: ``dev.store("interface", Interface(ip="10.10.10.10"))``

Simple attribute values such as :attr:`~peat.data.models.DeviceData.architecture` or :attr:`~peat.data.models.DeviceData.type` should be assigned directly, e.g. ``dev.architecture = "x86_64"``.

Complex attributes that contain objects, such as ``interfaces`` (which is a :class:`list` of :class:`~peat.data.models.Interface`), should be set using :meth:`.DeviceData.store`.

General data can be retrieved directly via attribute access, e.g. ``os_ver = dev.os.version``. Complex objects (such as "services") are easily accessed using the :meth:`.DeviceData.retrieve` helper method, which will search and filter objects based on the desired attributes, e.g. the IP address or port of a interface. However, they can also be accessed directly as regular lists, if desired.

Identity, merging and deduplication
-----------------------------------
:meth:`.DeviceData.store` merges a new item into an existing item of the list if they match the ``lookup``. Without an explicit ``lookup``, models that define identity fields are matched on ALL of them (exact match). The first stored item wins: existing values are kept and empty fields are filled from the new item. Deduplication of lists (:func:`~peat.data.data_utils.dedupe_model_list`, run on export) uses the same identity fields and also keeps the first item.

.. csv-table:: Identity fields of list models
   :header: "Model", "Identity fields", "Notes"

   ":class:`~peat.data.models.Interface`", "``name``", "``store()`` also matches ``mac``, ``ip``, ``serial_port``, ``id``"
   ":class:`~peat.data.models.Service`", "``protocol``, ``port``, ``transport``", "``store()`` without a ``lookup`` merges into the first service with the same ``protocol``, else the same ``port``; de-duplication keeps ``tcp/53`` and ``udp/53`` apart, also when one of them is ``open`` or ``verified``"
   ":class:`~peat.data.models.Relationship`", "``id``", "computed by ``annotate()`` from the edge (see below)"
   ":class:`~peat.data.models.NetworkStatistics`", "``interface``, ``type``, ``transport``, ``protocol``", "``protocol_statistics`` entries"
   ":class:`~peat.data.models.Route`", "``destination``, ``gateway``, ``interface``", ""
   ":class:`~peat.data.models.TimeSource`", "``protocol``, ``address``, ``port``", ""
   ":class:`~peat.data.models.Indicator`", "``type``, ``name``, ``interface``", "definitions and live readings merge"
   ":class:`~peat.data.models.HostProcess`", "``type``, ``pid``, ``name``", ""
   ":class:`~peat.data.models.Package`", "``name``, ``version``, ``path``", ""
   ":class:`~peat.data.models.LogicTask`", "``name``", ""
   ":class:`~peat.data.models.Vlan`", "``id``", ""
   ":class:`~peat.data.models.BaselineFinding`", "``baseline_id``, ``rule_id``, ``path``", "a re-compare replaces the finding"

Some time-varying models are "newest wins" instead of "first wins": a newer :class:`~peat.data.models.NetworkStatistics` sample (``timestamp``) replaces the older sample wholesale (counters of different samples are never mixed); newer :class:`~peat.data.models.Indicator` readings (``timestamp``) and :class:`~peat.data.models.Clock` readings (``observed``) overwrite older values, and the newer ``Clock.sources`` win. The reading of the newer ``Indicator`` (``state``, ``value``, ``health``, ``blink_rate``; its ``extra`` keys win) and the device ``time``/``offset`` of the newer ``Clock`` are kept even when empty (e.g. an unknown ``state``), whichever of the two was stored first; configured fields such as ``label``, ``latched`` or ``equation`` still fill gaps. On equal timestamps (two reads can get the same time from a coarse clock, e.g. on Windows) the sample stored later wins, if it adds a reading. Modules MUST set these timestamps with ``utils.utc_now()``. Relationships aggregate their observations: ``evidence`` is the union, ``first_seen`` the minimum, ``last_seen`` the maximum and ``count`` the maximum.

Modules MUST aggregate high-volume observations (log lines, connection logs, ARP refreshes) per peer before calling ``store()`` (one ``store()`` per relationship with ``count``/``first_seen``/``last_seen``).

Dates and times
---------------
Times reported by a device without a timezone ("naive" datetimes) are device-local time, the same convention as ``Event.created``: modules store them as reported (they never guess UTC). When the device's timezone is known (``DeviceData.geo.timezone``), annotation localizes the times of the new models (relationships, processes, time sources, statistics) with it (resolved with the system time zone database, else with the one bundled with ``python-dateutil``, e.g. on Windows), otherwise they are assumed to be UTC. ``Clock.time`` uses ``Clock.utc_offset`` when it is set. Times observed by PEAT itself (``NetworkStatistics.timestamp``, ``Indicator.timestamp``, ``Clock.observed``) MUST be timezone-aware UTC (``utils.utc_now()``). Sorting compares naive and aware datetimes safely (naive values are compared as UTC).

Secrets
-------
Never store secrets (passwords, SNMP community strings, keys) in any field. Credential facts are recorded as booleans in :class:`~peat.data.models.ServiceSecurity`: ``default_credentials`` is ``True`` only when a login with a vendor factory-default credential succeeded (:meth:`~peat.device.DeviceModule.is_factory_default_credential`) or the device configuration shows a factory-default credential in use (e.g. an M340 SNMP community ``public``/``private``), ``False`` only when the factory defaults were tried and rejected or the configured credentials are known and none is a factory default, and unset otherwise. Anonymous logins set ``anonymous_access=True`` and ``authentication_required=False``.

Lists of objects in Elasticsearch
---------------------------------
List fields of the host document (``host.interface``, ``host.indicators``, ``host.processes``, ...) are mapped as ``object``, not ``nested`` (Kibana Lens cannot aggregate ``nested`` fields). Object arrays do **not** keep the fields of one list item together: ``host.indicators.name:RUN and host.indicators.state:off`` also matches a device whose RUN LED is on and whose ERR LED is off. Use one of:

- the per-item indices: ``ot-device-relationships`` (one document per relationship) and ``ot-device-baseline-findings`` (one document per finding);
- the derived flattened field ``host.indicator_states.<name>`` (e.g. ``host.indicator_states.RUN:off``), which holds the live state or value of every indicator;
- the Python API (``peat.data.models``) for other correlated questions.

Routes and default gateways
---------------------------
A configured default gateway of an interface is stored in :attr:`Interface.gateway <peat.data.models.Interface.gateway>` (``host.interface.gateway``), e.g. by the SEL relay, M340, Totus, Windows CE, ControlLogix and IEC 61850 SCL (access point) modules. :attr:`DeviceData.routes <peat.data.models.DeviceData.routes>` (``host.routes``) holds the routing table entries the device reports (static, connected or learned routes). Some modules also report the default route there as ``0.0.0.0/0``, e.g. the Sage VxWorks boot line gateway and FortiGate static routes. PEAT does not derive routes from ``Interface.gateway``, and only route gateways become ``routes_via`` relationships. To find the default gateways of all devices, query both fields, e.g. ``host.interface.gateway:* or host.routes.destination:"0.0.0.0/0"``, with terms aggregations on ``host.interface.gateway`` and ``host.routes.gateway``. ``host.routes.gateway`` also holds the next hops of the other routes of a matching device (object arrays, see above).

Canonical vocabularies
======================
Use the same lowercase, underscore-separated names everywhere (``Service.protocol``, ``Relationship.protocol``, ``NetworkStatistics.protocol``, ``related.protocols``). A relationship uses the same protocol string as the device's own :class:`~peat.data.models.Service`.

Protocol names
--------------
.. csv-table::
   :header: "Name", "Protocol", "Transport / port", "Roles (``RelationshipEndpoint.role``)"

   "``modbus_tcp``", "Modbus TCP", "tcp/502", "``client`` / ``server``"
   "``modbus_rtu``", "Modbus RTU (serial)", "serial", "``client`` / ``server``"
   "``dnp3``", "DNP3", "tcp or udp/20000, serial", "``master`` / ``outstation``"
   "``iec101``, ``iec103``", "IEC 60870-5-101, IEC 60870-5-103", "serial", "``controlling_station`` / ``controlled_station``"
   "``iec104``", "IEC 60870-5-104", "tcp/2404", "``controlling_station`` / ``controlled_station``"
   "``c37_118``", "IEEE C37.118 synchrophasors", "tcp or udp/4712", "``pmu`` / ``pdc``"
   "``mms``", "IEC 61850 MMS (client/server, reports)", "tcp/102", "``client`` / ``server``"
   "``goose``", "IEC 61850 GOOSE", "Ethernet (L2 multicast)", "``publisher`` / ``subscriber``"
   "``sv``", "IEC 61850 Sampled Values", "Ethernet (L2 multicast)", "``publisher`` / ``subscriber``"
   "``cip``", "EtherNet/IP explicit messaging (CIP)", "tcp/44818", "``originator`` / ``target``, ``scanner`` / ``adapter``"
   "``enip``", "EtherNet/IP implicit I/O", "udp/2222", "``originator`` / ``target``"
   "``mirrored_bits``", "SEL MIRRORED BITS", "serial", "``peer``"
   "``sel``", "SEL ASCII/Fast Message", "serial, tcp", "``master`` / ``outstation``"
   "``bacnet``", "BACnet/IP", "udp/47808", "``client`` / ``server``"
   "``snmp``", "SNMP", "udp/161, traps udp/162", "``snmp_manager``"
   "``ntp``, ``sntp``", "(S)NTP", "udp/123", "``time_server``"
   "``ptp``", "IEEE 1588 PTP", "Ethernet, udp/319-320", "``time_server``"
   "``syslog``", "Syslog", "udp or tcp/514", "``log_server``"
   "``http``, ``https``", "HTTP(S)", "tcp/80, tcp/443", "``client`` / ``server``"
   "``ssh``, ``telnet``, ``ftp``", "SSH, Telnet, FTP", "tcp/22, tcp/23, tcp/21", "``client`` / ``server``"
   "``gdoi``, ``ocsp``, ``scep``", "GDOI key distribution, OCSP, SCEP (certificate services)", "udp/848, HTTP", "``gdoi_kdc``, ``ocsp_responder``, ``scep_server``"

Known spelling variants are normalized automatically: ``c37.118`` -> ``c37_118``, ``iec_104`` / ``iec60870_5_104`` -> ``iec104`` (``peat.data.validators.PROTOCOL_ALIASES``), and a :class:`~peat.data.models.Service` with ``protocol="modbus"`` and ``transport="tcp"`` becomes ``modbus_tcp``. ``cip`` and ``enip`` are different services and are not merged.

Other roles: ``client``, ``server``, ``peer``, ``gateway``, ``time_server``, ``log_server``, ``auth_server``, ``dns_server``, ``smtp_server``, ``snmp_manager``, ``parent``, ``child``, ``engineering_access``, ``io_provider`` (I/O data source), ``gdoi_kdc`` (GDOI key server), ``ocsp_responder``, ``scep_server``.

Relationship types
------------------
``Relationship.type`` reads as "``local`` <type> ``remote``":

- ``communicates_with``: configured or observed protocol session (the default). ``direction`` says who initiates. Allow-listed masters/clients are ``communicates_with`` with ``extra["allow_list"] = True``.
- ``allows_client``: pure access-list entry without a protocol session (e.g. an IP access-control table).
- ``neighbor_of``: ARP/ND/LLDP/CDP/FDB neighbor.
- ``routes_via``: route next hop (derived automatically from ``DeviceData.routes``, except next hops that are a loopback address or an address of the device, e.g. a ``lo0`` route via ``127.0.0.1``).
- ``syncs_time_from``: time server (derived automatically from ``DeviceData.clock.sources``, except loopback addresses, e.g. the NTP reference clocks ``127.127.x.y``, and addresses of the device).
- ``logs_to``: syslog server or log collector.
- ``authenticates_with``, ``depends_on`` (DNS, OCSP, KDC, I/O provider, ...), ``tunnel``.
- ``physical_link``: serial, backplane or point-to-point link.
- ``publishes_to``, ``subscribes_to``, ``reports_to``: IEC 61850 GOOSE/SV publications and subscriptions and MMS reports. Both ends of a stream share ``Relationship.reference`` (the control block reference).

``Relationship.evidence`` says how PEAT learned of the relationship: ``config``, ``scl``, ``arp``, ``nd``, ``lldp``, ``cdp``, ``fdb``, ``routing_table``, ``netstat``, ``log``, ``conn_log``, ``pcap``, ``live``, ``user``.

Media
-----
``Relationship.medium``: ``ethernet``, ``serial`` (electrical standard unknown), ``rs_232``, ``rs_422``, ``rs_485``, ``fiber_serial``, ``usb``, ``backplane``, ``wireless``, ``loopback``. If unset, it is copied from the ``type`` of the local interface when that value is in this vocabulary (``wifi``/``wlan`` -> ``wireless``).

Redundancy protocols
--------------------
``Redundancy.protocol``: ``prp``, ``hsr`` (IEC 62439-3), ``rstp``, ``stp``, ``mstp``, ``mrp``, ``dlr``, ``erps`` (ITU-T G.8032), ``hiper_ring``, ``ring`` (other ring protocols), ``lag`` (any link aggregation; the variant, e.g. ``802.3ad`` or ``active_backup``, goes in ``mode``), ``failover`` (active/standby ports), ``vrrp`` and ``ha`` (gateway/device pairs). Membership of LAG/PRP/failover ports is listed in ``redundancy.members`` of the aggregate interface; ``Interface.parent`` is only the single lower-layer interface of a VLAN sub-interface or alias.

Device health (NE 107)
----------------------
``DeviceData.health`` and ``Indicator.health`` use the NAMUR NE 107 categories: ``normal``, ``failure``, ``check_function``, ``out_of_specification``, ``maintenance_required`` and ``""`` (unknown). ``status``, ``run_mode`` and ``key_switch`` keep the raw device values. When several sources apply, the most severe value wins.

Relationship identity and inference
===================================
The identity of a relationship is the *edge*, not how it was observed. ``Relationship.id`` is the first 16 hex characters of the SHA-256 of :meth:`~peat.data.models.Relationship.key`, and is always recomputed by ``annotate()``:

- ``type`` (``communicates_with`` if empty);
- the server-side port (the local port for ``ingress``, the remote port for ``egress``, else the lower port); the ephemeral client port is ignored;
- ``protocol``, only if no port is known;
- the remote identity: ``remote.ip``, else ``remote.mac``, ``remote.hostname``, ``remote.name``, ``remote.address``;
- ``local.id`` (the module, for relationships stored on ``DeviceData.module``) and ``local.serial_port``;
- ``local.interface``, only for ``tunnel`` relationships (two tunnels to one gateway over different local interfaces are two relationships);
- the protocol addresses, only for edges without a remote IP and server port, and the VLAN, only for edges without a remote IP (L2 and serial edges);
- ``reference`` (IEC 61850 stream reference).

``transport``, ``local.interface`` (except for tunnels), ``local.ip``, roles and ``direction`` are attributes that merge. A configured DNP3 master and the socket-table sessions from it are therefore ONE record with ``evidence={"config", "netstat"}``. Several logical peers configured behind one edge (e.g. remote devices behind one gateway IP address and port) are also one relationship: modules combine them before storing it (e.g. ``extra["remote_devices"]`` of SEL RTAC client connections).

When fields are empty, ``Relationship.annotate()`` infers them:

- ``transport`` from protocols that use one transport only (e.g. ``modbus_tcp`` -> ``tcp``, ``snmp`` -> ``udp``);
- ``direction``: ``ingress`` if the local port is a port the device listens on (its own services), else ``egress`` if the remote port is well-known (below 1024 or a known OT port) and the local port is not, else ``ingress`` in the opposite case. A non-standard server port on both sides stays ``""``;
- the local port of an ``ingress`` record that names only the protocol (e.g. from a log line), from the device's own service;
- ``protocol`` and ``transport`` from the device's own service on the server port, else ``protocol`` from the well-known port (not for TCP port 102, which carries both IEC 61850 MMS and Siemens S7comm);
- ``local.interface`` from ``local.ip``, and ``medium`` from the local interface's ``type``.

Modules that know the direction or protocol set them explicitly. Relationships of modules (``DeviceData.module``) are moved to the parent device by ``populate_fields()``, keeping the module's identity in ``local.id``/``local.ip``/``local.name``.

DeviceData
==========
.. autopydantic_model:: peat.data.models.DeviceData

.. _data-models:

Data Models
===========
.. note::
   Most fields with a type of ``peat.data.models.ConstrainedStrValue`` are just :class:`str` type, but will automatically have any whitespace stripped when assigned to.

.. currentmodule:: peat.data.models

.. autosummary::

   Asset
   Baseline
   BaselineFinding
   BaselineProvenance
   BaselineRule
   BaselineSelector
   CertEntity
   Clock
   ConnectionStatistics
   Description
   Event
   File
   Firmware
   Geo
   Hardware
   Hash
   HostProcess
   IEC61850
   IEC61850AccessPoint
   IEC61850Address
   IEC61850Header
   IEC61850HistoryItem
   IEC61850LogicalDevice
   IEC61850Publication
   IEC61850ReportControl
   IEC61850Subscription
   Indicator
   IO
   Interface
   LatLon
   Logic
   LogicTask
   Memory
   NetworkStatistics
   NetworkTraffic
   OS
   Package
   ProcessParent
   Redundancy
   Register
   Related
   Relationship
   RelationshipEndpoint
   Route
   Service
   ServiceSecurity
   SSHKey
   Tag
   TimeSource
   UEFIFile
   UEFIHash
   Vendor
   Vlan
   X509

.. automodule:: peat.data.models
   :members:
   :exclude-members: DeviceData
