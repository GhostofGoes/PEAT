*********
Baselines
*********
A *baseline* is the expected state of a device: its factory defaults, a vendor hardening recommendation, an approved ("golden") configuration, or the state PEAT observed at an earlier pull. PEAT compares device data against baselines and reports every deviation as a *finding*. Typical uses:

- detect configuration drift between two pulls of the same device (change management, NERC CIP-010 R2);
- check devices against an approved configuration, or against a "typical device" profile of their type;
- flag devices that still use factory defaults or ignore vendor hardening guidance (open Telnet/FTP, factory-default passwords, key switch not in RUN).

Comparisons work on PEAT output (``device-data-full.json`` files, parse summaries), so they never query a device. They do no DNS or ARP lookups.

.. seealso::

   :class:`~peat.data.models.Baseline`, :class:`~peat.data.models.BaselineRule`, :class:`~peat.data.models.BaselineFinding` (:doc:`data_model`)

   :mod:`peat.api.baseline_api` and :mod:`peat.data.baseline` (:doc:`general_apis`)

   The baseline findings index (``ot-device-baseline-findings``): :doc:`database_schema`

   Declaring known defaults in a PEAT module: :ref:`declaring-known-defaults`


Concepts
========

Baseline
--------
A :class:`~peat.data.models.Baseline` has:

- ``id``, ``name``, ``description`` and ``version``;
- ``kind``: who or what produced the expected values (see below);
- ``scope``: ``device`` (one device) or ``device_type`` (every device of a type, a "device profile");
- ``selector``: which devices it applies to (:class:`~peat.data.models.BaselineSelector`). All non-empty selector fields must match the device, as case-insensitive :mod:`fnmatch` globs (e.g. ``firmware_version: "R5*"``). Fields: ``peat_module``, ``vendor_id``, ``model``, ``product``, ``part_number``, ``device_type``, ``firmware_version``, ``device_id``, ``serial_number``. A baseline whose selector does not match a device produces no findings for it;
- ``provenance``: where the expected values came from (:class:`~peat.data.models.BaselineProvenance`): creation time, author, source file and its SHA-256, source device, observation time, PEAT run ID and version, and approval (``approved_by``, ``approved``, ``change_ticket``);
- the expectations, as an ``expected`` :class:`~peat.data.models.DeviceData` snapshot, as ``rules``, or both;
- ``complete``: the snapshot is the complete observed state of the device (or device type), so values and list items that are absent from it are reported when they appear (see below);
- ``ignore``: extra path patterns to skip in snapshot comparisons.

Kinds
-----
.. csv-table::
   :header: "Kind", "Expected values", "Typical source"

   "``factory_default``", "Vendor out-of-box VALUES (e.g. Telnet listens on 23, relay ID is ``FEEDER 1``). A failed rule means *changed from the factory default* (severity ``info``).", "PEAT module known defaults"
   "``vendor_recommended``", "Vendor hardening guidance (e.g. Telnet absent, no factory default password accepted). A failed rule is a deviation from the recommendation.", "PEAT module known defaults"
   "``engineer_provided``", "An approved or golden configuration provided by an engineer.", "``peat parse`` of approved settings or project files"
   "``first_observed``", "The state when PEAT first saw the device (trust on first use).", "First PEAT pull or parse"
   "``previous_observed``", "The state at the previous pull (drift detection).", "Previous PEAT pull"
   "``approved``", "A reviewed baseline (NERC CIP-010 R1), typically an approved copy of another kind. An approved copy of an observed state is ``complete`` like the state it copies.", "Review of another baseline"

Snapshots and rules
-------------------
**Snapshot** (``expected``): the exported device data the device is expected to have. Each difference is one finding with ``result: fail`` and ``difference``:

- ``change``: the value differs;
- ``missing``: an expected value or list item (e.g. a service) is absent;
- ``unexpected``: a list item (e.g. a new service or user) is present but not expected.

Baselines that captured the complete device state also report new values (e.g. an ``os.name`` the snapshot does not have) and the items of lists the snapshot does not have (e.g. the first user or service of a device that had none) as ``unexpected``: ``first_observed`` and ``previous_observed`` baselines, and baselines with ``complete: true`` (:attr:`Baseline.complete <peat.data.models.Baseline.complete>`). ``peat baseline-create`` (:func:`~peat.api.baseline_api.create_baseline`) sets ``complete`` for the baselines it creates with the kinds ``first_observed``, ``previous_observed`` and ``approved``, and the flag stays when the ``kind`` of a saved baseline is changed. Other baselines (``engineer_provided``, ``vendor_recommended`` and ``factory_default`` snapshots, and hand-written baselines without ``complete: true``) only check the values they specify, so a partial "golden" snapshot can hold just the settings that matter. They still report new items of the lists they have.

List items are aligned by their identity, e.g. services by protocol, port and transport, users by name, files by path (``LIST_KEYS`` in :mod:`peat.data.baseline`), so the order of items never matters. Items without identity values (e.g. an interface with neither name nor address) are aligned by the values that are compared, never by ignored values such as their ``statistics``. Items that share an identity (e.g. two processes named ``python3``: processes are aligned by type and name, not by their PID) are paired by their compared values, not by their list order: each item is first paired with an item of the other side that has the same compared values, then with an unpaired snapshot item whose compared values it has (the first in the order of their compared values; an item of a partial snapshot, e.g. ``name: IPNET, version: "2.7"``, is paired with the device item with this name and version, which has more fields), the others in the order of their compared values. So processes that only got new PIDs have no findings, if one of two ``python3`` processes is gone, only that one is reported as ``missing``, and if a partial snapshot lists only one of the two versions of a package the device has, only the other version is reported as ``unexpected``. A service without a transport on one side (e.g. ``protocol: dnp3, port: 20000`` in a hand-written snapshot) is aligned with the service of the other side that has the same protocol and port and a transport (e.g. the ``dnp3`` service on ``20000/tcp`` of the device; PEAT sets the transport of many services, e.g. ``tcp`` for ``ftp``), if exactly one such service has no other match. If there are several (e.g. ``dns`` on ``53/tcp`` and ``53/udp``), none is aligned: the snapshot service ``protocol: dns, port: 53`` is reported as ``missing`` (``service[protocol=dns,port=53]``) and both device services as ``unexpected``, so give the transport of such services in the snapshot. A list that only one side has (empty lists are not exported) is compared item by item with an empty list, so each item is reported on its own and the noise rules below apply (e.g. a device whose only ARP neighbor is gone has no findings).

**Rules** (``rules``, :class:`~peat.data.models.BaselineRule`): constraints a snapshot cannot express, such as absence, negation, membership, patterns or ranges. Every enabled rule produces one finding with ``result`` ``pass``, ``fail``, ``unknown`` (no value to check) or ``error`` (e.g. a non-numeric value for ``min``), and ``difference: mismatch`` when it fails. A rule has a ``path``, an ``operator`` and a ``value``, plus ``id``, ``name``, ``category``, ``severity`` (default ``medium``), ``alert``, ``reason``, ``reference`` and ``standards``. ``reason`` may use ``{expected}``, ``{actual}`` and ``{path}``. The ``rule_id`` of the findings of a rule without an ``id`` is ``<path>:<operator>``, plus ``:<value as JSON>`` if the rule has a ``value`` (e.g. ``service[*].port:not_in:[23]``; :func:`~peat.data.baseline.rule_id`), so rules that check different values of the same path keep their own findings.

Paths
-----
Paths address the exported device data (the same structure as ``device-data-full.json``): ``segment(.segment)*``, where a segment is ``name``, ``name[key=value,...]`` (the list items whose fields have these values) or ``name[*]`` (all items of a list).

.. code-block:: text

   firmware.version
   extra.terminal_id
   service[protocol=ftp].enabled
   service[*].security.default_credentials
   users[name=ACC]
   iec61850.publications[type=GOOSE].security
   clock.utc_offset

Finding paths of snapshot differences use the identity of list items (only its non-empty fields, those of the expected item for an item that both sides have), e.g. ``service[protocol=http,port=80,transport=tcp]`` or ``files[path=/SETTINGS/SET_1.TXT].hash.sha256``, and a ``#n`` suffix for the second and further items that share an identity, e.g. ``processes[type=process,name=python3#1]``. File paths are always compared and written with ``/`` separators, whatever the OS that created the baseline or the device data (e.g. a baseline created on Linux can be compared on Windows).

Rule operators
--------------
.. csv-table::
   :header: "Operator", "``value``", "Passes when (for every value found at the path)", "No value found"

   "``equals``", "scalar", "every value equals ``value``", "``unknown``"
   "``not_equals``", "scalar", "no value equals ``value``", "``pass``"
   "``in``", "list", "every value is in the list", "``unknown``"
   "``not_in``", "list", "no value is in the list", "``pass``"
   "``present``", "", "at least one value exists", "``fail``"
   "``absent``", "", "no value exists", "``pass``"
   "``regex``", "pattern", "the pattern matches every value (Python :func:`re.search`)", "``unknown``"
   "``min``", "number", "every value is >= ``value``", "``unknown``"
   "``max``", "number", "every value is <= ``value``", "``unknown``"

Values are equal if they are equal or have the same text (JSON ``23`` equals ``"23"``; case-sensitive). The finding's ``actual`` holds the values that violated the rule.

Example rule:

.. code-block:: json

   {
       "id": "site.service.ftp.disabled",
       "name": "FTP disabled",
       "path": "service[protocol=ftp].enabled",
       "operator": "not_equals",
       "value": true,
       "category": "ports_services",
       "severity": "medium",
       "reason": "FTP (21/tcp, cleartext) is enabled",
       "standards": ["NERC CIP-007-6 R1.1"]
   }

Ignored values
--------------
Snapshot comparisons never compare values that are set by PEAT or the user instead of the device, that are stored in their own indices, or that change on every pull. The full list is ``DEFAULT_IGNORE`` in :mod:`peat.data.baseline`, including:

- ``label``, ``comment``, ``asset``, ``id``, ``related``, ``successful_pulls``, MAC vendors, and ``iec61850.scl_file`` (where PEAT read the SCL file, e.g. a path on the PEAT host for ``peat parse``);
- ``extra`` (unstructured), ``event``, ``memory``, UEFI data, ``baseline_findings``, raw ``original`` data and ``logic.formats``;
- the location of the ``logic``, ``firmware`` and ``boot_firmware`` files of the device and its modules (``path``, ``directory``, ``name``, ``extension``, ``mime_type``, ``owner``, ``group``, ``uid`` and ``gid``) if the file is only a file on the PEAT host: its ``path`` is its ``local_path``, because the module gave no path on the device. That is the file PEAT wrote to the device directory of the run (e.g. ``logic.txt``, ``firmware.bin`` or the ControlLogix ``parsed-logic.json``) or the input file of ``peat parse``, so its location changes with every run and differs between units. Its ``hash`` and ``size`` are compared;
- volatile values: uptimes, ``start_time``, all ``statistics``, live clock values (``clock.time``, ``clock.offset``, ...), the synchronization state (``clock.synchronized``), the active time source (``clock.source``) if the device reports it live (e.g. the SEL ``STA`` time source, which becomes ``internal`` when the IRIG-B signal is lost, or the protocol of the ``selected`` source in ``clock.sources``; a configured source selection, e.g. the Sage ``time.xml`` ``SOURCE``, is compared, and rules can check the live value), the live state of the time sources (``clock.sources`` ``state``, ``selected``, ``stratum``, ``offset`` and ``last_sync``; the configured sources are compared), live indicator states, process IDs and resource usage, relationship counters, times and ports (``local.port`` and ``remote.port``: the client port of a connection changes with every connection, and the server port is part of the relationship ``id``, so a new server port is reported as a missing and an unexpected relationship), PLC task scan times, file times, ``interface.connected``, the live redundancy state of interfaces (``redundancy.state``, ``role`` and ``partner``, e.g. the active port of a failover pair or an RSTP port role; the ``protocol``, ``mode``, ``lan`` and ``members`` are compared), and the ``status`` and ``process_pid`` of services (also those listed on interfaces).

These patterns also apply to the modules of a device (``module.*``), e.g. ``module.indicators.timestamp``.

``Baseline.ignore`` adds patterns (:mod:`fnmatch` syntax on paths without selectors; a pattern also matches everything below it), e.g. ``["firmware.version", "interface.description", "users.*"]``.

To reduce noise:

- files in the categories ``log``, ``event_record``, ``diagnostic`` and ``report`` change and appear on every pull: only their disappearance is reported, not changes or new files;
- relationships learned only from ARP, socket tables or logs come and go: a missing relationship is only reported if it was configured (``evidence`` ``config``, ``scl`` or ``user``). A *new* peer is always reported;
- the input files of ``peat parse`` (``files`` items whose ``path`` is their ``local_path``, e.g. an SCD file or a SEL ``SET_61850.CID`` file) are files on the PEAT host, not on the device: they are never reported as missing or unexpected, so the same SCD file parsed from another folder or under another name compares equal (an input file at the same path is still compared, e.g. its hash);
- routes of the type ``cache`` (transient route cache entries, one per recently used destination, e.g. from the FortiGate ``diagnose ip rtcache list``, see ``VOLATILE_ROUTE_TYPES`` in :mod:`peat.data.baseline`) and routes with a MAC address next hop (``extra.gateway_mac``: ARP entries, e.g. the host routes cloned from the ARP table in the GE UR routing table) are not compared: they are never reported as missing, new or changed, and a route table with only such entries is compared like an empty one (a new gateway they use is still reported as a new ``routes_via`` peer);
- a change of ``key_switch`` or ``run_mode`` has severity ``high`` (a strong tampering indicator).

Device type profiles
--------------------
A ``device_type`` baseline ("typical SEL-2032") describes every device of a type. It is built from one or more devices of ONE vendor and model, without per-unit identity (``DEVICE_TYPE_IGNORE`` in :mod:`peat.data.baseline`: addresses (also module interface addresses), names, serial numbers, file hashes, certificates, relationships, routes, IEC 61850 addressing, ...), the service listen addresses that are an address of the unit itself, and the input files of ``peat parse``. A wildcard (``0.0.0.0``, ``::``) or loopback listen address is part of the profile, so a service that moves from the loopback address to all addresses is reported. A service that moves from the address of the unit itself to all addresses is a new ``listen_address`` (``unexpected``): only complete profiles report it (``complete: true``, e.g. created with the kind ``first_observed`` or ``approved``). Profiles that only check what they specify do not report it, but they report the reverse move (from all addresses to the address of the unit) as a ``missing`` ``listen_address``. With several devices, the profile keeps only what all of them share, and the values that differ between them are added to ``ignore``. Its selector matches the vendor ID and model. Devices without a vendor ID (e.g. the IEDs of SCL files) must have the same vendor name (``description.vendor.name``, e.g. the SCL ``manufacturer``): the selector of their profile matches the model only, and the vendor name is compared as a value. Comparisons remove the same identity values from both sides.

Severity and categories
-----------------------
Rule findings use the rule's ``severity`` and ``category``. Snapshot differences use the category and severity of the area of the path, e.g. ``firmware``/``logic``/``serial_number`` ``high``, ``service``/``users``/``files``/``software``/``iec61850`` ``medium``, ``interface``/``routes``/``relationships``/``name`` ``low``. Severities are ``info``, ``low``, ``medium``, ``high`` and ``critical`` (``event.severity`` 1 to 5).

Findings
--------
:class:`~peat.data.models.BaselineFinding` records hold the baseline (``baseline_id``, ``baseline_name``, ``baseline_kind``, ``baseline_version``), the rule (``rule_id``, ``rule_name``, ``operator``), the ``path``, ``result``, ``difference``, ``expected`` and ``actual`` values (as JSON text, at most 4096 characters), ``severity``, ``category``, ``reason``, ``reference``, ``standards`` and the ``timestamp`` of the comparison. Comparing a device against a baseline again REPLACES the findings of that baseline.


Module known defaults
=====================
PEAT modules declare the factory defaults and vendor hardening recommendations of the devices they support (:attr:`DeviceModule.known_defaults <peat.device.DeviceModule.known_defaults>`): at most a ``<module>-factory-defaults`` baseline (``factory_default``, factory values) and a ``<module>-vendor-recommended`` baseline (``vendor_recommended``, hardening checks), each with rules only. ``--known-defaults`` uses the known defaults of the device's module, of the modules of the device's vendor, or of the modules given with ``-d``.

.. csv-table::
   :header: "Module", "Baselines", "Checks"

   ":class:`~peat.modules.sel.sel_relay.SELRelay`", "``sel-relay-factory-defaults``, ``sel-relay-vendor-recommended``", "Factory Telnet/FTP ports, relay ID (RID) and terminal ID (TID); FTP disabled, Telnet absent, no factory default password accepted, RID/TID changed from the factory values, GOOSE signed (``info``)"
   ":class:`~peat.modules.schneider.sage.sage.Sage`", "vendor recommended", "Telnet, FTP and HTTP absent, no factory default password accepted, no RTU setup placeholders"
   ":class:`~peat.modules.schneider.m340.m340.M340`", "vendor recommended", "No factory default FTP password accepted or SNMP ``public``/``private`` community configured, web server requires a password"
   ":class:`~peat.modules.rockwell.controllogix.ControlLogix`", "vendor recommended", "Key switch in RUN, no factory default password accepted"

Other modules declare no known defaults, e.g. :class:`~peat.modules.sel.sel_rtac.SELRTAC`: no factory default credential is known for RTACs, so a "no factory default password accepted" rule could never fail.

Print the current rules with ``peat baseline-show --known-defaults`` (all modules) or ``peat baseline-show --known-defaults -d <module>``. Module developers: see :ref:`declaring-known-defaults`.


Command line
============
Three commands work with baselines. Inputs are PEAT device data: ``device-data-full.json`` (or ``device-data-summary.json``) files, parse summaries (``parse-summary.json``), directories containing them (searched recursively, e.g. a run directory or ``peat_results/``), or ``-`` (JSON from standard input). The inputs can be given before or after the options, but not on both sides. If any file or device in an input fails to load (e.g. a truncated ``device-data-full.json`` in a directory), the command fails with exit code ``1``.

A run directory has the final (merged) state of each device: ``peat parse``, ``peat pull`` and ``peat scan`` write it to ``devices/<device id>/device-data-full.json`` at the end of the run (``device-data-full.json.1``, ``.2``, ... hold intermediate states, e.g. after each parsed file of a device, and are not read). A parse summary has an entry per parsed file and device, with the state of the device after that file: the last entry of each device (by device ID and ``id``) is used. That is the state after the device's last file (the entries are sorted by module: for a device parsed by several modules, after the last file of the last module). Use the run directory for the final state of every device, except devices that share a directory: devices whose IDs map to the same directory share it (e.g. IDs that differ only in case, or the SEL ``HISTORY.TXT`` and ``SER.TXT`` files of one relay, parsed as two devices with the relay's name), and with ``peat parse`` the final state of the later devices is then in a ``.1``, ``.2``, ... file, which is not read: use the parse summary for those devices.

Parse summaries and ``device-data-summary.json`` files do not have all device data: parse summaries have no ``relationships``, and device summaries also no ``files``, ``registers``, ``tag``, ``io``, ``event`` and ``memory``. These keys are not compared for such inputs, and a baseline created from them adds them to its ``ignore`` list (with a warning). The format of other inputs (``-``, files with other names) is not known, and empty lists are absent from every format: a device that has none of these lists is treated like a device summary, and a device without ``relationships`` like a parse summary (e.g. the host documents printed by ``peat pull -E``). Lists such an input has are compared. Use ``device-data-full.json`` files for complete comparisons: only they report the disappearance of all items of these lists.

``peat baseline-create``
------------------------
Creates baselines from device data. With ``--scope device`` (default), one baseline per device; with ``--scope device_type``, one profile of all the given devices (which must have the same vendor and model; the vendor is the vendor ID, or the vendor name of devices without one). Options: ``--kind`` (default ``first_observed``), ``--baseline-id``, ``--baseline-name``, ``--baseline-version`` (default ``1``), ``--author`` (default: the OS user name) and ``--description``. The baselines are written to ``-w/--write-file`` (a JSON list if there are several), or to ``<run dir>/baselines/baseline-<device id>.json`` (a device ID of more than 200 bytes in UTF-8 is cut, so the file name stays within the 255-byte limit of file systems). ``-E`` also prints them. A device that is in several inputs gets a baseline from each input (``baseline-<device id>-2.json``, ...); their default IDs can be the same, e.g. if the inputs have the same observation time (a warning is logged): give them unique IDs.

Default IDs are ``<device id>@<observation time>`` (e.g. ``192.0.2.10@20261030T120000Z``) and ``<vendor>-<model>-typical`` (e.g. ``SEL-2032-typical``, with the case of the vendor ID, or vendor name, and model). A device baseline applies to the device with the same ``id`` (normally its IP address, else its host name, name or MAC address); edit the ``selector`` to match on other fields, e.g. the serial number. The glob characters ``*``, ``?`` and ``[`` in the selector values of a new baseline are escaped (e.g. ``[[]``), so they match only themselves (e.g. the ID ``TEMPLATE@bay[1]`` of an IED in an ICD file).

Baselines of the kinds ``first_observed`` (default), ``previous_observed`` and ``approved`` are complete (``complete: true``): they report values and list items the device did not have when they appear. Baselines of the other kinds only check what they specify.

``peat baseline-compare``
-------------------------
Compares device data against baseline files (``-b/--baseline``, repeatable) and/or the known defaults of PEAT modules (``--known-defaults``, limited to modules with ``-d``). ``--no-passed`` omits the findings of passed rules.

Output:

- a table of the findings that did not pass, per device, and a summary line (or, with ``-E``, JSON: ``{"devices": [{"device_id", "source", "baselines", "summary", "findings"}]}``);
- ``<run dir>/devices/<device id>/baseline-findings.json`` (the findings of each device) and ``<run dir>/summaries/baseline-summary.json``;
- the ``ot-device-baseline-findings`` index, if Elasticsearch or OpenSearch is configured (``-e``). Host documents are not pushed again.

Example output:

.. code-block:: text

   Device 192.0.2.10 (baselines: 192.0.2.10@20261030T120000Z)
   SEVERITY  RESULT   DIFFERENCE  PATH                                          REASON
   high      fail     change      firmware.version                              firmware.version changed compared to baseline '192.0.2.10 first_observed'
   medium    fail     missing     service[protocol=ftp,port=21,transport=tcp]   service[protocol=ftp,port=21,transport=tcp] missing compared to baseline '192.0.2.10 first_observed'
   medium    fail     unexpected  service[protocol=http,port=80,transport=tcp]  service[protocol=http,port=80,transport=tcp] unexpected compared to baseline '192.0.2.10 first_observed'
   192.0.2.10: 3 findings, 3 failed, 0 passed (max severity: high)

Exit codes (of all ``baseline-*`` commands; ``3`` only of ``baseline-compare``):

- ``0``: success, even if there are findings;
- ``1``: error (invalid option combinations, e.g. no ``-b`` or ``--known-defaults``, or ``--baseline-id`` with several devices; unreadable inputs or baseline files, a baseline file that can't be written, no device data, no baseline applies to any device, failed Elasticsearch export);
- ``2``: invalid command line (an unknown option, or an invalid ``--kind``, ``--scope`` or ``--fail-on`` value);
- ``3``: ``--fail-on SEVERITY`` was given and a failed finding has that severity or higher (for scripts, CI jobs and scheduled checks).

``peat baseline-show``
----------------------
Prints baselines as JSON: from files (``-b``) and/or the known defaults of PEAT modules (``--known-defaults``, limited to modules with ``-d``).

Examples
--------
.. literalinclude:: ../peat/cli_args.py
   :name: Baseline create examples
   :language: python
   :start-after: baseline_create_examples = """
   :end-before: """  # End baseline-create examples

.. literalinclude:: ../peat/cli_args.py
   :name: Baseline compare examples
   :language: python
   :start-after: baseline_compare_examples = """
   :end-before: """  # End baseline-compare examples

.. literalinclude:: ../peat/cli_args.py
   :name: Baseline show examples
   :language: python
   :start-after: baseline_show_examples = """
   :end-before: """  # End baseline-show examples


Change management workflow (NERC CIP-010)
=========================================
#. Pull the device and create a ``first_observed`` baseline:

   .. code-block:: bash

      peat pull -i 192.0.2.10 -R relay-1-initial
      peat baseline-create -w relay-1-first.json peat_results/relay-1-initial/devices/

#. Review the baseline. Add the paths of values that should not be enforced to ``ignore`` instead of deleting them from ``expected``: the approved copy is complete (next step), so a value or list item that the snapshot does not have is reported as ``unexpected`` when the device has it. ``ignore`` patterns have no selectors, so they exempt a field of all items of a list (e.g. ``service.enabled``) or the whole list (e.g. ``service``), not a single item. Add rules for requirements, e.g. ports and services that must stay disabled.
#. Save an approved copy: set ``kind`` to ``approved``, a new ``id`` and ``version``, and ``provenance.approved_by``, ``provenance.approved`` and ``provenance.change_ticket``. Keep ``complete: true``, so the approved copy still reports values, accounts, services and peers the device did not have (e.g. the first user account of a device that had none). Keep the file under version control.
#. Compare every new pull against it (e.g. monthly, CIP-010 R2.1), and fail the job on relevant deviations:

   .. code-block:: bash

      peat pull -i 192.0.2.10
      peat baseline-compare -b relay-1-approved.json --known-defaults --fail-on medium -e http://localhost:9200 peat_results/<run>/

#. After an approved change, create a new baseline version from the pull that reflects the change.


Elasticsearch
=============
Findings are stored in ``ot-device-baseline-findings-<date>`` (one document per finding, see :doc:`database_schema`). The ECS fields follow the posture-management pattern: ``event.kind`` is ``alert`` for failed rules with ``alert: true``, ``event`` (with ``event.type`` ``change``, ``creation`` or ``deletion``) for drift against a ``previous_observed`` baseline, and ``state`` otherwise. ``event.action`` is ``baseline-check`` (passed), ``baseline-deviation`` (failed) or ``baseline-changed-from-default`` (failed ``factory_default`` check). ``rule.*`` describes the rule, ``baseline.*`` the baseline and the finding, and ``host.*`` the device.

Example KQL queries:

.. code-block:: text

   # Devices accepting factory default passwords
   rule.id : *default-credentials and baseline.finding.result : fail

   # High and critical deviations
   baseline.finding.result : fail and event.severity >= 4

   # Configuration drift since the previous pull
   baseline.kind : previous_observed and event.kind : event

   # Services that appeared or disappeared, on critical assets
   baseline.finding.path : service* and baseline.finding.difference : (missing or unexpected) and host.asset.criticality : (high_impact or extreme_impact)

   # Settings changed from the factory default
   event.action : baseline-changed-from-default

   # Units that differ from a "typical SEL-2032" profile (baseline.id is case-sensitive:
   # the default ID <vendor>-<model>-typical keeps the case of the vendor ID, or vendor
   # name, and model)
   baseline.id : "SEL-2032-typical" and baseline.finding.result : fail


Python API
==========
The same functionality is available from Python (:mod:`peat.api.baseline_api`):

.. code-block:: python

   from peat import compare_to_baseline, create_baseline, load_baselines, save_baselines
   from peat.api.baseline_api import load_device_data, summarize_findings

   (dev,) = load_device_data("peat_results/run1/devices/192.0.2.10/device-data-full.json")
   baseline = create_baseline(dev, "first_observed", author="J. Engineer")
   save_baselines(baseline, "relay-1.json")

   (current,) = load_device_data("peat_results/run2/devices/192.0.2.10/")
   findings = compare_to_baseline(current, load_baselines("relay-1.json"))
   print(summarize_findings(findings))

:func:`~peat.api.baseline_api.compare_to_known_defaults` compares a device against the known defaults of its module. Findings are stored in ``dev.baseline_findings`` and exported to ``device-data-baseline_findings.jsonl`` and the findings index with the rest of the device data.

.. note::
   Do not call :meth:`~peat.data.models.DeviceData.populate_fields` (or ``export()``) on ``Baseline.expected``: it would derive and merge values and change the snapshot. Use :func:`peat.data.baseline.device_to_doc` to read it.
