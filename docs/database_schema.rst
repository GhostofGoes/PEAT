.. _database-schema:

***************
Database Schema
***************
This section details the Elasticsearch database schema for PEAT. The objective with this schema is to establish common data structures that can be used to build visualizations and dashboards in Kibana.

Elastic Common Schema (`ECS <https://www.elastic.co/docs/reference/ecs/ecs-field-reference>`__) version: ``9.5.0``


Notes
=====
- **Elasticsearch is a NoSQL database, why is there a schema?** Because to share data between users and tools, the data should have a predictable format.
- The schemas here are descriptions of the :term:`JSON` fields expected of a "entry" in the Elasticsearch database (also known as a ``doc``).
- "Data Type" values are Elasticsearch data types (`reference <https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-types.html>`__). When storing as a plain :term:`JSON` file, ensure the format it is stored in either matches or can be cohered to the corresponding Elasticsearch format.
- Fields listed as ``required`` must be included in any docs that contain the parent field. If the field is at the root level, it is required for any docs in that index.
- Fields listed as ``optional`` do not have to be included in a doc push. However, any data that matches that field must use that field and not a custom field.
- Additional fields beyond those defined here are permitted, provided they're internally consistent (e.g. always the same for a version of a tool).
- These schemas follow the Elastic Common Schema (`ECS <https://www.elastic.co/docs/reference/ecs/ecs-field-reference>`__). Changes must adhere to the ECS, when possible.
- Free-text fields added for ECS 9.5.0 (e.g. ``event.reason``, ``relationship.description``, ``host.indicators.label``) are ``keyword`` fields limited to 1024 characters (``ignore_above``, like ECS keyword fields) with a full-text ``.text`` multi-field. Longer values are still stored in the document but are not searchable as keywords.
- Lists of objects (e.g. ``host.interface``, ``host.indicators``) are mapped as ``object`` (not ``nested``), so a query on two fields of the list can match fields of *different* list items. Use the per-item indices (relationships, baseline findings) or ``host.indicator_states`` for correlated queries (see :doc:`data_model`).


Indices
=======
This section lists the Elasticsearch indices (aka "indexes") used by PEAT, and what they are used for.

- **peat-logs-[year].[month].[day]**: Logs for PEAT. 1 document = 1 event.
- **ot-device-hosts-timeseries-[year].[month].[day]**: Results of PEAT pulls. 1 document = results from 1 device.
- **peat-scan-summaries-[year].[month].[day]**: Results of PEAT scans. 1 document = results from all devices in the scan.
- **peat-pull-summaries-[year].[month].[day]**: Results of PEAT pulls. 1 document = results from all devices in the scan.
- **peat-parse-summaries-[year].[month].[day]**: Results of PEAT parses. 1 document = results from all devices parsed.
- **peat-configs-[year].[month].[day]**: Configuration values used by PEAT for a run. 1 document = config values for a single PEAT run.
- **peat-state-[year].[month].[day]**: Internal state of PEAT for a run. 1 document = state values for a single PEAT run.
- **ot-device-files-[year].[month].[day]**: Files present on devices (from ``host.files``). 1 document = 1 file.
- **ot-device-registers-[year].[month].[day]**: Configured protocol data points (registers). 1 document = 1 register.
- **ot-device-tags-[year].[month].[day]**: Configured tag variables. 1 document = 1 tag.
- **ot-device-io-[year].[month].[day]**: Physical I/O points. 1 document = 1 I/O point.
- **ot-device-events-[year].[month].[day]**: Event logs and history extracted from devices. 1 document = 1 event.
- **ot-device-memory-[year].[month].[day]**: Memory reads from devices. 1 document = 1 memory read.
- **ot-device-relationships-[year].[month].[day]**: Configured and observed relationships between devices and other endpoints. 1 document = 1 relationship as observed by one PEAT run.
- **ot-device-baseline-findings-[year].[month].[day]**: Results of comparing devices against baselines. 1 document = 1 finding.
- **uefi-files-[year].[month].[day]**: Files from UEFI firmware images. 1 document = 1 file.
- **uefi-hashes-[year].[month].[day]**: Hashes of UEFI files. 1 document = 1 hash.

The base names of the indices can be changed in the PEAT configuration (``elastic_*_index`` settings, e.g. ``elastic_relationships_index``).

.. note::
   PEAT creates its indices with ``index.mapping.total_fields.limit`` set to ``20000``. The ``ot-device-hosts-timeseries`` mapping has about 2100 fields and the ``peat-parse-summaries`` mapping about 4100 fields, which is more than the Elasticsearch default limit of 1000. Indices or index templates created outside of PEAT (e.g. by Malcolm or OpenSearch templates) MUST raise ``index.mapping.total_fields.limit`` (5000 or more), otherwise documents will be rejected.

Universal Requirements
======================
- **ALL entries MUST include the Base and Agent field sets.**
- ALL timestamps MUST be in the :term:`UTC` timezone, in ISO 8601 format, and use the Elastic ``date`` data type.


Schema Update Process
=====================
There are a few ways the Schema we use will be updated:

- **ECS Schema Updates**: Elasticsearch regularly updates the Elastic Common Schema. We will bring in relevant changes from their updates into our schema.
- **PEAT Updates**: Updates to PEAT comes with new data in the database. Updates to this schema are included in this process.

.. _base-fields:

Base Fields
-----------
.. csv-table:: Base Fields
   :escape: \
   :file: field_references/base_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left

.. _agent-fields:

Agent Fields
------------
Information about the tool that generated the event (PEAT). ECS reference: `Agent Fields <https://www.elastic.co/docs/reference/ecs/ecs-agent>`__

.. csv-table:: Agent Fields
   :escape: \
   :file: field_references/agent_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left


PEAT Logs (``peat-logs-*``)
===========================
Logs from PEAT, such as errors or informational messages. Note that this does not include logs collected from OT devices by PEAT, those fall under ``ot-device-hosts-*``.

Notes
-----
- Index: ``peat-logs-<date>``, where ``date`` is, ``year.month.day`` in UTC. Example: ``peat-logs-2026.01.29``
- ``message``: Human-readable log message. No longer than 80 characters.
- Every entry includes the :ref:`base-fields` and :ref:`agent-fields`.
- The level and complete log entry text is contained in the ``log.*`` field set, defined below.
- Python :class:`logging.LogRecord` objects can be used to populate all of these fields (`logrecord attributes documentation <https://docs.python.org/3/library/logging.html#logrecord-attributes>`__).

Fields
------
ECS reference: `Log Fields <https://www.elastic.co/docs/reference/ecs/ecs-log>`__

.. csv-table:: Log Fields
   :escape: \
   :file: field_references/log_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left


OT Devices (``ot-device-hosts-timeseries-*``)
=============================================
:term:`OT` field device information collected by :term:`PEAT`.

Notes
-----
- Index: ``ot-device-hosts-timeseries-<date>``, where date is, ``year.month.day`` in UTC. Example: ``ot-device-hosts-timeseries-2026.01.29`` (for data collected on Jan 29th, 2026)
- ``message``: Human-readable description or summary of the device.
- Every entry includes the :ref:`base-fields` and :ref:`agent-fields`.
- All fields are nested under the ``host`` field, e.g. ``host.ip``.
- Nested and custom fields attempt to follow the ECS field set names where possible.
- Events that occur on the host and pertain to active status information, e.g. device power on/reset, service up, logic changed, etc, will be put into the ``ot-device-events-*`` index
- Some status attributes, such as system uptime, can be derived from device events or logs.

Additional notes on the fields

- Host documents are ECS asset inventory documents: they carry ``event.kind: asset``, ``event.category: [host]``, ``event.type: [info]`` and ``event.module`` (the PEAT module) at the document root.
- ``host.asset.*`` is owner-supplied asset context from the ``asset`` block of a ``hosts`` entry in the PEAT configuration file. ``host.asset.criticality`` uses the field name and values of Elastic Security asset criticality (``low_impact``, ``medium_impact``, ``high_impact``, ``extreme_impact``). Elastic Security keeps asset criticality in its own index: to use these values in Elastic Security, upload them with its asset criticality CSV import or API.
- ``host.tags`` (ECS 9.5.0) is a copy of ``host.asset.tags``.
- ``host.indicator_states`` is a derived, flattened summary ``{indicator name: state or value}`` of the live readings in ``host.indicators``, so that e.g. ``host.indicator_states.RUN:off`` is a single-term query.
- ``host.statistics.*``, ``host.protocol_statistics.*``, ``host.interface.statistics.*`` and ``host.service.statistics.*`` are cumulative counters as reported by the device (since ``statistics.since``), read at ``statistics.timestamp``. They are NOT the ECS ``host.network.*`` gauges.
- ``host.related.vlans`` is PEAT-specific (ECS has no ``related.vlans``).
- ``host.event.severity`` is numeric (``long``). Textual severities of ``Event.severity`` are deprecated and are exported as ``host.event.log_level``.
- ``host.relationships`` and ``host.baseline_findings`` are NOT part of host documents: they have their own indices (below). The full JSON export (``device-data-full.json``) contains them.
- The ``original`` raw contents of files are not exported (``host.files.original``, ``host.module.files.original``) unless ``elastic_save_blobs`` is enabled.

Fields
------
.. note::
   The ``host.extra`` field has sub-fields dynamically named based on the PEAT device module name (e.g. ``host.extra.selrelay.*``), which does not conform to :term:`ECS`. This is to prevent clashes with a dynamically defined schema. Example: you push a bunch of data from SEL, and a field (say, ``address``) happens to have the same name as a ION field. If the SEL address was a integer, but the ION is a string, when PEAT tries to push the ION data it will fail due to a different data type for the same field name.

.. csv-table:: OT Devices Fields
   :escape: \
   :file: field_references/ot_devices_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left


OT device events (``ot-device-events-*``)
=========================================
Event log entries and history extracted from devices (:class:`~peat.data.models.Event`), one document per event.

Notes
-----
- Index: ``ot-device-events-<date>``, where ``date`` is, ``year.month.day`` in UTC.
- Every entry includes the :ref:`base-fields` and :ref:`agent-fields`, and the basic ``host.*`` fields of the device (identity, description, ``host.asset.*``, ``host.tags``).
- ``event.kind`` is single-valued in this index (ECS): the most specific kind of the event, by precedence ``alert`` > ``pipeline_error`` > ``state`` > ``metric`` > ``enrichment`` > ``asset`` > ``event``. Host documents keep the full set in ``host.event.kind``.
- ``event.severity`` is only set for numeric severities. The textual log level is ``log.level`` at the document root.
- ``hash.*`` at the document root are the hashes of ``event.original``, computed by PEAT. ``event.hash.*`` is the hash set by the device module (``Event.hash``).

Fields
------
.. csv-table:: Event Fields
   :escape: \
   :file: field_references/event_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left


Relationships (``ot-device-relationships-*``)
=============================================
Configured and observed relationships between devices and other endpoints (:class:`~peat.data.models.Relationship`): communication peers (e.g. DNP3 masters, Modbus clients), ARP/LLDP neighbors, route next hops, time servers, serial links, IEC 61850 GOOSE/SV publications and subscriptions, and MMS reports.

Notes
-----
- Index: ``ot-device-relationships-<date>``, where ``date`` is, ``year.month.day`` in UTC.
- One document per relationship per PEAT run. ``@timestamp`` is the time of the push ("observed by this run"); ``event.start``/``event.end`` are the first/last observation. ``relationship.id`` is a deterministic identifier of the relationship (the edge), so the history of one relationship can be queried across runs.
- One relationship aggregates every observation of the same edge: a configured DNP3 master and the socket-table sessions from it are one document with ``relationship.evidence: [config, netstat]``.
- ECS ``source.*`` is the initiator and ``destination.*`` the responder; they are only set when ``network.direction`` is known (``ingress``: the remote side initiates, ``egress``: the device initiates). ``event.type`` is ``connection`` when the direction and both IP addresses are known, else ``info``.
- Layer 2 relationships (GOOSE, Sampled Values) have no IP addresses. Group (multicast) MAC addresses are only ever ``destination.mac`` and are never in ``related.mac``. Both ends of a GOOSE/SV stream share ``relationship.reference`` (the control block reference).
- Every entry includes the :ref:`base-fields` and :ref:`agent-fields`, and the basic ``host.*`` fields of the device.
- Field vocabularies (protocols, roles, relationship types, media) are documented in :doc:`data_model`.

Fields
------
.. csv-table:: Relationship Fields
   :escape: \
   :file: field_references/relationships_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left


Baseline findings (``ot-device-baseline-findings-*``)
=====================================================
Results of comparing devices against baselines (:class:`~peat.data.models.BaselineFinding`): factory defaults, vendor hardening recommendations, the first observed state of a device, previous pulls, or engineer-provided configurations.

Notes
-----
- Index: ``ot-device-baseline-findings-<date>``, where ``date`` is, ``year.month.day`` in UTC.
- One document per finding. ``@timestamp`` is the time of the comparison.
- ``event.kind`` is ``alert`` for failed rules marked as alerts, ``event`` (with ``event.type`` ``change``, ``creation`` or ``deletion``) for drift against a previous pull, and ``state`` (``event.type: [info]``) otherwise, following the Elastic posture-management (CSPM) pattern.
- The ECS ``rule.*`` fields describe the rule; ``rule.version`` is not set. The custom ``baseline.*`` fields describe the baseline and the finding.
- Every entry includes the :ref:`base-fields` and :ref:`agent-fields`, and the basic ``host.*`` fields of the device.

Fields
------
.. csv-table:: Baseline Finding Fields
   :escape: \
   :file: field_references/baseline_findings_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left


PEAT scan summaries (``peat-scan-summaries-*``)
===============================================
Results from :term:`PEAT` scans.

Notes
-----
Index: ``peat-scan-summaries-<date>``, where ``date`` is, ``year.month.day`` in UTC. Example: ``peat-scan-summaries-2026.01.01``
- Every entry includes the :ref:`base-fields` and :ref:`agent-fields`.

Fields
------
.. csv-table:: Scan Summary Fields
   :escape: \
   :file: field_references/scan_summaries_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left


PEAT pull summaries (``peat-pull-summaries-*``)
===============================================
Results from :term:`PEAT` pulls.

Notes
-----
Index: ``peat-pull-summaries-<date>``, where ``date`` is, ``year.month.day`` in UTC. Example: ``peat-pull-summaries-2026.01.01``
- Every entry includes the :ref:`base-fields` and :ref:`agent-fields`.

Fields
------
.. csv-table:: Pull Summary Fields
   :escape: \
   :file: field_references/pull_summaries_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left


PEAT parse summaries (``peat-parse-summaries-*``)
=================================================
Results from :term:`PEAT` parses.

Notes
-----
Index: ``peat-parse-summaries-<date>``, where ``date`` is, ``year.month.day`` in UTC. Example: ``peat-parse-summaries-2026.01.01``
- Every entry includes the :ref:`base-fields` and :ref:`agent-fields`.

Fields
------
.. csv-table:: Parse Summary Fields
   :escape: \
   :file: field_references/parse_summaries_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left


References
==========
- `ECS Reference <https://www.elastic.co/docs/reference/ecs/ecs-field-reference>`__
- `ECS Conventions <https://www.elastic.co/docs/reference/ecs/ecs-conventions>`__
- `ECS Guidelines <https://www.elastic.co/docs/reference/ecs/ecs-guidelines>`__
- `ECS Changelog <https://github.com/elastic/ecs/blob/master/CHANGELOG.md>`__
- `Field Datatypes <https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-types.html>`__
- `Multi-Fields <https://www.elastic.co/guide/en/elasticsearch/reference/current/multi-fields.html>`__
- `Elasticsearch Documentation <https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html>`__


Examples/further reading
========================
- `Filebeat ECS fields <https://www.elastic.co/guide/en/beats/filebeat/current/exported-fields-ecs.html>`__
- `Packetbeat ECS fields <https://www.elastic.co/guide/en/beats/packetbeat/current/exported-fields-ecs.html>`__
- `Winlogbeat ECS fields <https://www.elastic.co/guide/en/beats/winlogbeat/current/exported-fields-ecs.html>`__
- `Punch platform ECS example <https://punchplatform.com/2019/03/10/leveraging-the-elastic-common-schema/>`__
