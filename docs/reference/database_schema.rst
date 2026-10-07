.. _database-schema:

***************
Database schema
***************
The schema of the documents PEAT writes to Elasticsearch (or OpenSearch). Its objective is
to establish common data structures that can be used to build visualizations and
dashboards, and that downstream tools can rely on, regardless of which vendor's device the
data came from. The schema follows the Elastic Common Schema (:term:`ECS`) wherever ECS
has a suitable field, and extends it with :term:`OT`-specific fields under ``host.*``.

The schema is implemented in two places that must agree: the Pydantic
:doc:`data model </developer/data_model>` (:mod:`peat.data.models`), which defines the
fields and their Python types, and the Elasticsearch index mappings
(:mod:`peat.es_mappings`), which define the Elasticsearch data type of each field. The
tables on this page describe the fields; the index names and their configuration options
are in :doc:`elasticsearch_indices`, and usage is in :doc:`/user_guide/elasticsearch`.

:ECS version: 8.10 (``ecs.version`` in documents)

Conventions
===========
- **Elasticsearch is schemaless, so why a schema?** Because to share data between users
  and tools, the data must have a predictable format.
- The schemas here describe the :term:`JSON` fields expected of a document (a "doc") in an
  index.
- "Data type" values are Elasticsearch
  `field data types <https://www.elastic.co/docs/reference/elasticsearch/mapping-reference/field-data-types>`__.
  When storing documents as plain :term:`JSON` files, use a format that matches or can be
  coerced to the corresponding Elasticsearch type.
- **Every document includes the** :ref:`base-fields` **and** :ref:`agent-fields`.
- All timestamps are in the :term:`UTC` timezone, in ISO 8601 format, and use the
  Elasticsearch ``date`` type.
- Field names are nested JSON objects, not dotted strings: ``{"host": {"ip": ...}}``, not
  ``{"host.ip": ...}`` (per the
  `ECS guidelines <https://www.elastic.co/docs/reference/ecs/ecs-guidelines>`__).
- Fields are optional unless the description says otherwise, but any data that fits a
  defined field must use that field rather than a custom one. Additional fields beyond
  those defined here are permitted if they're internally consistent (always the same for a
  version of a tool).
- The document ``_id`` is unique per document: ``peat~<run-id>~<microsecond>``, where
  ``<microsecond>`` is an integer.
- Changes to the schema must adhere to ECS when possible. ECS updates are brought in as
  relevant, and PEAT features that add data update the schema as part of the change.

Shared field sets
=================

.. _base-fields:

Base fields
-----------
Present in every document. ECS reference:
`Base fields <https://www.elastic.co/docs/reference/ecs/ecs-base>`__.

.. csv-table:: Base fields
   :escape: \
   :file: field_references/base_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left

.. _agent-fields:

Agent fields
------------
Information about the tool that generated the document (PEAT). ECS reference:
`Agent fields <https://www.elastic.co/docs/reference/ecs/ecs-agent>`__.

.. csv-table:: Agent fields
   :escape: \
   :file: field_references/agent_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left

.. _event-fields:

Event fields
------------
The structure of an event, used by the ``host.event`` entries of a device document and by
the documents of the ``ot-device-events`` index (where the fields are at the top level,
without the ``host.`` prefix). ECS reference:
`Event fields <https://www.elastic.co/docs/reference/ecs/ecs-event>`__.

.. csv-table:: Event fields
   :escape: \
   :file: field_references/event_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left

Device documents (``ot-device-hosts-timeseries-*``)
===================================================
:term:`OT` field device information collected by PEAT, from a pull or parsed from a file.
One document per device per run, so the index accumulates a history of each device's
configuration, firmware, and status over time.

- ``message``: human-readable description or summary of the device.
- All device fields are nested under ``host``, e.g. ``host.ip``, and follow the ECS
  ``host`` field set where one exists, with OT-specific additions.
- ``host.extra`` has sub-fields named after the PEAT module that produced them
  (``host.extra.selrelay.*``), which is not ECS-conformant by design: it keeps
  vendor-specific data with clashing names and types from colliding in one mapping (if
  SEL's ``address`` were an integer and ION's a string, pushing the second would fail).
- The list-type fields (files, registers, tags, I/O, events, memory) are also written as
  one document per item to their own indices (below), for easier searching.
- Some status attributes, such as uptime, can be derived from device events or logs.

.. csv-table:: Device fields
   :escape: \
   :file: field_references/ot_devices_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left

The authoritative definition of each field, including Python types and validation, is the
:doc:`data model reference </developer/data_model>`.

Device item documents
=====================
The following indices hold one document per item from a device, in addition to the item
being embedded in the device document. Each document has the base and agent fields, the
device's identifying fields (``host.id``, ``host.ip``, ``host.description.*``), and the
item's fields as defined for the corresponding ``host.*`` field set above:

.. list-table::
   :header-rows: 1
   :widths: 30 30 40

   * - Index
     - Item type
     - Fields
   * - ``ot-device-files-*``
     - One file on (or from) the device
     - ``host.files.*`` (``file.*`` fields)
   * - ``ot-device-registers-*``
     - One protocol register or data point
     - ``host.registers.*``
   * - ``ot-device-tags-*``
     - One tag/variable
     - ``host.tag.*``
   * - ``ot-device-io-*``
     - One physical I/O point
     - ``host.io.*``
   * - ``ot-device-events-*``
     - One device event or log entry
     - :ref:`event-fields`
   * - ``ot-device-memory-*``
     - One memory read
     - ``host.memory.*``
   * - ``uefi-files-*``, ``uefi-hashes-*``
     - UEFI firmware image files and hashes (UEFI module)
     - ``type``, ``subtype``, ``base``, ``size``, ``guid``, ``name``, ``path``; ``file_system``, ``pathname``, ``hash``

PEAT logs (``peat-logs-*``)
===========================
PEAT's own log messages, such as errors or informational messages. This does **not**
include logs collected *from* devices; those are events in the device documents.

- ``message``: the human-readable log message.
- The level and complete log entry are in the ``log.*`` field set; the process and host
  that ran PEAT are in ``process.*``, ``observer.*``, and ``user.*``; PEAT-specific details
  are in ``peat.*``.
- Python :class:`logging.LogRecord` attributes map onto these fields
  (`LogRecord attributes <https://docs.python.org/3/library/logging.html#logrecord-attributes>`__).

ECS reference: `Log fields <https://www.elastic.co/docs/reference/ecs/ecs-log>`__.

.. csv-table:: Log fields
   :escape: \
   :file: field_references/log_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left

Summaries (``peat-scan-summaries-*``, ``peat-pull-summaries-*``, ``peat-parse-summaries-*``)
============================================================================================
One document per run. Their fields are documented with the :doc:`summary files
<summaries>`, which have the same content: :ref:`scan-summary`, :ref:`pull-summary`,
:ref:`parse-summary`.

Configuration and state (``peat-configs-*``, ``peat-state-*``)
==============================================================
One document per run. ``peat-configs`` holds the configuration values PEAT used
(the same content as ``peat_metadata/peat_configuration.yaml``), and ``peat-state`` the
internal state at the end of the run (``peat_metadata/peat_state.yaml``). Their fields are
the :class:`~peat.settings.Configuration` and :class:`~peat.settings.State` attributes in
lower case.

References
==========
- `ECS reference <https://www.elastic.co/docs/reference/ecs>`__,
  `conventions <https://www.elastic.co/docs/reference/ecs/ecs-conventions>`__, and
  `guidelines <https://www.elastic.co/docs/reference/ecs/ecs-guidelines>`__
- `ECS changelog <https://github.com/elastic/ecs/blob/main/CHANGELOG.md>`__
- Elasticsearch
  `field data types <https://www.elastic.co/docs/reference/elasticsearch/mapping-reference/field-data-types>`__
  and `multi-fields <https://www.elastic.co/docs/reference/elasticsearch/mapping-reference/multi-fields>`__
- Examples of ECS in practice: the exported fields of
  `Filebeat <https://www.elastic.co/docs/reference/beats/filebeat/exported-fields-ecs>`__,
  `Packetbeat <https://www.elastic.co/docs/reference/beats/packetbeat/exported-fields-ecs>`__,
  and `Winlogbeat <https://www.elastic.co/docs/reference/beats/winlogbeat/exported-fields-ecs>`__

.. seealso::

   :doc:`/developer/elastic_implementation`
      How documents are generated and pushed, and the index mappings
