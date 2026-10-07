.. _peat-index-reference:

*********************
Elasticsearch indices
*********************
The Elasticsearch (or OpenSearch) indices PEAT writes to, and the
:doc:`configuration option <configuration>` that sets each name. By default a date suffix
is appended to each name (``<index>-<year>.<month>.<day>``, :term:`UTC`), which
:attr:`ELASTIC_DISABLE_DATED_INDICES <peat.settings.Configuration.ELASTIC_DISABLE_DATED_INDICES>`
turns off. Usage is described in :doc:`/user_guide/elasticsearch`, and the fields of each
index in :doc:`database_schema`.

.. list-table::
   :header-rows: 1
   :widths: 26 50 24

   * - Index name
     - Description
     - Configuration option
   * - ``peat-logs``
     - PEAT logging events. One document per log message.
     - :attr:`ELASTIC_LOG_INDEX <peat.settings.Configuration.ELASTIC_LOG_INDEX>`
   * - ``peat-scan-summaries``
     - Scan result summaries. One document per scan, covering all devices.
     - :attr:`ELASTIC_SCAN_INDEX <peat.settings.Configuration.ELASTIC_SCAN_INDEX>`
   * - ``peat-pull-summaries``
     - Pull result summaries. One document per pull.
     - :attr:`ELASTIC_PULL_INDEX <peat.settings.Configuration.ELASTIC_PULL_INDEX>`
   * - ``peat-parse-summaries``
     - Parse result summaries. One document per parse run.
     - :attr:`ELASTIC_PARSE_INDEX <peat.settings.Configuration.ELASTIC_PARSE_INDEX>`
   * - ``peat-configs``
     - The configuration used by a PEAT run. One document per run.
     - :attr:`ELASTIC_CONFIG_INDEX <peat.settings.Configuration.ELASTIC_CONFIG_INDEX>`
   * - ``peat-state``
     - Dump of PEAT's internal state at the end of a run. One document per run.
     - :attr:`ELASTIC_STATE_INDEX <peat.settings.Configuration.ELASTIC_STATE_INDEX>`
   * - ``ot-device-hosts-timeseries``
     - Information collected from field devices or parsed from files. A new document is
       created for every pull of data from a device (the data is a time series, so
       differences between pulls are visible over time).
     - :attr:`ELASTIC_HOSTS_INDEX <peat.settings.Configuration.ELASTIC_HOSTS_INDEX>`
   * - ``ot-device-files``
     - Files present on a device (or that were present at one point), one document per
       file, with hashes and metadata.
     - :attr:`ELASTIC_FILES_INDEX <peat.settings.Configuration.ELASTIC_FILES_INDEX>`
   * - ``ot-device-registers``
     - Communication "registers" configured on devices (Modbus registers and coils, DNP3
       points, BACnet objects, ...), as extracted from device configuration.
     - :attr:`ELASTIC_REGISTERS_INDEX <peat.settings.Configuration.ELASTIC_REGISTERS_INDEX>`
   * - ``ot-device-tags``
     - Tag variables configured on devices, as extracted from device configuration.
     - :attr:`ELASTIC_TAGS_INDEX <peat.settings.Configuration.ELASTIC_TAGS_INDEX>`
   * - ``ot-device-io``
     - I/O (input/output) points available and/or configured on a device.
     - :attr:`ELASTIC_IO_INDEX <peat.settings.Configuration.ELASTIC_IO_INDEX>`
   * - ``ot-device-events``
     - Logging and event history extracted from devices: access logs, system logs,
       protection history, and so on. One document per event.
     - :attr:`ELASTIC_EVENTS_INDEX <peat.settings.Configuration.ELASTIC_EVENTS_INDEX>`
   * - ``ot-device-memory``
     - Memory reads from devices: the address, the value read, where it came from, and
       when the read occurred.
     - :attr:`ELASTIC_MEMORY_INDEX <peat.settings.Configuration.ELASTIC_MEMORY_INDEX>`
   * - ``uefi-files``
     - Files found in a UEFI firmware image by the UEFI module.
     - :attr:`ELASTIC_UEFI_FILES_INDEX <peat.settings.Configuration.ELASTIC_UEFI_FILES_INDEX>`
   * - ``uefi-hashes``
     - Hashes of files in a UEFI firmware image.
     - :attr:`ELASTIC_UEFI_HASHES_INDEX <peat.settings.Configuration.ELASTIC_UEFI_HASHES_INDEX>`

The type mappings PEAT applies when it creates an index are defined in
:mod:`peat.es_mappings` and are also written to ``elastic_data/mappings/`` in each run
directory that exported to Elasticsearch.
