*******************
Reference Documents
*******************

.. NOTE: the sphinx_argparse_cli directive below creates its own section
   heading, so it must come *before* the first regular section of this page,
   otherwise the generated section is nested inside that section. Don't add a
   manual heading above it either: with an empty ":title:" the generated
   sub-command sections end up outside of the table of contents and lose
   their numbering.

.. _cli-reference:

.. sphinx_argparse_cli::
   :module: peat.cli_args
   :func: build_argument_parser
   :prog: peat
   :title: Command Line Interface (CLI) usage reference

.. _peat-index-reference:

PEAT Elasticsearch indices reference
====================================
.. csv-table::
   :name: PEAT Elasticsearch indices
   :header: "Index name", "Description", "Index name :doc:`configuration option <configure>`"
   :widths: 20, 55, 25
   :align: left

   "``peat-logs``", "PEAT logging events.", ":attr:`ELASTIC_LOG_INDEX <peat.settings.Configuration.ELASTIC_LOG_INDEX>`"
   "``peat-scan-summaries``", "Scan result summaries.", ":attr:`ELASTIC_SCAN_INDEX <peat.settings.Configuration.ELASTIC_SCAN_INDEX>`"
   "``peat-pull-summaries``", "Pull result summaries.", ":attr:`ELASTIC_PULL_INDEX <peat.settings.Configuration.ELASTIC_PULL_INDEX>`"
   "``peat-parse-summaries``", "Parse result summaries.", ":attr:`ELASTIC_PARSE_INDEX <peat.settings.Configuration.ELASTIC_PARSE_INDEX>`"
   "``peat-configs``", "PEAT configurations.", ":attr:`ELASTIC_CONFIG_INDEX <peat.settings.Configuration.ELASTIC_CONFIG_INDEX>`"
   "``peat-state``", "Dumps of PEAT's internal state during a run.", ":attr:`ELASTIC_STATE_INDEX <peat.settings.Configuration.ELASTIC_STATE_INDEX>`"
   "``ot-device-hosts-timeseries``", "Information collected by PEAT from field devices or parsed files. A new Elasticsearch document is created for every pull of data from a device (the data is 'timeseries', with differences visible between pulls over time).", ":attr:`ELASTIC_HOSTS_INDEX <peat.settings.Configuration.ELASTIC_HOSTS_INDEX>`"
   "``ot-device-files``", "Information about files present on the device, or that were present on the device at one point in time.", ":attr:`ELASTIC_FILES_INDEX <peat.settings.Configuration.ELASTIC_FILES_INDEX>`"
   "``ot-device-registers``", "Information about individual communication 'registers' (e.g. Modbus registers/coils, DNP3 data points, BACNet objects, etc.) that are configured on devices, as extracted from device configuration information.", ":attr:`ELASTIC_REGISTERS_INDEX <peat.settings.Configuration.ELASTIC_REGISTERS_INDEX>`"
   "``ot-device-tags``", "Information about tag variables that are configured on devices, as extracted from device configuration information.", ":attr:`ELASTIC_TAGS_INDEX <peat.settings.Configuration.ELASTIC_TAGS_INDEX>`"
   "``ot-device-io``", "Information about I/O (Input/Output) available and/or configured on a device, as extracted from device configuration information.", ":attr:`ELASTIC_IO_INDEX <peat.settings.Configuration.ELASTIC_IO_INDEX>`"
   "``ot-device-events``", "Logging and other event history as extracted from devices. Examples include access logs, system logs, or protection history.", ":attr:`ELASTIC_EVENTS_INDEX <peat.settings.Configuration.ELASTIC_EVENTS_INDEX>`"
   "``ot-device-memory``", "Memory reads from devices, including address in memory, the value read, and information about where it came from and when the read occurred.", ":attr:`ELASTIC_MEMORY_INDEX <peat.settings.Configuration.ELASTIC_MEMORY_INDEX>`"
   "``ot-device-relationships``", "Configured and observed relationships between devices and other endpoints, such as communication peers (e.g. DNP3 masters), ARP neighbors, route next hops, time servers, serial links, and IEC 61850 GOOSE/SV publications and subscriptions. One document per relationship per PEAT run.", ":attr:`ELASTIC_RELATIONSHIPS_INDEX <peat.settings.Configuration.ELASTIC_RELATIONSHIPS_INDEX>`"
   "``ot-device-baseline-findings``", "Results (findings) of comparing devices against baselines, such as factory defaults, vendor hardening recommendations, the first observed state of a device, or an engineer-provided configuration. One document per finding.", ":attr:`ELASTIC_BASELINE_FINDINGS_INDEX <peat.settings.Configuration.ELASTIC_BASELINE_FINDINGS_INDEX>`"
   "``uefi-files``", "Files from UEFI firmware images (SPI dumps), with their CRC32 and paths.", ":attr:`ELASTIC_UEFI_FILES_INDEX <peat.settings.Configuration.ELASTIC_UEFI_FILES_INDEX>`"
   "``uefi-hashes``", "Hashes of files from UEFI systems.", ":attr:`ELASTIC_UEFI_HASHES_INDEX <peat.settings.Configuration.ELASTIC_UEFI_HASHES_INDEX>`"

PEAT configuration reference
============================
.. literalinclude:: ../examples/peat-config.yaml
   :name: PEAT configuration reference
   :language: yaml

.. _device-module-documents:

Device module documents
=======================
In-depth documentation for specific PEAT device modules. Refer to :doc:`device_modules` for the code documentation of all modules included with PEAT.

.. toctree::
   :maxdepth: 1

   sel
   siemens
   openplc
