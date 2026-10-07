.. _output-structure:

*******************
Results and output
*******************
Every run of PEAT writes its results to a *run directory*: a self-contained folder with
the data collected from each device, summaries, logs, and a record of the configuration
used. This page explains where that directory is, what's in it, and how to read it.

Output directory and run directory
==================================
By default, runs are saved under ``./peat_results/`` in the current working directory.
Change the parent directory with ``-o <dir>`` (``--out-dir``), the
:attr:`OUT_DIR <peat.settings.Configuration.OUT_DIR>` configuration option, or the
``PEAT_OUT_DIR`` environment variable.

Each run creates a new sub-directory, the **run directory**. Its name is set with
``-R <name>`` (``--run-name``); otherwise it is generated as
``<command>_<config-name>_<timestamp>_<run-id>``, where ``config-name`` is the ``name``
from the configuration file's ``metadata`` (``default-config`` if none was used) and
``run-id`` is the unique ID also recorded in the results as ``peat_run_id``
(``agent.id`` in Elasticsearch). ``--run-dir <path>`` uses an exact directory instead,
bypassing ``peat_results/``.

.. list-table::
   :header-rows: 1
   :widths: 55 45

   * - Command
     - Run directory
   * - ``peat scan --run-name example_run -i 192.0.2.1``
     - ``./peat_results/example_run/``
   * - ``peat pull -c examples/peat-config-sceptre-testing.yaml -i 192.0.2.1``
     - ``./peat_results/pull_sceptre-test-config_2026-06-17_16-55-32_179126071045/``
   * - ``peat scan -i 192.0.2.1``
     - ``./peat_results/scan_default-config_2026-09-27_10-05-11_179126071779/``
   * - ``peat scan --run-dir example_run_dir -i 192.0.2.1``
     - ``./example_run_dir/``

Running the same run name twice reuses the directory. Existing files are never
overwritten: a new copy is written with a number appended to the name
(``device-data-full.1.json``, ``device-data-full.2.json``, and so on).

Directory structure
===================
The location and names of these directories are configurable (``*_DIR`` options in
:doc:`configure`), so your layout may differ if any were changed. ``...`` stands for
miscellaneous files.

.. only:: html

   .. figure:: /images/terminal/run_directory.svg
      :alt: Terminal showing the directory tree of a run directory after parsing one file: devices/127.0.0.1/ with the device-data JSON and JSONL files and the parsed file, logs/ with peat.log, json-log.jsonl, debug-info.txt and telnet.log, peat_metadata/ with the configuration and state, and summaries/parse-summary.json
      :figclass: peat-terminal

      A real run directory after ``peat parse`` of a single file. The general layout is below.

.. code-block:: text

   ./peat_results/
      README.md                          # Short explanation of this layout
      <run-dir>/
         devices/
            <device-id>/
               device-data-full.json     # Everything collected or parsed for the device
               device-data-summary.json  # The same, without large fields (blobs, memory, events)
               device-data-<type>.jsonl  # One JSON object per line for list-type data
               ...                       # Pulled artifacts and vendor-specific parsed files
         elastic_data/                   # Copies of documents sent to Elasticsearch (only with -e)
            mappings/
         heat_artifacts/                 # Files reconstructed by HEAT
         logs/
            peat.log                     # Human-readable log of the run
            json-log.jsonl               # The same log, one JSON object per line
            debug-info.txt               # System information gathered at start-up
            elasticsearch.log            # Elasticsearch client logs (only with -e)
            telnet.log                   # Protocol transcripts (Telnet, ENIP, ...)
            enip/
         peat_metadata/
            peat_configuration.yaml      # The complete configuration used for the run
            peat_state.yaml              # PEAT's internal state at the end of the run
         summaries/
            scan-summary.json
            pull-summary.json
            parse-summary.json
         temp/                           # Scratch space used during the run
         zeek_logs/                      # Zeek output (HEAT FTP extractor only)

- ``devices/``: all output for devices, with a sub-directory per **device ID**. The ID is
  usually the :term:`IP` address for network operations, but can be another identifier
  when the IP isn't known: a serial port, a name parsed from a file, or the source file's
  name.
- ``summaries/``: the :doc:`summary </reference/summaries>` of the command as a
  :term:`JSON` file: metadata about the operation (duration, modules used, how many
  devices or files) and a combined set of device summaries. To see *all* data for a device,
  look in ``devices/``.
- ``elastic_data/``: copies of the documents pushed to Elasticsearch, so the indices can be
  rebuilt if the server is lost, or loaded into a server that wasn't reachable during the
  run. Only created when Elasticsearch output is enabled. See :doc:`elasticsearch`.
- ``logs/``: records of what PEAT did, including protocol transcripts. Start here when
  :doc:`troubleshooting`.
- ``peat_metadata/``: dumps of PEAT's configuration and internal state. The configuration
  dump is a complete, reusable configuration file (see :ref:`auto-generated-configs`).

Encrypted archives created with ``peat encrypt-results`` are written outside this
structure, by default to the current working directory as ``encrypted_<run-dir>.zip``
(see :doc:`encryption`).

Device data files
=================
``device-data-full.json`` and ``device-data-summary.json`` contain the device's data in
PEAT's :doc:`data model </developer/data_model>`, which is the same for every vendor.
The top-level fields you will use most:

.. only:: html

   .. figure:: /images/terminal/device_summary.svg
      :alt: Terminal showing the start of a device-data-summary.json file: created timestamp, description with brand, model, product and vendor (Sandia National Laboratories SCEPTRE), id and name rtu-1, ip 127.0.0.1, type RTU, os Canonical Ubuntu, and the beginning of the logic section
      :figclass: peat-terminal

      The start of a ``device-data-summary.json`` for a parsed SCEPTRE RTU. The same fields
      are documented in the :doc:`data model </developer/data_model>`.

.. list-table::
   :header-rows: 1
   :widths: 24 76

   * - Field
     - Contents
   * - ``id``, ``ip``, ``mac``, ``hostname``, ``name``, ``serial_port``
     - Identifiers for the device.
   * - ``description``
     - Vendor, brand, model, and product strings.
   * - ``type``, ``run_mode``, ``status``, ``uptime``, ``start_time``, ``part_number``, ``serial_number``
     - Device class (``PLC``, ``Relay``, ``RTU``, ...) and status information.
   * - ``firmware``, ``boot_firmware``, ``os``, ``hardware``
     - Firmware identification and version, operating system, hardware details.
   * - ``logic``
     - Process logic: the original and parsed representations, plus hashes and file metadata.
   * - ``interface``, ``service``
     - Network and serial interfaces, and the services (protocols and ports) on them, with
       their status (``open``, ``verified``, ``closed``).
   * - ``files``
     - Files pulled from or found on the device, with hashes, sizes, and paths.
   * - ``registers``, ``tag``, ``io``
     - Protocol registers (Modbus, DNP3, ...), tags/variables, and physical I/O points.
   * - ``event``
     - Log and event history extracted from the device (access logs, system logs, relay events).
   * - ``memory``
     - Memory reads, with address, value, and provenance.
   * - ``users``, ``ssh_keys``, ``related``
     - User accounts, SSH keys, and "related" indicators (IPs, hosts, files, hashes,
       protocols) collected along the way.
   * - ``module``
     - Sub-components of the device (e.g. modules in a PLC rack), each with the same fields.
   * - ``extra``
     - Vendor- or module-specific data that doesn't fit the common fields, keyed by module.

The ``.jsonl`` files (``device-data-event.jsonl``, ``device-data-service.jsonl``, and so on)
contain the list-type fields with one JSON object per line, which is convenient for
ingestion into Splunk and similar tools. ``device-data-full.json`` is written minified
unless :attr:`FORMATTED_OUTPUT <peat.settings.Configuration.FORMATTED_OUTPUT>` is enabled;
pipe it through ``jq`` to read it.

Alongside the data model files are the artifacts PEAT pulled or produced for the device:
raw configuration files, decompiled logic, parsed configuration, and protocol dumps. These
vary by device and are listed in :doc:`/reference/output_files`.

Viewing results
===============
.. code-block:: bash

   peat pull --run-name example_pull -i 192.0.2.0/24 10.0.0.5-10 172.16.17.18
   # … wait a while …

   # The scan (device discovery) summary
   cat peat_results/example_pull/summaries/scan-summary.json

   # Color-highlighted and formatted with "jq" (https://jqlang.org/)
   jq . peat_results/example_pull/summaries/pull-summary.json

   # Every file pulled, as a tree (install "tree" with: sudo apt install tree)
   tree -a peat_results/example_pull/devices/

   # The device data without the bulky memory and event entries
   jq 'del(.memory, .event)' peat_results/example_pull/devices/192.168.3.200/device-data-full.json

   # Firmware versions of every device pulled
   jq -r '[.id, .description.product, .firmware.version] | @tsv' \
       peat_results/example_pull/devices/*/device-data-summary.json

   # Services with a verified status across all devices
   jq -c '{id, services: [.service[] | select(.status == "verified") | "\(.protocol)/\(.port)"]}' \
       peat_results/example_pull/devices/*/device-data-summary.json

Results can also be printed to the terminal as JSON with ``-E`` (``--print-results``);
combine with ``-q`` to suppress the log messages so the output can be piped to another
program. For dashboards and queries across many runs, export to
:doc:`Elasticsearch or OpenSearch <elasticsearch>`.

Disabling file output
=====================
Setting a directory option to an empty string disables output to that directory: for
example ``LOG_DIR: ""`` in a configuration file disables all log files (including protocol
transcripts). This works well for :attr:`SUMMARIES_DIR <peat.settings.Configuration.SUMMARIES_DIR>`,
:attr:`ELASTIC_DIR <peat.settings.Configuration.ELASTIC_DIR>`, and
:attr:`LOG_DIR <peat.settings.Configuration.LOG_DIR>`. Disabling the heavily used
:attr:`DEVICE_DIR <peat.settings.Configuration.DEVICE_DIR>` or
:attr:`OUT_DIR <peat.settings.Configuration.OUT_DIR>` should also work, but has regressed
in the past, so test locally before relying on it in the field.

Protecting results
==================
Results can contain sensitive material: device credentials in pulled configurations,
network layouts, and process logic. Store run directories accordingly. PEAT can encrypt a
run directory into a password-protected archive for storage or transfer, see
:doc:`encryption`.
