*********************
Device output files
*********************
The files PEAT writes for each device, in ``peat_results/<run-dir>/devices/<device-id>/``.
The data model files are the same for every device; the artifact files vary by module.
The structure of the run directory itself is described in :doc:`/user_guide/output`.

Common files
============
.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - File
     - Contents
   * - ``device-data-full.json``
     - Everything PEAT collected or parsed for the device, in the
       :doc:`data model </developer/data_model>`. Includes large fields such as file
       contents, memory reads, and events. Written minified unless
       :attr:`FORMATTED_OUTPUT <peat.settings.Configuration.FORMATTED_OUTPUT>` is set.
   * - ``device-data-summary.json``
     - The same data without the large fields; the file to start with.
   * - ``device-data-<type>.jsonl``
     - List-type data (``event``, ``files``, ``interface``, ``service``, ``registers``,
       ``tag``, ``io``, ``memory``, ``users``, ``ssh_keys``, ``module``) as JSON Lines,
       one object per line, for ingestion into Splunk and similar tools.
   * - The pulled or parsed source files
     - Raw files are kept unmodified alongside the data model files (configuration files,
       project files, firmware images, logs), named as they were on the device or on disk.

Vendor-specific files
=====================
These lists are not exhaustive; modules add files as their capabilities grow.

Schneider Electric Modicon M340
-------------------------------
.. list-table::
   :header-rows: 1
   :widths: 22 12 66

   * - Type of file
     - Extension
     - Description
   * - project
     - ``apx``
     - Raw project file pulled from the device (``peat parse`` can be run on this)
   * - parsed-config
     - ``txt``
     - Configuration and metadata extracted from the device and/or project file
   * - tc6
     - ``xml``
     - :term:`TC6` XML usable by the :term:`PLCOpen` editor and compilable to Structured
       Text or executable C code emulating the logic. Only written if logic and/or
       variables are successfully extracted.
   * - logic
     - ``st``
     - Structured Text extracted from the project file. Only written if logic is
       successfully extracted.
   * - text-dump
     - ``txt``
     - Debugging dump created if logic extraction fails
   * - blob-packets
     - ``txt``
     - Raw dump of the bytes transferred when downloading a project file
   * - umas-packets
     - ``json``
     - Metadata and contents of the :term:`UMAS` packets transferred when downloading a
       project file

Rockwell Allen-Bradley ControlLogix
-----------------------------------
.. list-table::
   :header-rows: 1
   :widths: 22 12 66

   * - Type of file
     - Extension
     - Description
   * - parsed-logic
     - ``txt``
     - Decompiled ladder logic in a human-readable form
   * - parsed-logic
     - ``json``
     - Values extracted from the ladder logic in machine-readable form
   * - raw-logic
     - ``json``
     - The raw tags and values pulled from the device

SEL relays
----------
.. list-table::
   :header-rows: 1
   :widths: 22 12 66

   * - Type of file
     - Extension
     - Description
   * - ``formatted-logic``
     - ``txt``
     - The logic sections of the configuration, formatted for reading
   * - ``parsed-config``
     - ``json``
     - The parsed configuration
   * - ``relay_files/CFG``
     - ``TXT``
     - Basic device data (firmware, model) and the list of configuration files on the relay
   * - ``relay_files/SET_ALL``
     - ``TXT``
     - All relay settings in one file
   * - ``relay_files/SETTINGS/SET_*``
     - ``TXT``
     - Individual settings files; which ones exist varies by relay model
   * - ``decompressed_<name>``
     - ``xml`` / ``txt``
     - Decompressed contents of any ``.CID`` (IEC 61850) files found on the relay

See :doc:`devices/sel` for details on the SEL file types.

OpenPLC Runtime v4
------------------
.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - File
     - Description
   * - ``openplc_runtime.log``
     - The runtime's log, also parsed into ``event`` entries
   * - ``compilation_status.log``
     - Status and output of the last program compilation
   * - ``<plugin>_<command>.json``
     - Output of each plugin command configured in ``plugins_to_query``

See :doc:`devices/openplc`.

Other modules
-------------
Other modules write the raw files they retrieve (for example Sage RTU configuration and
firmware files, FortiGate configuration backups and logs, GE relay settings pages, iDirect
options files) and, where applicable, parsed logic or configuration in ``txt`` or ``json``
form. The module's documentation in :doc:`/developer/device_modules` describes its output.
