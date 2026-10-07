*************
Parsing files
*************
``peat parse`` extracts information from device files without touching a device. The
input can be:

- **Files pulled from a device**, such as an SEL relay's ``SET_ALL.TXT`` or the project
  file PEAT downloads from a Modicon M340. A pull parses these automatically; ``peat
  parse`` lets you re-parse them later, with a newer version of PEAT or different options.
- **Project files exported from vendor engineering software**, such as an ``.rdb``
  database from SEL AcSELerator QuickSet, an ``.L5X`` export from Rockwell Studio 5000, or
  an ``.apx`` project from Schneider Unity Pro/Control Expert. These are often found on
  engineering workstations (see :doc:`pillage`).
- **Output of collection tools** that PEAT knows how to read, such as the
  ``wince_pillage`` tool for Windows CE devices or a UEFI SPI flash extraction.

The results use the same :doc:`data model </developer/data_model>` as a pull, so a parsed
project file and a pulled device can be compared directly.

Basic usage
===========
.. code-block:: bash

   # Parse a single file, with the module given explicitly
   peat parse -d selrelay ./SET_ALL.TXT
   peat parse -d m340 ./project-file.apx
   peat parse -d l5x ./basetest.L5X

   # Let PEAT pick the module from the file name and contents
   peat parse ./set_all.txt ./751_001.rdb

   # Parse every matching file in a directory, recursively
   peat parse -d sel ./relay_backups/
   peat parse -d m340 ./m340_files/

   # Several modules and paths: "--" separates options from paths
   peat parse -d selrelay m340 -- ./SET_ALL.TXT ./project.apx

   # Name the run
   peat parse --run-name parse_example -d selrelay ./SET_ALL.TXT

   # Windows paths work as expected
   peat parse -d m340 'C:\Projects\Station.apx'

.. only:: html

   .. figure:: /images/terminal/parse_sceptre.svg
      :alt: Terminal showing peat parse of a SCEPTRE Modbus server file: PEAT prints its banner, the log file and run directory, the file being parsed, the JSONL exports it writes, the parse summary path, and that it finished in under a second
      :figclass: peat-terminal

      Parsing one file (``peat parse -d sceptre modbus-server.xml``). The log names the run directory, the files written, and the summary. Output shortened.

Which module parses what
========================
Each module declares the file name patterns and :ref:`file signatures <file-signatures>`
(magic bytes, XML tags, substrings) it can parse. When ``-d`` is omitted, PEAT matches each
file against every parse-capable module and uses the ones that match; when ``-d`` names
one module, that module is used for every file given. A single module must be specified
when reading from standard input.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Module (``-d``)
     - Parses
   * - ``selrelay``
     - ``SET_ALL.TXT``, ``CFG.TXT``, ``SER.TXT``, and ``HISTORY.TXT`` files from a relay;
       ``.rdb`` AcSELerator QuickSet databases; ``.CID`` (IEC 61850) files
   * - ``selrtac``
     - RTAC project exports (``*rtacexport*.tar.gz``, ``*rtac*.tgz``, ``devices.tar.gz``)
       and the XML files inside them (``Tag Processor.xml``, ``SystemTags.xml``,
       ``Main Controller.xml``, ...); accepts a directory
   * - ``m340``
     - ``.apx`` project files, from the device or from Unity Pro/Control Expert
   * - ``l5x``
     - ``.L5X`` exports from Studio 5000 / RSLogix 5000
   * - ``sage``
     - Sage RTU configuration and firmware archives (``*_Config*.tar.gz``,
       ``*_Firmware*.tar.gz``) and ``rtusetup.xml``; accepts a directory
   * - ``gerelay``
     - A directory of pages pulled from a GE Multilin UR relay's web interface
   * - ``easygen3500xt``, ``wdw2301e``
     - Woodward ToolKit settings files (``.wset``) and ``.tc`` files (support is partial)
   * - ``fortigate``
     - FortiGate configuration backups (``*Fortigate*.conf``) and ``FG100F*.log`` logs
   * - ``windowsce``
     - JSON output of the ``wince_pillage.exe`` tool (``wince_pillage*.json``,
       ``pillage-results.json``, ``pillage-system_info.json``)
   * - ``uefi``
     - UEFI SPI flash extraction output (``spi*.txt`` and ``*hashes*.json``); accepts a
       directory
   * - ``sceptre``
     - SCEPTRE virtual field device XML configurations

Run ``peat parse --list-modules`` for the modules in your installation, and see
:doc:`/getting_started/supported_devices` for details on each. Modules may be added at
runtime with ``-I`` (:doc:`third_party_modules`), which is the standard way to parse the
output of your own tools.

Standard input and pipes
========================
Use ``-`` (or omit the path) to read a single file from standard input. This is how files
are parsed with the :doc:`container <containers>`, and it's handy in pipelines:

.. code-block:: bash

   cat ./SET_ALL.TXT | peat parse -d selrelay
   peat parse -d m340 < ./project-file.apx

   # Process results with jq: extract the IP address from a parsed M340 project
   peat parse -q -E -d m340 ./project-file.apx | jq '.["M340"][]["ip"]'

   # Count the events in a parsed file
   peat parse -q -E -d selrtac ./soe.csv | jq '.event | length'

On Windows, ``Get-Content file | peat parse ...`` works for text files but not binary
project files; use a path argument or ``<`` redirection for those.

Results
=======
Parsed devices are written to ``peat_results/<run-dir>/devices/<device-id>/`` like a pull.
The device ID comes from the file (an IP address or name in the configuration) or, if none
can be determined, from the file's name. The :ref:`parse summary <parse-summary>` in
``summaries/parse-summary.json`` lists every file parsed, which module parsed it, the
results, and any failures:

.. code-block:: bash

   jq '{num_files_parsed, num_parse_successes, num_parse_failures, parse_failures}' \
       peat_results/parse_example/summaries/parse-summary.json

   # Module and device ID for each parsed file
   jq -r '.parse_results[] | [.name, .module, .results.id] | @tsv' \
       peat_results/parse_example/summaries/parse-summary.json

Parsing does not try to resolve IP, MAC, or hostnames found in files against the network
(``RESOLVE_IP``, ``RESOLVE_MAC``, ``RESOLVE_HOSTNAME`` are disabled for parse runs unless
you explicitly enable them), so it is safe to run on an isolated analysis machine.

Tips
====
- Parsing an empty (0 byte) file may produce odd results (see :ref:`known-issues`).
- Directory parsing searches sub-directories recursively; point it at the smallest
  directory that contains the files you want.
- Results can be exported to Elasticsearch (``-e``) exactly like a pull, which is a good
  way to load a batch of historical backups for comparison.
- The :doc:`/reference/example_artifacts` page lists where to find example files to
  practice with.

Examples
========
The complete list of parse examples from ``peat parse --examples``:

.. literalinclude:: ../../peat/cli_args.py
   :language: bash
   :start-after: parse_examples = """
   :end-before: """  # End parse examples
