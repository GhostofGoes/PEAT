**********
Quickstart
**********
This page gets you from a fresh install to your first results with each of PEAT's three
core commands. Each workflow is self-contained: run the command, read the output, find
the results. Expect to spend about ten minutes.

Before you start:

- :doc:`Install PEAT <install>`. The examples use ``peat``; on Windows use ``.\peat.exe``,
  and with the container prefix each command with ``docker run`` as shown in the
  :ref:`container <quickstart-container>` tab.
- Have the address of a :doc:`supported device <supported_devices>` on a network you are
  authorized to scan, or use the parse workflow, which needs no device at all.
- On Linux, run active commands (``scan``, ``pull``) with ``sudo``; on Windows, use an
  Administrator PowerShell. PEAT works without elevated permissions, but scanning is
  slower and less reliable (see :doc:`requirements`).

.. _quickstart-first-run:

First run
=========
Verify the installation and look around the command line interface. Every command accepts
``--help``, and ``--examples`` prints a cheat sheet of real-world invocations.

.. tab-set::

   .. tab-item:: Linux
      :sync: linux

      .. code-block:: console

         $ peat --version
         PEAT 2026.9.2

         $ peat --help
         $ peat scan --help
         $ peat scan --examples

   .. tab-item:: Windows
      :sync: windows

      .. code-block:: doscon

         PS> .\peat.exe --version
         PEAT 2026.9.2

         PS> .\peat.exe --help
         PS> .\peat.exe scan --help
         PS> .\peat.exe scan --examples

   .. tab-item:: Container
      :sync: container
      :name: quickstart-container

      .. code-block:: console

         $ docker run --rm -i ghcr.io/sandialabs/peat:latest --version
         PEAT 2026.9.2

         $ docker run --rm -i ghcr.io/sandialabs/peat:latest scan --help

      For scans and pulls, add ``--network host`` (so PEAT can reach the network directly)
      and mount an output directory so results are kept:
      ``docker run --rm -i --network host -v "$(pwd)/peat_results:/peat_results" ghcr.io/sandialabs/peat:latest ...``.
      See :doc:`/user_guide/containers`.

The ``--help`` output lists the commands:

.. code-block:: text

   commands:
     parse               Parse and extract data from project files, device configs, and PEAT pulls
     pull                Pull and extract firmware, configs, logic, and/or logs from devices
     scan                Scan the network for devices
     push                Push firmware, configuration, or logic to a device
     pillage             Find and parse firmware, configuration, and logic from a disk image
     heat                HEAT (High-fidelity Extraction of Artifacts from Traffic) ...
     config-builder      PEAT Configuration Builder - Textual in-console GUI for generating
                         template YAML configuration files to use with PEAT.
     encrypt-config, decrypt-config, encrypt-results, decrypt-results

.. tip::
   PEAT pauses for a few seconds after you press Enter before printing anything. This is
   normal: the executable is unpacking itself and importing its dependencies.

Workflow 1: scan a network
==========================
A scan discovers devices and identifies ("fingerprints") the ones PEAT recognizes without
pulling data from them. It is the safest first step on an unfamiliar network.

**Step 1: dry run.** Check what PEAT *would* do, without sending a packet. This is a good
habit before any active operation on a production network:

.. code-block:: console

   $ sudo peat scan --dry-run -i 192.0.2.0/24
   04:25:16.805 | WARNING: Dry run mode is enabled! Actions won't be executed, but logs and state will still be written to files and saved to Elasticsearch (if enabled).
   04:25:16.810 | Running scan of 1 target using 20 modules (comm_type: unicast_ip)
   04:25:16.812 | WARNING: Dry run enabled, skipping calling command functions
   04:25:16.813 | Finished run in 0.2 seconds at 2026-10-06 04:25:16.813450+00:00 UTC

**Step 2: scan.** Scan the subnet, naming the run ``first_scan`` so the results are easy to
find. Replace ``192.0.2.0/24`` with your network. To limit the scan to the kinds of devices
you expect, add ``-d`` with one or more module names or aliases, for example
``-d sel`` or ``-d controllogix m340``:

.. code-block:: console

   $ sudo peat scan -R first_scan -i 192.0.2.0/24

       ____  _________  ______
      / __ \/ ____/   |/_  __/
     / /_/ / __/ / /| | / /
    / ____/ /___/ ___ |/ /
   /_/   /_____/_/  |_/_/

   PEAT 2026.9.2
   Run ID (agent.id): 179126071779

   04:25:19.389 | Log file: peat_results/first_scan/logs/peat.log
   04:25:19.410 | Run directory: first_scan
   04:25:19.415 | Running scan of 254 targets using 20 modules (comm_type: unicast_ip)
   04:25:19.417 | Checking online status of 254 hosts using ARP and/or ICMP requests
   04:25:21.420 | 3 hosts are responding (checked 254 hosts in 2 seconds)
   04:25:21.424 | Scanning 3 IPs using 16 modules: ControlLogix, Easygen3500XT, Fortigate, GERTU, GERelay, Idirect, M340, MicroNet, OpenPLCv4, SCEPTRE, SEL3620, SELRTAC, SELRelay, Sage, Siprotec, Totus
   04:25:21.425 | Beginning scan of 3 hosts...go get a coffee, this may take a while
   04:25:21.494 | 192.0.2.22   | Checking 12 ports for 192.0.2.22 using 37 methods
   04:25:23.812 | 192.0.2.22   | 192.0.2.22 has 2 open ports with 2 known protocols: ftp, telnet
   04:25:23.815 | 192.0.2.22   | Fingerprinting 192.0.2.22 using 3 matching methods
   04:25:24.101 | 192.0.2.22   | Identification method 'telnet' from module 'SELRelay' succeeded for 192.0.2.22
   04:25:24.103 | 192.0.2.22   | Scanned 192.0.2.22 in 2.6 seconds using 3 methods (protocols: ftp, telnet)
   ...
   04:25:43.796 | Completed scan of 3 devices in 22.37 seconds (3 results)
   04:25:43.801 | Saved scan summary to peat_results/first_scan/summaries/scan-summary.json
   04:25:43.804 | Finished run in 24.61 seconds at 2026-10-06 04:25:43.804855+00:00 UTC

Reading the output: PEAT first checks which of the 254 addresses are online, then checks
the ports each module uses on the responding hosts, and finally runs each module's
identification method against the open ports. A host that answers is *online*; a host that
PEAT identifies is *verified*.

**Step 3: results.** The scan summary lists every host that was online and the details of
each verified device:

.. code-block:: console

   $ cat peat_results/first_scan/summaries/scan-summary.json
   {
       "peat_version": "2026.9.2",
       "peat_run_id": "179126071779",
       "scan_duration": 22.38,
       "scan_modules": ["ControlLogix", "Easygen3500XT", ... ],
       "scan_type": "unicast_ip",
       "scan_targets": ["192.0.2.0/24"],
       "num_hosts_active": 3,
       "num_hosts_online": 2,
       "num_hosts_verified": 1,
       "hosts_online": ["192.0.2.1", "192.0.2.50"],
       "hosts_verified": [
           {
               "id": "192.0.2.22",
               "ip": "192.0.2.22",
               "mac": "00:30:A7:11:12:13",
               "type": "Relay",
               "description": {
                   "vendor": {"id": "SEL", "name": "Schweitzer Engineering Laboratories"},
                   "model": "SEL-351S",
                   ...
               },
               "service": [
                   {"port": 21, "protocol": "ftp", "status": "open", "transport": "tcp"},
                   {"port": 23, "protocol": "telnet", "status": "verified", "transport": "tcp"}
               ],
               "peat_module": "SELRelay"
           }
       ]
   }

Add ``-E`` (``--print-results``) to also print the summary to the terminal, and ``-q`` to
silence the log messages, which makes the output pipeable: ``peat scan -q -E -i ... | jq .``.
A complete scan summary of a real device is in
:ref:`the summaries reference <scan-summary>`.

.. seealso::
   :doc:`/user_guide/scan` for broadcast scanning, serial ports, intensive scans, scanning
   from a file of targets, and tuning.

Workflow 2: pull artifacts from a device
========================================
A pull interrogates devices and saves what it finds: configuration, logic, firmware, logs,
and more, depending on the device. A pull always scans first and only pulls from devices
it successfully identifies, so you can point it at a subnet or a single address.

**Step 1: credentials (if needed).** Many devices accept PEAT's built-in default credentials
for their vendor, but if your devices use custom accounts, PEAT needs them. Create a
configuration file from the example (``peat-config-simple.yaml`` ships with the release
bundles, or download it from
`GitHub <https://github.com/sandialabs/PEAT/blob/main/examples/peat-config-simple.yaml>`__)
and set the credentials under ``device_options``; for example, for an SEL relay:

.. code-block:: yaml
   :caption: my-config.yaml

   metadata:
     name: "my-site"

   device_options:
     sel:
       credentials:
         acc: "OTTER"
         2ac: "TAIL"
     ftp:
       user: "FTPUSER"
       pass: "TAIL"

The :doc:`/user_guide/configure` page explains every section of the file, and
``peat config-builder`` can generate one interactively.

**Step 2: pull.** Pull from one device, limiting PEAT to the module you expect
(``-d selrelay``) and passing the configuration file:

.. code-block:: console

   $ sudo peat pull -R first_pull -c my-config.yaml -d selrelay -i 192.0.2.22
   ...
   04:31:02.310 | Running pull of 1 target using 1 module (comm_type: unicast_ip)
   04:31:02.311 | Checking online status of 1 hosts using ARP and/or ICMP requests
   04:31:02.420 | 1 hosts are responding (checked 1 hosts in 0 seconds)
   04:31:05.101 | 192.0.2.22   | Identification method 'telnet' from module 'SELRelay' succeeded for 192.0.2.22
   04:31:05.110 | Beginning pull for 1 devices
   04:31:05.112 | 192.0.2.22   | Pulling from 192.0.2.22
   04:31:05.120 | 192.0.2.22   | Pulling data via HTTP from 192.0.2.22:80 (timeout: 5.0)
   04:31:09.482 | 192.0.2.22   | Downloading files via FTP from 192.0.2.22:21
   04:31:12.903 | 192.0.2.22   | Parsing SET_ALL.TXT
   04:31:13.250 | 192.0.2.22   | Finished pulling from 192.0.2.22
   04:31:13.255 | Finished pulling from 1 devices in 8.1 seconds
   04:31:13.260 | Saved pull summary to peat_results/first_pull/summaries/pull-summary.json
   04:31:13.262 | Finished run in 11.3 seconds at 2026-10-06 04:31:13.262881+00:00 UTC

**Step 3: results.** Everything PEAT collected is in the run directory, with a
sub-directory per device:

.. code-block:: console

   $ tree peat_results/first_pull/
   peat_results/first_pull/
   ├── devices/
   │   └── 192.0.2.22/
   │       ├── device-data-full.json        # Everything PEAT knows about the device
   │       ├── device-data-summary.json     # The same, minus large fields (file contents, memory)
   │       ├── device-data-event.jsonl      # One JSON object per line, per data type
   │       ├── device-data-interface.jsonl  #   (events, interfaces, services, registers, ...)
   │       ├── ...
   │       ├── formatted-logic.txt          # Human-readable protection and control logic
   │       ├── parsed-config.json           # The parsed device configuration
   │       └── relay_files/                 # The raw files pulled from the device
   │           ├── CFG.TXT
   │           ├── SET_ALL.TXT
   │           └── SETTINGS/
   ├── logs/
   │   ├── peat.log                         # Human-readable log of the run
   │   ├── json-log.jsonl                   # The same log, one JSON object per line
   │   └── telnet.log                       # Protocol transcript (useful when debugging)
   ├── peat_metadata/
   │   ├── peat_configuration.yaml          # The complete configuration used for this run
   │   └── peat_state.yaml
   └── summaries/
       ├── scan-summary.json
       └── pull-summary.json

Start with ``device-data-summary.json``. It uses the same structure for every vendor, so
once you know where to find the firmware version or the list of services for one device,
you know it for all of them:

.. code-block:: console

   $ jq '.firmware.version, .firmware.id, [.service[] | {protocol, port, status}]' \
        peat_results/first_pull/devices/192.0.2.22/device-data-summary.json
   "R516"
   "SEL-351S-6-R516-V2-Z004004-D20190111"
   [
     {"protocol": "ftp", "port": 21, "status": "verified"},
     {"protocol": "telnet", "port": 23, "status": "verified"},
     {"protocol": "http", "port": 80, "status": "open"}
   ]

The device directory also contains vendor-specific files, which are listed per device in
:doc:`/reference/output_files`. The raw files PEAT downloaded are kept unmodified, so they
can be used with the vendor's own software or parsed again later.

.. seealso::
   :doc:`/user_guide/pull` for pulling from many devices, serial pulls, choosing which
   protocols to use, and skipping the scan when you already have an inventory.

Workflow 3: parse a file
========================
Parsing works entirely offline, on files pulled from a device or project files exported
from the vendor's engineering software. This walkthrough uses an example configuration for
a :term:`SCEPTRE` virtual RTU that is included in the PEAT repository, so it runs anywhere.

**Step 1: get a file to parse.** Download the example (or use any file from a pull, such
as an SEL ``SET_ALL.TXT``, a Rockwell ``.L5X`` export, or a Schneider ``.apx`` project):

.. code-block:: console

   $ curl -fLO https://raw.githubusercontent.com/sandialabs/PEAT/main/examples/devices/sceptre/ep/modbus-server.xml

**Step 2: parse.** Specify the module with ``-d`` (PEAT can also auto-detect the module
from the file name or contents when ``-d`` is omitted):

.. code-block:: console

   $ peat parse -R first_parse -d sceptre -- modbus-server.xml
   04:25:11.754 | Log file: peat_results/first_parse/logs/peat.log
   04:25:11.775 | Run directory: first_parse
   04:25:11.779 | Parsing 1 filepaths
   04:25:11.781 | Parsing SCEPTRE file '/home/user/modbus-server.xml'
   04:25:11.805 | Exporting interface to JSONL for Splunk ingestion
   04:25:11.807 | Exporting service to JSONL for Splunk ingestion
   04:25:11.809 | Exporting registers to JSONL for Splunk ingestion
   04:25:11.810 | Exporting tag to JSONL for Splunk ingestion
   04:25:11.812 | Exporting io to JSONL for Splunk ingestion
   04:25:11.819 | Saved parse summary to peat_results/first_parse/summaries/parse-summary.json
   04:25:11.820 | Completed parsing of 1 files in 0.04 seconds
   04:25:11.820 | Finished run in 0.25 seconds at 2026-10-06 04:25:11.820566+00:00 UTC

The ``--`` separates options from the file paths; it is required when an option that takes
multiple values (like ``-d``) comes right before the paths.

**Step 3: results.** The parsed device data is in the run directory, keyed by the device ID
extracted from the file (here the RTU's IP address):

.. code-block:: console

   $ cat peat_results/first_parse/devices/127.0.0.1/device-data-summary.json
   {
       "created": "2026-10-06T04:25:11.801330",
       "description": {
           "brand": "SCEPTRE",
           "full": "Sandia National Laboratories SCEPTRE",
           "model": "SCEPTRE",
           "product": "SCEPTRE",
           "vendor": {"id": "Sandia", "name": "Sandia National Laboratories"}
       },
       "id": "rtu-1",
       "ip": "127.0.0.1",
       "name": "rtu-1",
       "type": "RTU",
       "os": {"full": "Canonical Ubuntu", "name": "Ubuntu", "vendor": {"id": "Canonical", "name": "Canonical"}},
       "logic": {
           "file": {
               "name": "modbus-server.xml",
               "size": 4837,
               "mime_type": "application/xml",
               "hash": {"sha256": "FCFD20DD982D0FD5ACCF944148EBF34D7B026920A53995820F4E374A2D28DD81", ...}
           },
           "parsed": "var_O0 = !(var_I1 >= 500.55)\nvar_O1 = var_O0,delay:10\ncounter = counter + (var_I1 < 500.55)\n..."
       },
       "interface": [
           {
               "application": "modbus",
               "enabled": true,
               "type": "ethernet",
               "ip": "127.0.0.1",
               "services": [{"enabled": true, "port": 5502, "protocol": "modbus", "role": "server", "transport": "tcp"}]
           }
       ],
       "registers": [ ... ],
       "tag": [ ... ],
       "io": [ ... ]
   }

PEAT extracted the device's identity, its Modbus server configuration, the process logic
(``logic.parsed``), and the register, tag, and I/O point definitions, and recorded hashes of
the input file. Parsing a whole directory works the same way (``peat parse -d sel ./relay_backups/``),
and PEAT picks the right module for each file when several modules are allowed.

.. seealso::
   :doc:`/user_guide/parse` for parsing directories, reading from standard input, project
   files, and which modules can parse what.

Where to go next
================
- Run ``peat <command> --examples`` for more invocations of each command.
- The :doc:`/tutorials/index` show complete, realistic workflows end to end.
- :doc:`/user_guide/output` explains every file in a run directory, and
  :doc:`/user_guide/elasticsearch` shows how to send results to Elasticsearch, OpenSearch,
  or Malcolm for dashboards.
- :doc:`/user_guide/configure` covers configuration files, environment variables, and the
  order in which settings are applied.
- Something not working? See :doc:`/user_guide/troubleshooting`.
