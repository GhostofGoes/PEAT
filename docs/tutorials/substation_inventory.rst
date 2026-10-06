*******************************************
Inventory and back up a substation's relays
*******************************************
*You look after protection at Substation A: a dozen SEL relays and an SEL RTAC on a
protection LAN. The settings documentation is a spreadsheet nobody trusts, and the last
settings backup was taken by a contractor with the vendor software, one relay at a time.
You want an inventory you can trust and a settings backup you can repeat every month and
diff.*

What you need
=============
- A Linux workstation or laptop on the protection LAN (``192.0.2.0/24`` here), with PEAT
  installed and ``sudo`` access. A Windows laptop works too; see
  :doc:`windows_field_laptop`.
- The relays' Telnet/FTP account details (SEL's default access levels are ``acc`` and
  ``2ac``; FTP is often a separate user), and the RTAC's web credentials.
- Permission from operations. A pull logs into every relay and downloads its files; it
  reads, but it does log in. Schedule it, and tell whoever watches the IDS.

Step 1: write the site configuration
====================================
Start from ``peat-config-simple.yaml`` and describe the site. Everything here applies to
all SEL devices; the ``hosts`` section pins down the two devices that differ.

.. code-block:: yaml
   :caption: substation-a.yaml

   metadata:
     name: "substation-a"
     description: "Substation A protection LAN: SEL-351S/451/751 relays and SEL-3530 RTAC"
     author: "protection group"
     created: "2026-10-01"

   # Fail fast on the local LAN
   default_timeout: 3.0

   device_options:
     sel:
       # Use FTP for files when it's enabled on the relay, Telnet as the fallback
       pull_methods:
         - ftp
         - telnet
       # Event reports are large and change constantly; we only want settings
       never_download_dirs:
         - EVENTS
       credentials:
         acc: "OTTER"
         2ac: "TAIL"
     ftp:
       user: "FTPUSER"
       pass: "TAIL"
     http:
       timeout: 10.0

   hosts:
     - label: "rtac"
       comment: "SEL-3530 RTAC, substation gateway"
       identifiers:
         ip: 192.0.2.10
       peat_module: "SELRTAC"
       options:
         web:
           user: "peat-readonly"
           pass: "s3cret"
     - label: "feeder-7"
       comment: "SEL-751 on feeder 7, FTP disabled by policy"
       identifiers:
         ip: 192.0.2.27
       peat_module: "SELRelay"
       options:
         sel:
           pull_methods:
             - telnet

Protect the file, it holds credentials:

.. code-block:: bash

   chmod 600 substation-a.yaml
   # Optional: encrypt it; PEAT prompts for the password when the file is used with -c
   peat encrypt-config -f substation-a.yaml

Step 2: dry run
===============
Check that PEAT parses the configuration, finds the modules, and expands the targets the
way you expect, without sending a packet:

.. code-block:: console

   $ sudo peat scan --dry-run -c substation-a.yaml -d sel -i 192.0.2.0/24
   | Configuration 'substation-a' loaded from 'substation-a.yaml'
   | WARNING: Dry run mode is enabled! ...
   | Running scan of 1 target using 3 modules (comm_type: unicast_ip)
   | WARNING: Dry run enabled, skipping calling command functions

``-d sel`` selects all three SEL modules (relays, RTACs, and the 3620 gateway).

Step 3: scan for the inventory
==============================
.. code-block:: console

   $ sudo peat scan -R substation-a-inventory -c substation-a.yaml -d sel -i 192.0.2.0/24
   | Checking online status of 254 hosts using ARP and/or ICMP requests
   | 14 hosts are responding (checked 254 hosts in 3 seconds)
   | Scanning 14 IPs using 3 modules: SEL3620, SELRTAC, SELRelay
   | 192.0.2.10   | Identification method 'http' from module 'SELRTAC' succeeded for 192.0.2.10
   | 192.0.2.21   | Identification method 'telnet' from module 'SELRelay' succeeded for 192.0.2.21
   ...
   | Completed scan of 14 devices in 41.2 seconds (14 results)

Turn the summary into the inventory table your spreadsheet should have been:

.. code-block:: console

   $ jq -r '.hosts_verified[] | [.ip, .mac, .description.product, .firmware.id // "", .peat_module] | @tsv' \
         peat_results/substation-a-inventory/summaries/scan-summary.json | column -t
   192.0.2.10  00:30:A7:0A:10:01  SEL-3530        SEL-3530-R144-V2-Z011002-D20190216  SELRTAC
   192.0.2.21  00:30:A7:0A:21:01  SEL-351S        SEL-351S-6-R516-V2-Z004004-D20190111  SELRelay
   192.0.2.22  00:30:A7:0A:22:01  SEL-451         SEL-451-5-R322-V0-Z011011-D20180630  SELRelay
   ...

   # Hosts that answered but PEAT could not identify: the switch, a laptop, something else?
   $ jq '.hosts_online' peat_results/substation-a-inventory/summaries/scan-summary.json
   ["192.0.2.1", "192.0.2.254"]

Everything in ``hosts_online`` deserves a look: it is on the protection LAN and PEAT
doesn't know what it is.

Step 4: pull the settings
=========================
.. code-block:: console

   $ sudo peat pull -R substation-a-2026-10 -c substation-a.yaml -d sel -i 192.0.2.0/24
   | Beginning pull for 14 devices
   | 192.0.2.10   | Pulling from 192.0.2.10
   | 192.0.2.10   | Finished pulling from 192.0.2.10
   | 192.0.2.21   | Pulling from 192.0.2.21
   | 192.0.2.21   | Downloading files via FTP from 192.0.2.21:21
   ...
   | 192.0.2.27   | WARNING: Skipping method 'ftp' for pull from 192.0.2.27: 'ftp' not listed in 'sel.pull_methods' option
   | 192.0.2.27   | Finished pulling from 192.0.2.27
   | Finished pulling from 14 devices in 6 minutes and 12 seconds

Each relay's directory now holds the raw settings files, exactly as the relay serves them,
plus PEAT's parsed views:

.. code-block:: console

   $ tree peat_results/substation-a-2026-10/devices/192.0.2.21/
   peat_results/substation-a-2026-10/devices/192.0.2.21/
   ├── device-data-full.json
   ├── device-data-summary.json
   ├── device-data-*.jsonl
   ├── formatted-logic.txt
   ├── parsed-config.json
   └── relay_files/
       ├── CFG.TXT
       ├── SET_ALL.TXT
       └── SETTINGS/
           ├── SET_1.TXT
           ├── SET_G.TXT
           ├── SET_L1.TXT
           ├── SET_P1.TXT
           └── ...

``relay_files/`` is your backup: ``SET_ALL.TXT`` is the complete configuration, and the
individual ``SET_*.TXT`` files are what you would push back to restore it (see
:doc:`/user_guide/push`). ``formatted-logic.txt`` is the protection and control logic
(SELogic equations) laid out for reading, and ``parsed-config.json`` the settings as
structured data. :doc:`/reference/devices/sel` explains the files and the FID string.

A quick sanity check across the fleet, straight from the data model:

.. code-block:: console

   $ jq -r '[.ip, .description.model, .firmware.version, (.event | length)] | @tsv' \
         peat_results/substation-a-2026-10/devices/*/device-data-summary.json | column -t
   192.0.2.10  SEL-3530  R144  812
   192.0.2.21  SEL-351S  R516  0
   192.0.2.22  SEL-451   R322  0
   ...

(The RTAC's ``event`` entries are its system log; relay event reports were skipped by
``never_download_dirs``.)

Step 5: make it monthly
=======================
Put the pull in a script and run it from ``cron`` (or a scheduler on the workstation)
with a run name that carries the date. The exit code tells you whether every device
succeeded:

.. code-block:: bash
   :caption: /opt/peat/pull-substation-a.sh

   #!/usr/bin/env bash
   set -euo pipefail
   cd /opt/peat
   RUN="substation-a-$(date +%Y-%m)"
   if peat pull -q -R "$RUN" -c substation-a.yaml -d sel -i 192.0.2.0/24; then
       echo "PEAT pull $RUN succeeded"
   else
       echo "PEAT pull $RUN had failures, see peat_results/$RUN/logs/peat.log" >&2
       exit 1
   fi

.. code-block:: text
   :caption: crontab -e (first Sunday of the month, 02:00)

   0 2 1-7 * 0  /opt/peat/pull-substation-a.sh >> /var/log/peat-substation-a.log 2>&1

Step 6: find what changed
=========================
Because the raw files are kept unmodified and the run names carry the date, a settings
change shows up as a diff:

.. code-block:: console

   $ diff -u peat_results/substation-a-2026-09/devices/192.0.2.22/relay_files/SET_ALL.TXT \
             peat_results/substation-a-2026-10/devices/192.0.2.22/relay_files/SET_ALL.TXT
   --- .../substation-a-2026-09/devices/192.0.2.22/relay_files/SET_ALL.TXT
   +++ .../substation-a-2026-10/devices/192.0.2.22/relay_files/SET_ALL.TXT
   @@ -212,7 +212,7 @@
   -50P1P   := 6.00
   +50P1P   := 8.00

   # Across the whole fleet at once
   $ for d in peat_results/substation-a-2026-10/devices/*/; do
       ip=$(basename "$d")
       diff -q "peat_results/substation-a-2026-09/devices/$ip/relay_files/SET_ALL.TXT" \
               "$d/relay_files/SET_ALL.TXT" > /dev/null || echo "CHANGED: $ip"
     done
   CHANGED: 192.0.2.22

Was the pickup change to the 50P1P element on the feeder 22 relay authorized? Now you
know to ask. For firmware changes, compare ``firmware.id`` in the summaries; for a
structured comparison, use the data model (see the ``DeepDiff`` example in
:doc:`/developer/python_examples`), or send every run to
:doc:`Elasticsearch <elasticsearch_dashboard>` and chart it.

Step 7: keep the results safe
=============================
The run directories contain the relays' complete settings and, in the pulled files,
their passwords. Restrict access to ``peat_results/``, and when results leave the
workstation, encrypt them:

.. code-block:: bash

   peat encrypt-results -f peat_results/substation-a-2026-10 -w /secure/archive/

See :doc:`/user_guide/encryption` and, for the hand-off to analysts elsewhere,
:doc:`isolated_network`.

Variations
==========
- **Serial relays.** Older relays without Ethernet are reachable through a serial cable:
  ``peat pull -d selrelay -s /dev/ttyUSB0 --baudrates 9600`` (see :doc:`/user_guide/scan`
  and the serial notes in :doc:`/reference/devices/sel`).
- **Mixed vendors.** Add the other vendors' modules to ``-d`` (``-d sel ge m340``) and
  their credentials to ``device_options``; the output structure stays the same.
- **No ICMP.** If the LAN's firewall blocks pings, use ``-Y`` with the known addresses
  from the ``hosts`` section, or ``peat pull --skip-scan -c substation-a.yaml`` once every
  host has a ``peat_module``.
