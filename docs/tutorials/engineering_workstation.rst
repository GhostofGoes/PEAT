********************************************
Investigate an engineering workstation image
********************************************
*An incident response team has imaged the engineering workstation of a water treatment
plant after suspicious activity. You have the disk image (a VMDK from the virtualization
host) and, separately, PEAT pulls from the plant's Schneider M340 and Rockwell
ControlLogix PLCs taken yesterday. The questions: what project files and relay settings
did the workstation hold, what logic do they contain, and does it match what's running
on the PLCs?*

This is what ``peat pillage`` and ``peat parse`` are for. Pillage finds the vendor files
on the image; parse turns them into the same data model as the pulls, so the comparison is
file to file and field to field.

What you need
=============
- A Linux analysis machine (Ubuntu 22.04 or newer is well tested) with root access,
  PEAT, and ``qemu-utils`` (``sudo apt install qemu-utils``). The kernel must support the
  image's filesystem (NTFS for a Windows workstation; ``ntfs3`` is built into modern
  kernels).
- The disk image: raw, qcow2, VMDK, VDI, or VHD/VHDX, as a single file. Work on a copy,
  and compute its hash first.
- The PEAT pulls from the live devices (``peat_results/plant-2026-10-05/``).

.. warning::
   Pillage mounts the image **read-only**, but forensic practice still applies: hash the
   image before and after, and keep your working copy separate from the evidence copy.

Step 1: hash the evidence
=========================
.. code-block:: console

   $ sha256sum ews-01.vmdk | tee ews-01.vmdk.sha256
   7c1d5...  ews-01.vmdk

Step 2: tell pillage what to look for
=====================================
The ``pillage`` section of a configuration file lists, per vendor, the file names and
extensions worth copying. The reference configuration's defaults cover the common
vendors; here it's trimmed to the plant's vendors plus a catch-all for relay settings,
and ``auto_copy`` is on so the run is unattended:

.. code-block:: yaml
   :caption: pillage.yaml

   metadata:
     name: "ews-01-pillage"

   pillage:
     auto_copy: true
     recursive: true
     default:
       locations: []
       filenames: []
       extensions: []
     brands:
       Modicon:
         extensions: [apx, stu, sta, xef]
       L5X:
         extensions: [l5x, acd, l5k]
       SEL:
         filenames: [set_all.txt, cfg.txt]
         extensions: [rdb, cid]

Pillage copies anything that matches; ``parse`` later decides what it can actually read
(PEAT parses ``.apx`` and ``.L5X``; ``.stu``/``.sta``/``.acd`` are kept as evidence for the
vendor tools).

Step 3: pillage the image
=========================
.. code-block:: console

   $ sudo peat pillage -R ews-01 -c pillage.yaml -P ./ews-01.vmdk
   | Pillage source path: ./ews-01.vmdk
   | Loading nbd kernel module
   | Attaching ./ews-01.vmdk to /dev/nbd1 (read-only)
   | Mounting /dev/nbd1p2 at pillage_temp
   | Searching 184,213 files...
   | Copying C:/Users/eng/Documents/Unity/WTP_Filters_v12.apx -> pillage_results/Modicon/WTP_Filters_v12.apx
   | Copying C:/Users/eng/Documents/Unity/WTP_Filters_v12.stu -> pillage_results/Modicon/WTP_Filters_v12.stu
   | Copying C:/Users/eng/Desktop/backup/WTP_Filters_v11.apx -> pillage_results/Modicon/WTP_Filters_v11.apx
   | Copying C:/RSLogix 5000/Projects/Clarifier.L5X -> pillage_results/L5X/Clarifier.L5X
   | Copying C:/Users/eng/Downloads/Clarifier (1).L5X -> pillage_results/L5X/Clarifier (1).L5X
   | Copying C:/SEL/QuickSet/Settings/Feeder1.rdb -> pillage_results/SEL/Feeder1.rdb
   | Unmounting and detaching image
   | Pillage complete: 6 files copied

   $ tree pillage_results/
   pillage_results/
   ├── L5X/
   │   ├── Clarifier (1).L5X
   │   └── Clarifier.L5X
   ├── Modicon/
   │   ├── WTP_Filters_v11.apx
   │   ├── WTP_Filters_v12.apx
   │   └── WTP_Filters_v12.stu
   └── SEL/
       └── Feeder1.rdb

Two things are already interesting: a second copy of the clarifier project in
``Downloads`` with a browser-style ``(1)`` suffix, and an older filter project on the
desktop. The PEAT log (``peat_results/ews-01/logs/peat.log``) records the original path of
every copied file, which you'll want for the timeline.

If the mount fails, wait a few seconds and retry; if PEAT couldn't clean up, see
"When things go wrong" in :doc:`/user_guide/pillage`.

Step 4: parse what was found
============================
Parse each vendor's directory with its module. Name the runs so they're easy to tell
apart from the live pulls.

.. code-block:: console

   $ peat parse -R ews-01-m340 -d m340 ./pillage_results/Modicon/
   | Parsing 1 filepaths
   | Parsing M340 file '.../pillage_results/Modicon/WTP_Filters_v12.apx'
   | Parsing M340 file '.../pillage_results/Modicon/WTP_Filters_v11.apx'
   | Completed parsing of 2 files in 1.84 seconds

   $ peat parse -R ews-01-l5x -d l5x ./pillage_results/L5X/
   $ peat parse -R ews-01-sel -d selrelay ./pillage_results/SEL/

Each parsed file becomes a device directory with the familiar files, plus the parser's
output. For the M340 projects, that includes the Structured Text logic and a TC6 XML
export:

.. code-block:: console

   $ ls peat_results/ews-01-m340/devices/
   192.0.2.41  WTP_Filters_v11

   $ ls peat_results/ews-01-m340/devices/192.0.2.41/
   WTP_Filters_v12.apx  device-data-full.json  device-data-summary.json  logic.st  parsed-config.txt  tc6.xml ...

(The newer project named the PLC's IP, so it's keyed by it; the older one had no address
and is keyed by file name.)

Step 5: compare with the live PLCs
==================================
The pull from the plant's M340 produced the same kinds of files from the running
controller. Compare the logic first, then the project metadata:

.. code-block:: console

   # Logic: the v12 project on the workstation vs. what the PLC is running
   $ diff <(jq -r '.logic.parsed' peat_results/ews-01-m340/devices/192.0.2.41/device-data-full.json) \
          <(jq -r '.logic.parsed' peat_results/plant-2026-10-05/devices/192.0.2.41/device-data-full.json)
   142c142
   <     IF Turbidity_NTU > 1.0 THEN Filter_Backwash := TRUE; END_IF;
   ---
   >     IF Turbidity_NTU > 4.0 THEN Filter_Backwash := TRUE; END_IF;

   # Hashes of the project blobs
   $ jq '.logic.hash.sha256' peat_results/ews-01-m340/devices/192.0.2.41/device-data-full.json \
                              peat_results/plant-2026-10-05/devices/192.0.2.41/device-data-full.json
   "9F1E...A3"
   "0C77...1B"

   # Project name, author, last update, as recorded in each project file
   $ jq '{name: .logic.name, author: .logic.author, updated: .logic.last_updated}' \
        peat_results/ews-01-m340/devices/192.0.2.41/device-data-summary.json \
        peat_results/plant-2026-10-05/devices/192.0.2.41/device-data-summary.json

The PLC is running logic that differs from the latest project on the workstation: the
backwash threshold was changed from 1.0 to 4.0 NTU, and the running project's hash
doesn't match either saved version. That is a finding for the incident report, and the
timestamps and ``logic.author`` give the next lead.

The same comparison works for the ControlLogix (``.L5X`` project vs. the ``parsed-logic``
pulled over CIP) and for the SEL settings (``.rdb`` vs. the relay's ``SET_ALL.TXT``).
For a structured diff of entire devices rather than individual fields, see the ``DeepDiff``
example in :doc:`/developer/python_examples`, or load everything into
:doc:`Elasticsearch <elasticsearch_dashboard>`.

Step 6: preserve
================
.. code-block:: console

   $ sha256sum ews-01.vmdk | diff - ews-01.vmdk.sha256 && echo "image unchanged"
   $ peat encrypt-results -f peat_results/ews-01-m340 -w ./case-2026-114/
   $ peat encrypt-results -f peat_results/ews-01-l5x -w ./case-2026-114/
   $ tar -czf case-2026-114/pillage_results.tgz pillage_results/

Notes
=====
- Pillage currently writes to ``./pillage_results/`` in the current directory, not into
  the run directory; keep the two together in your case folder.
- Pillage from inside the PEAT container can't attach disk images; mount the image on the
  host and pass the mount point with ``-v`` instead (see :doc:`/user_guide/containers`).
- A live workstation can be pillaged over a mounted share (``-P /mnt/ews-c``), which is
  useful before an image exists, but it isn't a forensic acquisition.
- Project files can contain credentials for the devices they program. Treat
  ``pillage_results/`` as sensitive.
