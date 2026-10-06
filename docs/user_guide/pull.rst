******************************
Pulling artifacts from devices
******************************
``peat pull`` actively interrogates devices to retrieve detailed information and
:term:`artifacts <Artifact>`: configuration, process logic, firmware, logs, event history,
memory, file listings, and more, depending on what each device and its PEAT module
support. Everything collected is normalized into PEAT's :doc:`data model
</developer/data_model>` and written to the run directory, with the raw files kept
unmodified alongside.

A pull is a scan followed by a per-device collection: PEAT first :doc:`scans <scan>` the
targets and only pulls from the devices it successfully identifies, using the module that
identified each one. The scan summary is saved too, so a pull gives you an inventory and
the artifacts in a single run.

Basic usage
===========
.. code-block:: bash

   # Pull from a single device, or everything PEAT recognizes on a subnet
   peat pull -i 192.0.2.1
   peat pull -i 192.0.2.0/24

   # Limit to the devices you expect (recommended), with a run name
   peat pull -R site-a -d selrelay -i 192.0.2.0/24
   peat pull -d m340 controllogix -i 192.0.2.1-5
   peat pull -d rtu -i 192.0.2.0/24

   # Pull from everything discovered by a broadcast, or from the results of a previous scan
   peat pull -b 192.0.2.0/24
   peat pull -f peat_results/first_scan/summaries/scan-summary.json

   # Pull from a Woodward 2301E on serial port 0 (COM0 on Windows, /dev/ttyS0 on Linux)
   peat pull -d 2301e -s 0

   # Verify the configuration without touching devices
   peat pull --dry-run -c peat-config.yaml -d selrelay -i 192.0.2.0/24

.. warning::
   Pulls read from devices, but reading isn't free: PEAT logs into devices, lists and
   downloads files, and runs diagnostic commands. On fragile or heavily loaded devices,
   limit what is pulled (see :ref:`pull-what`), pull during a maintenance window, and
   try a single device before a whole subnet.

Credentials and per-device options
==================================
PEAT modules know the default credentials and ports for their devices, and many pulls work
with no configuration at all. When devices use custom accounts, provide them in a
:doc:`configuration file <configure>`:

- ``device_options`` applies to every device of a kind (for example all SEL relays)
- ``hosts`` entries apply options to a specific device, and can also pin the module to use

.. code-block:: yaml
   :caption: Credentials for all SEL relays, plus an override for one relay

   device_options:
     sel:
       credentials:
         acc: "OTTER"
         2ac: "TAIL"
     ftp:
       user: "FTPUSER"
       pass: "TAIL"

   hosts:
     - label: "feeder-7"
       identifiers:
         ip: 192.0.2.23
       peat_module: "SELRelay"
       options:
         ftp:
           pass: "a-different-password"
         sel:
           never_download_dirs:
             - EVENTS

The configuration reference (:ref:`peat-config`) lists the options for each module, and
``peat config-builder`` can create a file interactively (:doc:`config_builder`).

.. _pull-what:

Choosing what is pulled
=======================
Most modules can use several protocols and let you restrict which ones are used
(``pull_methods``), and what is downloaded. A few examples:

.. code-block:: yaml

   device_options:
     sel:
       # Only use Telnet for SEL relays (e.g. FTP is disabled on the devices)
       pull_methods:
         - telnet
       # Skip event records and HMI files, which can be large
       never_download_dirs:
         - EVENTS
         - HMI
       # Or download only specific files
       only_download_files:
         - SET_ALL.TXT
         - CFG.TXT
     fortigate:
       pull_methods: [ssh]
       log_pull_timeout: 60.0

A ready-made example that forces Telnet for SEL devices is
:download:`peat-config-sel-force-telnet.yaml <../../examples/peat-config-sel-force-telnet.yaml>`.
Per-module details are in the :ref:`configuration reference <peat-config>` and the
:doc:`device reference pages </reference/devices/index>`.

Pulling without scanning
========================
When you already have an inventory, ``--skip-scan`` pulls directly from the hosts in the
configuration file's ``hosts`` list, each with its ``peat_module``, without the discovery
and identification phase. A single ``-d`` module can serve as the fallback for hosts
without a ``peat_module``. With a configuration file that has a ``hosts`` list, the ``-i``
argument is optional.

.. code-block:: bash

   peat pull --skip-scan -c peat-config.yaml
   peat pull --skip-scan -c peat-config.yaml -d selrelay -i 192.0.2.22 192.0.2.23

This is faster and avoids scan traffic, at the cost of PEAT not verifying that the device
is what the configuration says it is.

Results
=======
Each device's results are in ``peat_results/<run-dir>/devices/<device-id>/``:

- ``device-data-full.json`` and ``device-data-summary.json``: the device in PEAT's data
  model (see :doc:`output`)
- The raw artifacts pulled from the device, unmodified (configuration files, project
  files, firmware images, logs), and files PEAT derived from them (parsed configuration,
  decompiled or formatted logic). These are listed per device in
  :doc:`/reference/output_files`.

The :ref:`pull summary <pull-summary>` in ``summaries/pull-summary.json`` lists the
devices pulled and their data (minus large fields). Only the device data is printed to the
terminal with ``-E``.

.. code-block:: bash

   # Which devices were pulled, and did every pull succeed?
   jq -r '.pull_devices[]' peat_results/site-a/summaries/pull-summary.json
   grep -c "Pull failed" peat_results/site-a/logs/peat.log

   # Every file pulled from every device, with sizes
   tree -ah peat_results/site-a/devices/

   # Compare the settings of a relay against the pull from last month
   diff peat_results/site-a-september/devices/192.0.2.22/relay_files/SET_ALL.TXT \
        peat_results/site-a/devices/192.0.2.22/relay_files/SET_ALL.TXT

Devices with several communication modules
==========================================
A PLC with multiple Ethernet modules appears at several IP addresses. PEAT de-duplicates
devices after the scan and merges their data into one device, keyed by the first module
that was identified. Merging isn't perfect yet for ControlLogix PLCs with two or more
communication modules that are both interrogated (see :ref:`known-issues`); if you need a
deterministic result, target one module's address.

Pulling from many devices
=========================
- Pulls are sequential, one device at a time, so a large pull takes roughly the sum of the
  individual pulls. Split very large populations into several runs if needed.
- Use ``-R`` with a meaningful name (site, date) so runs are easy to compare later.
- Use ``-c`` with a site configuration that limits modules and protocols, and consider
  excluding bulky, low-value artifacts (event records, HMI files).
- Export to :doc:`Elasticsearch <elasticsearch>` (``-e``) to query across devices and
  runs.
- The :doc:`tutorials </tutorials/index>` include a worked example of inventorying and
  backing up a substation's relays.

Examples
========
The complete list of pull examples from ``peat pull --examples``:

.. literalinclude:: ../../peat/cli_args.py
   :language: bash
   :start-after: pull_examples = """
   :end-before: """  # End pull examples
