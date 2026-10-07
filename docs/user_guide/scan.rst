*****************
Scanning networks
*****************
``peat scan`` discovers :doc:`supported devices </getting_started/supported_devices>` on a
network or on serial ports, determines what they are, and gathers basic information about
them. It is essentially a lightweight :term:`Nmap` specialized for :term:`OT` devices, with
a focus on minimizing or eliminating impacts to field devices and processes: PEAT only
probes the ports its modules use, in the gentlest order its modules know, and stops as
soon as a device is identified.

The scan writes a :ref:`scan summary <scan-summary>` to
``peat_results/<run-dir>/summaries/scan-summary.json``, optionally prints it to the
terminal (``-E``), and optionally exports it to the ``peat-scan-summaries`` Elasticsearch
index (``-e``).

.. tip::
   If you know you want detailed information from the devices, run ``peat pull`` directly.
   A pull always performs a scan first and only pulls from the devices it identifies, so
   there is no need to scan and then pull as separate steps.

.. only:: html

   .. figure:: /images/terminal/scan_examples.svg
      :alt: Terminal showing the first part of the peat scan --examples cheat sheet: scanning a single host, a subnet, with broadcasts, with specific modules, and ranges of addresses
      :figclass: peat-terminal

      ``peat scan --examples`` is a cheat sheet of real-world invocations; the :ref:`complete list <scan-examples>` is at the end of this page.

How a scan works
================
For each target host PEAT:

1. **Checks whether the host is online**, using :term:`ARP` requests on the local subnet
   and :term:`ICMP` echo requests for routed hosts when it has root/Administrator
   permissions, or a :term:`TCP` connection attempt to one port (80 by default,
   :attr:`SYN_PORT <peat.settings.Configuration.SYN_PORT>`) otherwise. Hosts that answer
   are *online*.
2. **Checks which ports are open**, limited to the ports used by the identification
   methods of the selected modules (each unique port is checked once).
3. **Runs identification methods** against the open ports, in order of each method's
   reliability, and stops at the first success. A host identified this way is *verified*,
   and its data (vendor, model, firmware, services) comes from that method.

.. raw:: html
   :file: ../images/scan_pipeline.svg

.. only:: not html

   Hosts that don't answer the online check are *offline* and not probed further (they
   appear only in the summary's ``scan_targets``); hosts with no open ports or no
   successful method are listed in ``hosts_online``; identified hosts are in
   ``hosts_verified`` with the vendor, model, firmware, services, and MAC address from
   the method that succeeded.

``-Y`` (``--assume-online``) skips the online check, ``--sweep`` stops after it, and
``--intensive-scan`` runs every identification method regardless of open ports and
earlier successes. The :doc:`design documentation </design/scanning>` describes each
step in detail.

Unicast IP scanning
===================
The default. Targets are IP addresses, hostnames, :term:`CIDR` networks, ranges, host
labels from the configuration file, or files of hosts (see :ref:`targets`):

.. code-block:: bash

   # A single host
   peat scan -i 192.0.2.1

   # A subnet: all 254 hosts from 192.0.2.1 to 192.0.2.254
   peat scan -i 192.0.2.0/24

   # Several networks, a range, and a hostname
   peat scan -i 192.0.2.0/24 10.0.0.0/24 192.168.0.10-20 relay-7.example.net

   # Only the kinds of devices you expect (recommended)
   peat scan -d sel -i 192.0.2.0/24
   peat scan -d m340 controllogix -i 192.0.2.0/24

   # Use a file of targets (one per line, or a JSON array)
   peat scan -i examples/target_hosts.txt

   # Use the results of a previous run as the targets
   peat scan -f examples/example-scan-summary.json
   cat examples/example-scan-summary.json | peat scan -f -

Host discovery only
-------------------
``--sweep`` only checks which hosts are online (like ``nmap -sn``), without fingerprinting:

.. code-block:: bash

   peat scan --sweep -i 192.0.2.0/24

   # Pipe the online hosts into a full scan
   peat scan -q -E --sweep -i 192.0.2.0/24 | peat scan -f -

Hosts that don't answer pings
-----------------------------
Devices behind firewalls, or devices that drop ICMP (the SEL RTAC, for example), appear
offline. ``-Y`` (``--assume-online``) skips the online check and fingerprints every target
(like ``nmap -Pn``). This significantly increases the time to scan more than one host, so
use it for specific addresses rather than whole subnets:

.. code-block:: bash

   peat scan -Y -i 192.0.2.22 192.0.2.23
   peat scan -Y -f examples/example-scan-summary.json

Intensive scanning
------------------
``--intensive-scan`` runs *every* identification method against *every* target, regardless
of which ports are open, and keeps going after the first successful identification. It
takes significantly longer and generates much more traffic and load on devices. Only use it
when you aren't worried about performance impacts to field devices, for example in a lab or
when a device isn't being identified by a normal scan.

.. code-block:: bash

   peat scan -d controllogix -i 192.0.2.0/24 --intensive-scan

.. _broadcast-scanning:

Broadcast scanning
==================
Network broadcasts discover devices more efficiently and less intrusively than probing
every address: PEAT sends a single packet (or a small set) to the broadcast address of a
subnet (``192.0.2.255`` for ``192.0.2.0/24``) and waits for devices to respond. Devices
that respond are then interrogated further using the normal unicast methods.

Benefits:

- Far fewer packets on the network, and only devices that expect the traffic respond
- Reduced risk of upsetting unrelated devices
- Efficient discovery in very large networks (for example a whole /16 with 65,534 addresses)

Limitations:

- Only IP (:term:`OSI Model` layer 3) broadcasts are supported; layer 2 (:term:`MAC`)
  broadcasts may be added later.
- PEAT must be in the same broadcast domain as the devices. In a container, this requires
  ``--network host`` (see :doc:`containers`).
- Supported by modules whose protocols have a discovery broadcast: currently the
  ControlLogix module (using the :term:`CIP` List Identity broadcast).

Targets for ``-b`` (``--broadcast``) are networks, broadcast addresses, local interface
names, or files containing them:

.. code-block:: bash

   # Discover devices on a network using IP broadcasts
   peat scan -b 192.0.2.0/24

   # Broadcast on the network of a local interface
   peat scan -b eth1

   # Broadcast targets from a file, and combinations of everything
   peat scan -b examples/broadcast_targets.txt
   peat scan -b 192.0.3.0/24 192.168.2.255 192.0.2.0/25 eth1 examples/broadcast_targets.txt

   # Pull from every device discovered by broadcast
   peat pull -b 192.0.2.0/24

Serial port scanning
====================
Devices connected directly over RS-232 (including USB-to-serial adapters) are scanned with
``-s`` (``--serial``). Targets are port names or numbers; a number ``N`` means ``COMN`` on
Windows and ``/dev/ttySN`` plus ``/dev/ttyUSBN`` on Linux. Since the state of a serial port
can't be checked beforehand, scanning many unconnected ports takes a while; name the ports
you have and limit the baud rates with ``--baudrates`` when you know them.

.. code-block:: bash

   # Search for devices on serial ports 0 through 4
   peat scan -s 0-4

   # Specific ports
   peat scan -s /dev/ttyUSB0 /dev/ttyS1
   peat scan -d selrelay -s COM4 COM6

   # Only try a baud rate of 9600
   peat scan -d selrelay -s COM4 --baudrates 9600

   # Enumerate the active serial ports on this host
   peat scan -s 0-9 --sweep

Modules that support serial identification: the SEL relay module and the Woodward 2301E
and easYgen 3500XT modules (see :doc:`/getting_started/supported_devices`). On Linux, access to serial devices
requires root or membership of the ``dialout`` group.

Reading the results
===================
The scan summary separates hosts into:

- ``hosts_online``: responded to the online check but were **not** identified (PEAT doesn't
  know what they are, or no module for them was selected)
- ``hosts_verified``: identified, with the device data collected during identification
  (vendor, model, firmware when available, services and their status, MAC address)

.. code-block:: bash

   # Verified devices as a table: IP, product, PEAT module
   jq -r '.hosts_verified[] | [.ip, .description.product, .peat_module] | @tsv' \
       peat_results/first_scan/summaries/scan-summary.json

   # Hosts PEAT could not identify (candidates for an intensive scan or a new module)
   jq '.hosts_online' peat_results/first_scan/summaries/scan-summary.json

See :ref:`scan-summary` for every field. A device's full data is also written to
``devices/<ip>/device-data-full.json`` in the run directory.

Scanning considerations
=======================
- **Permissions**: root (Linux) or Administrator (Windows) lets PEAT use ARP and ICMP for
  online checks, which are faster and gentler than TCP connection attempts, and resolves
  device MAC addresses. See :doc:`/getting_started/requirements`.
- **Timeouts**: ``-T`` (``--timeout``) defaults to 5 seconds. Lower it on fast local
  networks with many empty addresses; raise it for slow serial links or devices.
- **Threads**: online and port checks run with up to
  :attr:`MAX_THREADS <peat.settings.Configuration.MAX_THREADS>` (260) concurrent threads.
  Fingerprinting itself runs one host at a time, lowest IP first.
- **Routed networks**: MAC addresses can't be resolved for devices behind a router or
  gateway, and online checks use ICMP (with a TCP fallback) instead of ARP.
- **IDS alerts**: PEAT's scans look like reconnaissance to an intrusion detection system.
  Coordinate with the network's defenders first.
- **Dry run**: ``--dry-run`` validates the targets, modules, and configuration without
  sending any packets.

.. _scan-examples:

Examples
========
The complete list of scan examples from ``peat scan --examples``:

.. literalinclude:: ../../peat/cli_args.py
   :language: bash
   :start-after: scan_examples = """
   :end-before: """  # End scan_examples
