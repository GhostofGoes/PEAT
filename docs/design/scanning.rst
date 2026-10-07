.. _scanning-process:

************************************
How scanning and fingerprinting work
************************************
A descriptive summary of how scanning (also called fingerprinting, identification, or
verification) works in PEAT. The implementation is :mod:`peat.api.scan_api`; refer to it
for the details. The user-facing guide is :doc:`/user_guide/scan`.

Three kinds of scan exist, selected by the kind of targets given: unicast IP (``-i``),
broadcast IP (``-b``), and serial (``-s``). All three share the same final steps: run the
modules' identification methods, record the results in the datastore, and produce a
:ref:`scan summary <scan-summary>`.

Identification methods
======================
Each device module declares how it can be identified in two class attributes:

- ``ip_methods``: a list of :class:`~peat.api.identify_methods.IPMethod` instances, each
  with a ``type`` of ``unicast_ip`` or ``broadcast_ip``
- ``serial_methods``: a list of :class:`~peat.api.identify_methods.SerialMethod` instances

A method bundles the function that performs the identification
(``identify_function``), the protocol name (``protocol``) and its default port
(``default_port``) and transport, a human-readable name and description, and a
``reliability`` score from 0 to 10. The reliability is the method author's judgment of how
consistently the method produces results, how fast it is, and how much load it puts on
the device; higher is better. PEAT sorts methods by reliability so the gentlest, most
dependable checks run first. A method may also define a custom ``port_function`` to check
whether its port is open, for services that need special handling (or that are prone to
toppling over when probed naively).

Unicast IP scanning
===================
Unicast :term:`IP` scanning sends packets directly to each device.

#. **Generate the target list.** The user's targets (hosts, hostnames, networks, ranges,
   labels, files) are expanded into an ordered list of unique IP addresses, sorted from
   lowest to highest (``10.0.0.92`` before ``10.10.0.1``).
#. **Collect the applicable modules.** By default, every imported module with a non-empty
   ``ip_methods`` attribute; filtered by ``-d`` if given.
#. **Check which hosts are online.** Checks are multi-threaded, one thread per host, up to
   :attr:`MAX_THREADS <peat.settings.Configuration.MAX_THREADS>` (260) at a time.

   - With ``root``/Administrator rights (raw sockets available): :term:`ARP` requests for
     hosts in a local subnet (the same broadcast domain), :term:`ICMP` echo requests for
     hosts behind a gateway. If ICMP fails and
     :attr:`ICMP_FALLBACK_TCP_SYN <peat.settings.Configuration.ICMP_FALLBACK_TCP_SYN>` is
     set (the default), a TCP connection attempt is tried as well, since many devices and
     firewalls drop ICMP.
   - Without raw sockets: a TCP connection to one port,
     :attr:`SYN_PORT <peat.settings.Configuration.SYN_PORT>` (80 by default). If the
     device responds (with a ``SYN-ACK`` or a ``RST``), it's online.
   - ``--assume-online`` skips this step; ``--sweep`` stops after it. ``127.0.0.1`` is
     always considered online. Hosts that respond are marked ``_is_active`` and added to
     the datastore.

#. **Collect the identification methods** of the selected modules with ``type ==
   "unicast_ip"``.
#. **Determine the ports to check.** For each method, the port is the module's or
   protocol's configured port if the user set one (``device_options.<protocol>.port`` or
   a host's options), otherwise the method's ``default_port``. Ports are collected into a
   set of unique ``(protocol, port)`` pairs, so if five methods use port 80 it is checked
   once, not five times.
#. **Check which ports are open**, multi-threaded, one thread per host. A TCP full connect
   is used unless the method has a ``port_function``; UDP services (SNMP, CIP) use a
   protocol-specific check. Each result is stored on the device as a
   :class:`~peat.data.models.Service` with status ``open`` or ``closed``. Configured ports
   are applied for the check only and reverted afterwards, so a module's custom port never
   leaks into another module's defaults.
#. **Run the identification methods for each host**, one host at a time, in order from
   the lowest IP to the highest.

   - Only methods whose ``(protocol, port)`` is open are tried, sorted by reliability,
     highest first.
   - Each method's ``identify_function(dev)`` is called. A method that raises is logged
     and treated as a failure.
   - **Intensive scanning** (``--intensive-scan``,
     :attr:`INTENSIVE_SCAN <peat.settings.Configuration.INTENSIVE_SCAN>`) changes two
     things: all methods are tried regardless of open ports, and all are tried even after
     one succeeds, which can result in several successful verifications of one device.
   - Otherwise the process stops at the first success.
   - For each success, the service is stored (or updated) with status ``verified``, and
     the device is marked ``_is_verified`` with ``_module`` set to the module that
     identified it.

#. **Generate the scan summary**: PEAT version and run ID, duration and scan type, the
   modules used, the hosts checked (resolved and original targets), the hosts that were
   online but not verified, and the verified hosts with their data.
#. **Export the summary**: to ``summaries/scan-summary.json`` (if file output is
   enabled), to the terminal (``-E``; off by default since July 2024), and to the
   ``peat-scan-summaries`` index (``-e``).

Broadcast scanning
==================
#. **Generate the broadcast target list.** Networks, broadcast addresses, interface names,
   and files are resolved to an ordered list of unique broadcast addresses.
#. **Collect the applicable modules**: modules with ``ip_methods``, filtered by ``-d``.
#. **Collect the identification methods** with ``type == "broadcast_ip"``.
#. **Run the methods for each broadcast target**, sorted by reliability. A broadcast
   method sends the broadcast packet(s) and waits for responses itself; unlike unicast
   methods, its ``identify_function`` returns a *list* of the hosts that responded. Each is
   stored in the datastore, marked active and verified with ``_module`` set, with its
   services.
#. **Generate and export the summary** as for unicast scans, with the broadcast addresses
   as the targets. There is no "online but not verified" category, since only devices that
   understood the broadcast respond.

Only IP (layer 3) broadcasts are implemented; the ControlLogix module's :term:`CIP` List
Identity request is the current user. Layer 2 broadcasts may be added later.

Serial port scanning
====================
Only RS-232 is supported (as of 2024).

#. **Generate the serial port list** from the user's targets, sorted by name. Numbers are
   expanded to ``COMn`` on Windows and to ``/dev/ttySn`` and ``/dev/ttyUSBn`` on Linux.
#. **Collect the applicable modules**: modules with a non-empty ``serial_methods``
   attribute, filtered by ``-d``.
#. **Collect the identification methods** from ``serial_methods``.
#. **Run the methods for each port**, multi-threaded (one thread per port, up to
   ``MAX_THREADS``), methods sorted by reliability. Each method typically tries the
   configured baud rates (``--baudrates``, ``device_options.baudrates``, or the module's
   fallbacks). The state of a port is *not* checked beforehand, so many unconnected ports
   make for long scans; checking port state first is a planned improvement. Successes are
   recorded as for unicast scans.
#. **Generate and export the summary**, with the serial ports as the targets.

After the scan
==============
``pull`` and ``push`` call :func:`~peat.api.scan_api.scan` and then operate on
``datastore.verified``. Before that, :meth:`Datastore.deduplicate()
<peat.data.store.Datastore.deduplicate>` merges devices that are the same physical device
seen at several addresses (same IP, MAC, or serial port), and prunes inactive devices.
Devices identified by several modules (intensive scans) keep the module of the first
success as ``_module``.

Known gaps
==========
- Serial port state isn't checked before identification (see above).
- Merging of multi-module devices (a ControlLogix with several communication modules) is
  not fully deterministic; see :ref:`known-issues`.
- UDP port checks for protocols other than SNMP currently fall back to a TCP check of the
  same port number, which is a heuristic.
