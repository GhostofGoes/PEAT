*******
Siemens
*******

Siemens Siprotec 7SJ6x relays
-----------------------------
.. warning::
   The PEAT Siprotec module has been tested with 7SJ61 and 7SJ64 relays. It should also work against others in the 7SJ6x family, however this has not been tested and shouldn't be relied upon.

The SIPROTEC 4 7SJ61 protection relays can be used for line protection of high and medium voltage networks with earthed (grounded), low-resistance earthed, isolated or compensated neutral point. When protecting motors, the SIPROTEC 4 7SJ61 is suitable for asynchronous machines of all sizes. The relay performs all functions of backup protection supplementary to transformer differential protection.

The relay provides control of the circuit breaker, further switching devices and automation functions. The integrated programmable logic (CFC) allows the user to implement their own functions, e.g. for the automation of switchgear (interlocking). The user is also allowed to generate user-defined messages. The flexible communication interfaces are open for modern communication architectures with control systems.

Data collection
^^^^^^^^^^^^^^^
PEAT utilizes two protocols to interrogate the Siprotec: :term:`HTTP` ("Web") and :term:`SNMP`.

HTTP
++++
Data collected via :term:`HTTP`:

- Firmware version
- "BF" number (unique hardware identifier as listed on the physical device)
- Hardware capabilities (The Machine-Readable Product Designation as listed on the physical device)
- WebMonitor version and build timestamp (stored as a software package, ``software``
  entry with ``name`` ``WebMonitor`` and ``category`` ``application``)

This data is collected by parsing two files pulled via HTTP GET requests: ``MLFB.txt`` and ``VER.txt``. ``MLFB.txt`` contains the device's firmware version, "BF" number, and Machine-Readable Product Designation ("MLFB"). The "BF" number is a sort of serial number that we believe can be used to uniquely identify a device. The MLFB contains information about the device's capabilities, such as the type of over-current protection, installed modules, and region. ``VER.txt`` contains the version of the integrated web interface on the Ethernet module, WebMonitor, as well as a timestamp of when that version of the software was compiled.

.. note::
  The German translation of "Machine-Readable Product Designation", "Maschinenlesbare Fabrikatebezeichnung", is the source of the acronym "MLFB"

SNMP
~~~~
Data collected via :term:`SNMP`:

- Firmware version of the Ethernet module
- Model number of the Ethernet module
- System uptime (``sysUpTime``, in hundredths of a second, as defined by RFC 3418), and the
  device start time computed from it
- Network statistics (such as how many incorrect SNMP authentication attempts were made, which is indicative of a network scan)
- Network mask, MAC address and interface status (all ``ifOperStatus`` values of RFC 2863)
- Ethernet, GOOSE and optical counters, link status and network redundancy (RSTP, PRP, HSR)
  from the Siemens ``SipEthernet``, ``SipGoose`` and ``SipOptical`` MIBs and the IEC 62439 MIB
- SNTP servers

This data was collected via standard "SNMP GET" requests and SNMP "walks" of the MIB files
published by Siemens.

How the SNMP data is stored in the PEAT data model:

.. list-table::
   :header-rows: 1

   * - Data
     - Field
   * - EN100 Ethernet module (IP address, MAC address, network mask, admin/operational status)
     - ``interface`` entry with ``name`` ``EN100``
   * - ``SipEthernet`` module-wide counters
     - ``statistics`` of the ``EN100`` interface (frames sent, broadcast/multicast frames
       received, CRC errors, frames lost). The other counters are kept with their MIB names
       in snake case in ``statistics.extra`` (e.g. ``n_rx_tel_int``).
   * - Link status, optical receive level and RSTP role/state of each channel, and the
       ``SipOptical`` transceiver counters
     - ``interface`` entries ``Ch1`` and ``Ch2`` (``physical``, ``connected``, ``statistics``,
       ``redundancy``)
   * - PRP/HSR (IEC 62439-3) node type and active LANs
     - ``redundancy`` of the ``EN100`` interface (``protocol``, ``mode``, ``members``) and of
       each channel (``lan`` ``A``/``B``, ``state`` ``active``/``inactive``)
   * - ``SipGoose`` matched telegrams received
     - ``statistics.ingress.messages`` of the ``goose`` service. Mismatched telegrams are in
       ``statistics.extra.mismatched_telegrams`` (they are not errors).
   * - ``snmpInBadCommunityNames``, ``snmpInBadVersions``, ``snmpInBadCommunityUses``
     - ``statistics.connections.authentication_failures`` and ``statistics.extra`` of the
       ``snmp`` service
   * - SNTP primary/secondary server and the server in use
     - ``clock.sources`` (``protocol`` ``sntp``, ``priority``, ``selected``) and
       ``clock.source``. PEAT also derives ``syncs_time_from`` relationships from them.

Identity data (``sysDescr``, ``sysName``, ``sysObjectID``), resource usage (CPU load, memory
pools) and the RSTP bridge settings are kept in ``extra.module_<sysName>``.

.. note::
  ``snmp_walk()`` keys the values of a walk by object name, so only the last row of the
  ``SipOptical`` per-channel table is available. Its ``channel`` index (``0`` or ``1`` in the
  MIB) says which channel it is: ``0`` is ``Ch1`` and ``1`` is ``Ch2``. A row with another
  index is kept in ``extra.module_<sysName>.sip_optical``.

.. note::
  The SNMP functionality currently does not work reliably on the 7SJ64, since the SNMP server and configuration varies significantly between the 7SJ61 and 7SJ64. Development was started on a 7SJ61, and due to time constraints we were not able to debug and modify the functionality to work reliably on the 7SJ64.
