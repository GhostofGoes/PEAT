*****************
Network protocols
*****************
The TCP/IP protocols and ports PEAT uses to identify and communicate with devices, and
which modules use them. Use this table to configure firewalls and intrusion detection
exceptions (see :ref:`network-requirements`). Ports are the defaults; most can be changed
per protocol or per host in the :doc:`configuration file <configuration>`
(``device_options.<protocol>.port``).

Download this table as
:download:`tcp_ip_protocols_used_by_peat.csv <tcp_ip_protocols_used_by_peat.csv>`.

.. csv-table::
   :escape: \
   :file: tcp_ip_protocols_used_by_peat.csv
   :header-rows: 1
   :widths: 14 12 12 40 22
   :align: left

Host discovery
==============
Before any of the protocols above are used, PEAT checks whether hosts are online:

- :term:`ARP` requests for hosts on the local subnet and :term:`ICMP` echo requests for
  routed hosts, when PEAT runs with root or Administrator permissions (raw sockets)
- Otherwise, a :term:`TCP` connection attempt to port 80
  (:attr:`SYN_PORT <peat.settings.Configuration.SYN_PORT>`), which is also the fallback
  when ICMP is blocked (:attr:`ICMP_FALLBACK_TCP_SYN <peat.settings.Configuration.ICMP_FALLBACK_TCP_SYN>`)

Port checks are TCP connections (``SYN``, ``SYN-ACK``, ``RST``) to the ports of the
selected modules' identification methods. UDP services (SNMP, CIP) are checked with a
protocol-specific request. See :doc:`/design/scanning` for the details.

Serial
======
Devices connected over RS-232 (directly or with a USB-to-serial adapter) use the vendor's
serial protocol: SEL ASCII commands for SEL relays and :term:`ServLink` for the Woodward
2301E. Baud rates to try are configurable (``--baudrates``, ``device_options.baudrates``).

.. seealso::

   :doc:`/developer/general_apis`
      The protocol implementations in :mod:`peat.protocols`

   :doc:`/getting_started/supported_devices`
      Which protocols each device supports
