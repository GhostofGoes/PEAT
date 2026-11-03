*****************************
Device module implementations
*****************************
Code documentation for the :class:`~peat.device.DeviceModule` implementations included with PEAT.

.. note::
   The source code for documented classes and functions is available by clicking the ``source`` to the right of the documentation for the class or function.

Class diagram
=============
.. automod-diagram:: peat.modules

Rockwell Automation
===================

Allen-Bradley ControlLogix PLC
------------------------------
.. automodule:: peat.modules.rockwell.controllogix
   :members:
   :no-undoc-members:

Rockwell Scanning
^^^^^^^^^^^^^^^^^
.. automodule:: peat.modules.rockwell.ab_scan
   :members:

Rockwell Communications
^^^^^^^^^^^^^^^^^^^^^^^
.. automodule:: peat.modules.rockwell.clx_cip
   :members:

.. automodule:: peat.modules.rockwell.clx_http
   :members:

Rockwell Parsing
^^^^^^^^^^^^^^^^
.. automodule:: peat.modules.rockwell.ab_parse
   :members:

.. automodule:: peat.modules.rockwell.clx_relay_ladder_parser
   :members:

.. automodule:: peat.modules.rockwell.clx_string_logic_parser
   :members:

.. automodule:: peat.modules.rockwell.clx_identity
   :members:

Rockwell known defaults
^^^^^^^^^^^^^^^^^^^^^^^
.. automodule:: peat.modules.rockwell.clx_defaults
   :members:

Studio5000/RSLogix 5000 L5X file parsing
----------------------------------------
.. automodule:: peat.modules.rockwell.logic_l5x
   :members:
   :no-undoc-members:

Parsing
^^^^^^^
.. automodule:: peat.modules.rockwell.l5x_parse
   :members:

Camlin
======

Totus DGA
---------
.. automodule:: peat.modules.camlin.totus
   :members:
   :no-undoc-members:

Totus HTTP
^^^^^^^^^^
.. automodule:: peat.modules.camlin.totus_http
   :members:

Fortinet
========

Fortigate Firewall
------------------
.. automodule:: peat.modules.fortinet.fortigate
   :members:
   :no-undoc-members:

General Electric
================

GE D25 RTU
----------
.. automodule:: peat.modules.ge.ge_rtu
   :members:
   :no-undoc-members:

GE Relays
---------
.. automodule:: peat.modules.ge.ge_relay
   :members:
   :no-undoc-members:

IEC 61850 (vendor-neutral)
==========================

IEC 61850 SCL files
-------------------
The :class:`~peat.modules.iec61850.iec61850_scl.IEC61850SCL` module parses
IEC 61850-6 System Configuration description Language (SCL) files exported by
substation engineering tools: ``SCD``, ``ICD``, ``IID``, ``CID`` (plain XML),
``SED`` and ``SSD``. It produces one device per IED in the file (each with its
own ``parse_results`` entry in the :ref:`parse-summary`), with:

- :attr:`~peat.data.models.DeviceData.iec61850`: SCL header and change history,
  IED identity (``manufacturer``, ``type``, ``configVersion``), access points
  (IP addresses, MMS port, authentication, PRP/HSR redundancy, physical ports),
  logical devices and nodes, GOOSE/SV/report control blocks with their MAC
  address, APPID and VLAN, and subscriptions (``ExtRef`` inputs)
- network interfaces (``application`` ``iec61850``), services (``mms`` server,
  ``goose``/``sv`` publisher, with their security settings) and relationships
  (``publishes_to``, ``subscribes_to``, ``reports_to``). The ``reference`` of a
  relationship (e.g. ``PROT1PRO/LLN0$GO$gcbTrip``) is the same on the publisher
  and on each subscriber, which joins both ends across devices
- ``scl-validation`` alert events for duplicate or out-of-range GOOSE/SV APPIDs
  (within an IED and across the IEDs of one file on the same VLAN) and for
  invalid address values

Notes:

- ``APPID`` and ``VLAN-ID`` are hexadecimal in SCL (``064`` is VLAN 100).
- Files are not validated against the IEC XSD schemas, which are not
  distributed with PEAT. Elements are matched by name, with or without the
  SCL namespace.
- Every address value is validated on its own. An invalid value (e.g. a
  ``VLAN-ID`` above 4095 or a malformed MAC address) is left unset, recorded in
  ``iec61850.extra.invalid_addresses`` and reported as an alert. The rest of
  the file is still parsed.
- IPv6 addresses, data type templates, ``DOI``/``DAI`` values and ``Private``
  elements are not modeled. An ``SSD`` without IEDs produces no device.
- An IED reuses the device of the same IED from the same file (the file is
  parsed again), else an existing device with the same IED name, else one with
  the same IP address. A device found by name or IP is only reused if it has no
  IED name yet or the same IED name, no other IP address and no other
  manufacturer: the IEDs of two substations with the same IED names stay
  separate devices. The IEDs of one file never share a device. ``TEMPLATE``
  (the IED name in every ``ICD`` file) only matches a device parsed from the
  same file.
- A new device is named after its IED. A ``TEMPLATE`` IED, or an IED without an
  IP address of its own whose name another device already has, is named
  ``<IED name>@<file name without extension>`` (e.g. ``TEMPLATE@relay`` for
  ``relay.icd``, with ``-2``, ``-3``, ... appended if needed), so every device
  has its own ID and output directory. ``iec61850.ied_name`` is always the IED
  name from the file.
- The device ``ip`` is the first access point IP, unless it is ``0.0.0.0``, the
  IED is a ``TEMPLATE`` (default address), or another device already has it
  (several IEDs with one IP). Such addresses stay in ``iec61850.access_points``
  (and in the interfaces, except ``0.0.0.0``), and these devices are not merged
  by de-duplication.
- zlib-compressed SEL ``SET_61850.CID`` files are handled by
  :class:`~peat.modules.sel.sel_relay.SELRelay`, which uses the same SCL parser.

.. automodule:: peat.modules.iec61850.iec61850_scl
   :members:
   :no-undoc-members:

SCL parsing
^^^^^^^^^^^
.. automodule:: peat.parsing.scl
   :members:

iDirect
=======

iDirect Modem
-------------
.. automodule:: peat.modules.idirect.idirect
   :members:
   :no-undoc-members:

OpenPLC
=======

OpenPLC Runtime v4
------------------
.. automodule:: peat.modules.openplc.openplcv4
   :members:
   :no-undoc-members:

Sandia
======

SCEPTRE Field Device
--------------------
.. automodule:: peat.modules.sandia.sceptre_fcd
   :members:
   :no-undoc-members:

Schneider Electric
==================

Modicon M340 PLC
----------------
.. automodule:: peat.modules.schneider.m340.m340
   :members:
   :no-undoc-members:

M340 parsing
^^^^^^^^^^^^
.. automodule:: peat.modules.schneider.m340.m340_parse
   :members:

M340 pulling
^^^^^^^^^^^^
.. automodule:: peat.modules.schneider.m340.m340_pull
   :members:

UMAS protocol
^^^^^^^^^^^^^
.. automodule:: peat.modules.schneider.m340.umas_packets
   :members:

.. automodule:: peat.modules.schneider.m340.umas_codes
   :members:

M340 known defaults
^^^^^^^^^^^^^^^^^^^
.. automodule:: peat.modules.schneider.m340.m340_defaults
   :members:

.. ION power meter
.. ---------------
.. .. automodule:: peat.modules.schneider.ion.ion
..    :members:
..    :no-undoc-members:

.. ION HTTP
.. ^^^^^^^^
.. .. automodule:: peat.modules.schneider.ion.ion_http
..    :members:

.. ION Telnet
.. ^^^^^^^^^^
.. .. automodule:: peat.modules.schneider.ion.ion_telnet
..    :members:

.. ION parsing
.. ^^^^^^^^^^^
.. .. automodule:: peat.modules.schneider.ion.ion_parse
..    :members:

Sage RTU
--------
.. automodule:: peat.modules.schneider.sage.sage
   :members:
   :no-undoc-members:

Sage parsing
^^^^^^^^^^^^
.. automodule:: peat.modules.schneider.sage.sage_parse
   :members:

Sage Telnet
^^^^^^^^^^^
.. automodule:: peat.modules.schneider.sage.sage_telnet
   :members:

Sage SSH
^^^^^^^^^^^^
.. automodule:: peat.modules.schneider.sage.sage_ssh
   :members:

Sage commands
^^^^^^^^^^^^^
.. automodule:: peat.modules.schneider.sage.sage_commands
   :members:

Sage known defaults
^^^^^^^^^^^^^^^^^^^
.. automodule:: peat.modules.schneider.sage.sage_defaults
   :members:

Schweitzer Engineering Laboratories (SEL)
=========================================

SEL Relays
----------
.. automodule:: peat.modules.sel.sel_relay
   :members:
   :no-undoc-members:

SEL RTAC
--------
.. automodule:: peat.modules.sel.sel_rtac
   :members:
   :no-undoc-members:

SEL 3620 Gateway
----------------
.. automodule:: peat.modules.sel.sel_3620
   :members:
   :no-undoc-members:

Internal APIs
-------------

SELHTTP
^^^^^^^
.. automodule:: peat.modules.sel.sel_http
   :members:

SELTelnet
^^^^^^^^^
.. automodule:: peat.modules.sel.sel_telnet
   :members:

SELSerial
^^^^^^^^^
.. automodule:: peat.modules.sel.sel_serial
   :members:

SELASCII
^^^^^^^^^
.. automodule:: peat.modules.sel.sel_ascii
   :members:

General comms functions
^^^^^^^^^^^^^^^^^^^^^^^
.. automodule:: peat.modules.sel.sel_comms
   :members:

Relay Parsing
^^^^^^^^^^^^^
.. automodule:: peat.modules.sel.relay_parse
   :members:

RTAC Parsing
^^^^^^^^^^^^
.. automodule:: peat.modules.sel.rtac_parse
   :members:

SEL known defaults
^^^^^^^^^^^^^^^^^^
.. automodule:: peat.modules.sel.sel_defaults
   :members:

Siemens
=======

SIPROTEC 7SJ6x relays
---------------------
.. automodule:: peat.modules.siemens.siprotec
   :members:
   :no-undoc-members:

Woodward
========

MicroNet Plus
-------------
.. automodule:: peat.modules.woodward.micronet
   :members:
   :no-undoc-members:

2301E Generator Controller
--------------------------
.. automodule:: peat.modules.woodward.wdw_2301e
   :members:
   :no-undoc-members:

easYgen 3500XT Genset Controller
--------------------------------
.. automodule:: peat.modules.woodward.easygen_3500xt
   :members:
   :no-undoc-members:

Windows
=======

WindowsCE
---------
.. automodule:: peat.modules.windows.wince
   :members:
   :no-undoc-members:

Internal APIs
-------------

ServLink protocol
^^^^^^^^^^^^^^^^^
.. automodule:: peat.modules.woodward.wdw_svl
   :members:

MicroNet parsing
^^^^^^^^^^^^^^^^
.. automodule:: peat.modules.woodward.parse_micronet
   :members:
