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

Studio5000/RSLogix 5000 L5X file parsing
----------------------------------------
.. automodule:: peat.modules.rockwell.logic_l5x
   :members:
   :no-undoc-members:

Parsing
^^^^^^^
.. automodule:: peat.modules.rockwell.l5x_parse
   :members:

RSLogix 500 RSS project file parsing
------------------------------------
.. automodule:: peat.modules.rockwell.logic_rss
   :members:
   :no-undoc-members:

Output files
^^^^^^^^^^^^
These files are written to a directory for each project file,
``rss/<file name>_<first 8 characters of the file's SHA-256>/``, in the device's results
directory (``peat_results/<run>/devices/<device>/``). The streams and their inventory are
written before anything is decoded, so they're kept even if decoding fails.

.. csv-table::
   :header: File, Description

   ``streams/*.bin``, "Decoded (decompressed) payload of each ``ObjectData`` stream. Streams that couldn't be decoded are written raw, with a ``.raw`` extension."
   ``streams/*.raw``, "Other streams, e.g. ``SummaryInformation``, ``Contents`` and the VBA project streams. File names start with a number and long stream paths are shortened, so the inventory has the full path of each stream."
   ``stream-inventory.json``, "Every stream with its path, size, SHA-256, compression mode, decode status, MFC class names and output file."
   ``parsed.json``, "Everything that was decoded: metadata, every instruction (opcode, operands, compiled bytes, mnemonic and its confidence), documentation, rung comments, warnings and errors."
   ``ladder.txt``, "Ladder logic as text, with rung comments as ``;`` comment lines. Same as ``logic.parsed`` for the project file the device's data is from."
   ``ladder-onlineimage.txt``, "Ladder logic of the ``ONLINEIMAGE`` copy, if it differs from the offline project. Rung comments aren't included, since they're keyed by the rung numbers of the offline program."

Projects and backups
^^^^^^^^^^^^^^^^^^^^
The device is identified by the processor name, or ``rss_<file name>`` if the processor isn't named. A project and its backups (``PROJECT_BAK000.RSS``, ...) have the same processor name, so they're the same device. The device's logic, tags and metadata come from the project file that was saved last (by the SummaryInformation save time; if the times are unknown or equal, the file parsed last). Every project file is listed in ``extra.rslogix500.project_files`` with its SHA-256, save time, output directory and if it was used for the device's data.

To collect project files with ``peat pillage``, add the ``rss`` extension to a brand in the pillage configuration, as in the example configuration files. RSS news feeds are also collected, but they're skipped when the files are parsed.

Limits
^^^^^^
Project files are untrusted input, so the amount of data and work is limited for each file. Real project files are far below these limits.

- Each stream can be at most 64 MiB (raw or decoded), and all streams together at most 256 MiB. Streams after these limits are listed in the inventory with the status ``too_large``, and aren't extracted.
- At most 250,000 instructions and 250,000 documented addresses are decoded. Rung comments can be at most 65,536 characters.
- The searches for instructions and documentation entries give up after a fixed number of attempts at offsets that turn out to be invalid. When a limit is reached, the parse continues with what was decoded and a warning is added.

Decoded fields and confidence
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The RSS format is undocumented. The parser was developed with a small number of real project files (RSLogix 500 versions from 2000 to 2010, file format versions ``0x71`` and ``0x80``) and public reverse engineering notes. No real project files are included in PEAT; the tests use synthetic files. If you have RSS files, the optional test ``tests/modules/rockwell/test_rss_real_samples.py`` (set ``PEAT_TEST_RSS_DIR``) checks them.

- **Confirmed** on the sample files: the OLE container and ``ObjectData`` header, the three compression modes (stored, PKWARE DCL, zlib), the MFC serialization, program file headers, instruction records and rung topology, address descriptions, rung comments, the processor name, type code and driver, the RSLogix version, and the custom SummaryInformation properties.
- **Inferred**: the position of the symbol field in address descriptions (always empty in the samples), the meaning of ``ONLINEIMAGE`` (the image from the last online session), and the mnemonics of opcodes marked ``medium`` in :mod:`~peat.modules.rockwell.rss_const` (RET, CTU, AND, ADD, MUL, LIM). Unknown opcodes are written as ``OP_<hex>`` with all of their operand strings.
- **Addresses**: data table addresses, specialty I/O module files (``M0`` and ``M1``, documented as ``M00000:008.000``, which is ``M0:8.0``), and program file documentation (``PFILE:00003``) are recognized. Only data table and module file addresses become tags.
- **Not decoded** (extracted raw only): data table values (``DATA FILES``), I/O and channel configuration (including Ethernet settings), the legacy ``DATABASE`` stream of old files, VBA source code, and the compiled bytes of each instruction. The processor type code is a number, since its mapping to catalog numbers is unknown. Password fields are never decoded.

Parsing
^^^^^^^
.. automodule:: peat.modules.rockwell.rss_parse
   :members:

.. automodule:: peat.modules.rockwell.rss_const
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
