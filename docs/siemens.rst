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
- WebMonitor version and build timestamp

This data is collected by parsing two files pulled via HTTP GET requests: ``MLFB.txt`` and ``VER.txt``. ``MLFB.txt`` contains the device's firmware version, "BF" number, and Machine-Readable Product Designation ("MLFB"). The "BF" number is a sort of serial number that we believe can be used to uniquely identify a device. The MLFB contains information about the device's capabilities, such as the type of over-current protection, installed modules, and region. ``VER.txt`` contains the version of the integrated web interface on the Ethernet module, WebMonitor, as well as a timestamp of when that version of the software was compiled.

.. note::
  The German translation of "Machine-Readable Product Designation", "Maschinenlesbare Fabrikatebezeichnung", is the source of the acronym "MLFB"

SNMP
~~~~
Data collected via :term:`SNMP`:

- Firmware version of the Ethernet module
- Model number of the Ethernet module
- System uptime (in milliseconds)
- Network statistics (such as how many incorrect SNMP authentication attempts were made, which is indicative of a network scan)
- Network mask
- Interface status

This data was collected via standard "SNMP GET" requests. Due to time constraints, it is only a subset of the wealth of information that can be collected via SNMP, as we discovered by performing SNMP "walks" and investigating the SNMP MIB files published by Siemens.

.. note::
  The SNMP functionality currently does not work reliably on the 7SJ64, since the SNMP server and configuration varies significantly between the 7SJ61 and 7SJ64. Development was started on a 7SJ61, and due to time constraints we were not able to debug and modify the functionality to work reliably on the 7SJ64.

.. _siemens-s7:

Siemens SIMATIC S7 PLCs
-----------------------
.. warning::
   The S7 module is new (TRL 3). The scan and pull functionality has been tested against a simulated S7comm server in the unit tests, and against the python-snap7 S7 server emulator when it's installed (python-snap7 isn't a PEAT dependency, so those tests are skipped otherwise). It hasn't been tested against physical PLCs or Siemens' own simulators yet. The parsers have been tested with the public example files listed in :ref:`siemens-s7-examples`.

The SIMATIC S7 family are Siemens' PLCs, and among the most widely deployed PLCs in the world. The current product lines are the S7-1200 (small) and S7-1500 (medium to large). The S7-300 (medium) and S7-400 (large) are being phased out by Siemens, but are still very common in the field. The S7-200 and S7-200 SMART are small PLCs with their own engineering software, and aren't supported by PEAT.

The :class:`~peat.modules.siemens.s7.S7` module supports:

- **Scan**: identify S7 PLCs over S7comm (TCP 102)
- **Pull**: read basic information from the PLC over S7comm: order number, hardware and firmware versions, serial number, PLC name, plant identifier, operating mode, and the number of each type of block loaded on the PLC
- **Parse**: STEP 7 V5.x and TIA Portal projects and project archives, TIA Portal Openness XML exports, STL and SCL sources, and symbol tables

.. code-block:: bash

   # Scan a subnet for S7 PLCs
   peat scan -d S7 -i 192.0.2.0/24

   # Pull information from a PLC
   peat pull -d S7 -i 192.0.2.10

   # Parse a STEP 7 V5.x project archive, a TIA Portal project archive, and a directory of exported files
   peat parse -d S7 -- project.zip project.zap19 ./exported_blocks/

Engineering software
^^^^^^^^^^^^^^^^^^^^
S7 PLCs are programmed with Siemens' engineering software, which runs on Windows. Which tool is used depends on the PLC model, and to a lesser extent the age of the project.

.. list-table::
   :header-rows: 1

   * - Software
     - PLCs
     - Notes
   * - STEP 7 V5.x ("SIMATIC Manager", also called "STEP 7 Classic")
     - S7-300, S7-400, ET 200 CPUs, WinAC
     - The classic engineering software, first released in the mid-1990s. Latest version is V5.7. Program editors for STL ("AWL" in German), LAD ("KOP"), and FBD ("FUP"). SCL, S7-GRAPH, and CFC are optional packages. Hardware is configured in HW Config and networks in NetPro.
   * - TIA Portal ("Totally Integrated Automation Portal") with STEP 7 Basic or Professional
     - S7-1200, S7-1500, ET 200SP CPUs, S7-1500 Software Controller, S7-PLCSIM Advanced, and (Professional only) S7-300 and S7-400
     - Introduced in 2010 (V11), with a new major version roughly every year (V19 in 2023, V20 in 2024). Projects can only be opened by the same or a newer version of TIA Portal. STEP 7 Basic only supports the S7-1200. TIA Portal also includes WinCC (HMI), Startdrive (drives), and other tools in one project.
   * - SIMATIC AX
     - S7-1500 and ET 200SP CPUs
     - A newer, text-based IDE built on VS Code, with Structured Text (ST) sources managed with Git and a package manager (``apax``). Not supported by PEAT yet.
   * - STEP 7-Micro/WIN and STEP 7-Micro/WIN SMART
     - S7-200 and S7-200 SMART
     - Separate tools for the small S7-200 PLCs, using ``.mwp`` and ``.smart`` project files. Not supported by PEAT.
   * - SIMATIC PCS 7
     - S7-400 (and S7-410)
     - The Siemens process control system (DCS), built on top of STEP 7 V5.x with CFC and SFC. Projects use the STEP 7 V5.x format.

Third-party tools also read and write S7 files, notably `DotNetSiemensPLCToolBoxLibrary <https://github.com/dotnetprojects/DotNetSiemensPLCToolBoxLibrary>`__ (reads STEP 5, STEP 7 V5.x, and TIA Portal Openness projects, and converts MC7 code back to STL), `awlsim <https://github.com/mbuesch/awlsim>`__ (a STL interpreter/simulator), and `S7-Project-Explorer <https://github.com/enlyze/S7-Project-Explorer>`__ (exports variables from ``.s7p`` projects).

File formats
^^^^^^^^^^^^
.. list-table::
   :header-rows: 1

   * - File
     - Software
     - Description
     - PEAT support
   * - ``.s7p`` and project directory
     - STEP 7 V5.x
     - A project is a directory with a ``<name>.s7p`` file (project name and GUID) and subdirectories of dBASE III/IV tables (``.dbf``, with ``.dbt`` memo files and ``.mdx`` indexes). See the layout below.
     - Parsed: S7 programs, block folders and blocks, symbol tables, and the project change log
   * - ``.zip``
     - STEP 7 V5.x
     - Project archive created with "File > Archive", a regular ZIP file of the project directory. This is how STEP 7 V5.x projects are typically shared.
     - Parsed, same as the project directory
   * - ``.s7l``
     - STEP 7 V5.x
     - Library, same structure as a project
     - Not yet
   * - ``.apNN`` (e.g. ``.ap19``) and project directory
     - TIA Portal VNN
     - A project is a directory with a small ``<name>.apNN`` XML file (project name and version), and the project data in ``System/PEData.plf``, an undocumented binary format. Other directories include ``XRef/`` (cross references), ``Vci/`` (version control), ``IM/``, ``Logs/``, and ``UserFiles/``.
     - Parsed: project metadata, and best-effort extraction of CPU names, order numbers, and IPv4 addresses from ``PEData.plf``
   * - ``.zapNN`` (e.g. ``.zap19``)
     - TIA Portal VNN
     - Project archive, a ZIP file of the project directory without some caches
     - Parsed, same as the project directory
   * - ``.alNN``, ``.zalNN``
     - TIA Portal VNN
     - Global library, and archived global library
     - Not yet
   * - ``.xml`` (SimaticML)
     - TIA Portal (Openness)
     - XML exports of blocks, PLC data types, and tag tables, created with the TIA Portal Openness API or tools and add-ins built on it. The root element is ``<Document>`` with an ``<Engineering version="VNN">`` element. LAD/FBD networks are stored as a graph of parts and wires (``FlgNet``), SCL and STL as sequences of tokens.
     - Parsed: block type, name, number, language, interface, title and comment, SCL/STL network sources, and tag tables
   * - ``.awl`` (STL), ``.scl``, ``.db``, ``.udt``
     - STEP 7 V5.x and TIA Portal
     - Plain text source files. STEP 7 V5.x stores sources in the ``S7ASRCOM/`` project directory. TIA Portal can generate sources from blocks for S7-1200/1500 (SCL, DB, and UDT).
     - Parsed: blocks with header attributes (title, author, family, name, version), know-how protection, and interface
   * - ``.asc``, ``.sdf``, ``.seq``, ``.dif``
     - STEP 7 V5.x
     - Symbol table exports. ``.asc`` is fixed-width, ``.sdf`` is CSV.
     - ``.asc`` and ``.sdf`` parsed
   * - ``.xlsx``
     - TIA Portal
     - Tag table export
     - Not yet
   * - ``.s7dcl``, ``.s7res``
     - TIA Portal V20+
     - SIMATIC SD (structured document) text format for blocks, for use with version control
     - Not yet
   * - ``.cfg``
     - STEP 7 V5.x
     - HW Config hardware configuration export
     - Not yet
   * - ``.gsd``, ``.gsdml``
     - All
     - Device description files for PROFIBUS (GSD) and PROFINET (GSDML) devices, published by device vendors
     - Not applicable
   * - ``.upd``
     - All
     - Firmware update files for CPUs and modules, installed with a memory card or online from STEP 7/TIA Portal
     - Not yet

STEP 7 V5.x project layout
++++++++++++++++++++++++++
The most important files in a STEP 7 V5.x project directory are listed below. File names are not case-sensitive, and differ in case between projects.

- ``<name>.s7p``: the project file. Starts with a length-prefixed project name and the project GUID.
- ``hrs/S7RESOFF.DBF``: the S7 programs ("resources") in the project, with their names and type (``S7 CPU``). ``hrs/linkhrs.lnk`` links each program to its block folder, using the offset in the program's ``RSRVD4_L`` field.
- ``ombstx/offline/BSTCNTOF.DBF``: the offline block folders, with the number of each type of block and their total size.
- ``ombstx/offline/<folder ID as 8 hex digits>/BAUSTEIN.DBF``: the blocks in a block folder (type and number). Block type codes: ``0x08`` OB, ``0x0A`` DB, ``0x0B`` SDB, ``0x0C`` FC, ``0x0D`` SFC, ``0x0E`` FB, ``0x0F`` SFB, ``0x00`` UDT, ``0x1B`` VAT.
- ``ombstx/offline/<folder ID>/SUBBLK.DBF``: the parts of each block ("sub-blocks"): compiled MC7 code (``MC5CODE`` memo), interface, network comments, and the block header (``BLOCKNAME``, ``BLOCKFNAME`` (family), ``USERNAME`` (author), ``VERSION``, ``BLKLANG``, ``CHECKSUM``). A ``PASSWORD`` value of 3 means the block has know-how protection.
- ``YDBs/SYMLISTS.DBF`` and ``YDBs/<ID>/SYMLIST.DBF``: the symbol tables. ``YDBs/YLNKLIST.DBF`` links each symbol table to its S7 program.
- ``siprom/CHANGELOG.DBF``: the project change log, with the Windows computer and user names that changed the project. This is valuable for forensics.
- ``hOmSave7/``: HW Config hardware configuration (stations, racks, modules, and their IP and PROFIBUS addresses). Not parsed yet.
- ``S7ASRCOM/``: STL, SCL, and GRAPH source files.

Timestamps in the tables are 6 bytes: the number of milliseconds since midnight (4 bytes, big-endian) followed by the number of days since 1984-01-01 (2 bytes, big-endian), in the local time of the engineering station. The change log uses OLE Automation dates (days since 1899-12-30, as a decimal number).

.. _siemens-s7-examples:

Public example files
^^^^^^^^^^^^^^^^^^^^
Siemens publishes many example projects on the `Siemens Industry Online Support (SIOS) <https://support.industry.siemens.com>`__ site, but they require an account and their license terms don't allow redistributing them, so they can't be included in PEAT. Open source projects on GitHub have example files under licenses that are compatible with PEAT, and these are used as test files for the parsers (in ``tests/modules/siemens/data_files/``, with a ``README.md`` listing their sources and licenses):

- `DotNetSiemensPLCToolBoxLibrary <https://github.com/dotnetprojects/DotNetSiemensPLCToolBoxLibrary>`__ (LGPL-2.1): a STEP 7 V5.x project archive (``UnitTest Simatic Project.zip``) and a TIA Portal V19 project archive (``TestProjekt.zap19``)
- `CodeGeneratorOpenness <https://github.com/mking2203/CodeGeneratorOpenness>`__ (GPL-3.0): TIA Portal V14 SP1 and V16 Openness XML exports of LAD and GRAPH blocks
- `tia-portal-openness-mcp <https://github.com/1748477582/tia-portal-openness-mcp>`__ (MIT): TIA Portal V21 Openness XML exports of a SCL FC, global DB, and tag table
- `SIEMENS_SIMATIC_STEP7_Classic_Algorithms <https://github.com/LeoSunSET/SIEMENS_SIMATIC_STEP7_Classic_Algorithms>`__ (MIT): STEP 7 V5.x STL sources
- `awlsim <https://github.com/mbuesch/awlsim>`__ (GPL-2.0-or-later): STL sources and ``.asc`` symbol tables
- `S7-PLC-Snippets <https://github.com/thomas-v2/S7-PLC-Snippets>`__ (LGPL-3.0): STEP 7 V5.x and TIA Portal SCL sources

Network protocols
^^^^^^^^^^^^^^^^^
- **S7comm** (TCP 102): the original S7 protocol, used by STEP 7 V5.x, HMIs, and PLC-to-PLC communication. It runs over ISO-on-TCP (RFC 1006): a TPKT header, then COTP (ISO 8073), then the S7 PDU. A connection starts with a COTP Connection Request with the remote TSAP set to the rack and slot of the CPU (e.g. ``0x0102`` for rack 0, slot 2), then a S7 "Setup Communication" job to negotiate the PDU size. S7comm has no authentication, except the optional CPU protection level passwords. It is supported by the S7-300/400 and, for compatibility, by the S7-1200/1500.
- **S7comm-plus** (TCP 102): the newer protocol used by TIA Portal for the S7-1200 (firmware 4.0+) and S7-1500, with integrity protection and, since TIA Portal V17 and S7-1500 firmware 2.9, TLS. It is required for engineering functions (downloads and uploads of blocks) on those PLCs, and isn't implemented by PEAT.
- **System Status Lists** (SZL, "System-Zustandsliste" in German, SSL in English documentation): read-only diagnostic data structures, read with the S7comm "userdata" function. PEAT reads SZL ``0x0011`` (module identification: order number, hardware and firmware versions), ``0x001C`` (component identification: PLC name, module name, plant ID, serial number, module type), and ``0x0424`` (operating mode). These are the same reads used by the `Nmap s7-info script <https://nmap.org/nsedoc/scripts/s7-info.html>`__. The S7-1200/1500 respond to these over S7comm, but the "PUT/GET" setting (disabled by default) is required for reading and writing data with S7comm, which PEAT doesn't do.
- Other services that may be enabled: HTTP/HTTPS web server (TCP 80/443), SNMP (UDP 161) on PROFINET interfaces, OPC UA (TCP 4840) on the S7-1500, and PROFINET DCP (Ethernet, ethertype ``0x8892``) for discovery and IP address assignment. PEAT doesn't use these for S7 PLCs yet.

The configuration options for the module (rack and slot combinations to try, connection type, and block listing) are in the ``s7`` section of the :ref:`PEAT configuration file <PEAT configuration reference>`, and the port and timeout in the ``s7comm`` section.

Virtual PLCs for development and testing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Physical S7 PLCs aren't always available for development, so several virtual or "soft" PLCs are options for developing and testing the scan and pull functions:

.. list-table::
   :header-rows: 1

   * - Option
     - License and cost
     - Fidelity
     - Notes
   * - `python-snap7 <https://github.com/gijzelaerr/python-snap7>`__ server
     - MIT, free
     - Low. Emulates a S7-300 (CPU 315-2 PN/DP) with fixed identification data. Some SZL responses aren't in the standard format, SZL ``0x0424`` (operating mode) isn't supported, and there are no blocks.
     - Pure Python since version 3.0, so it runs anywhere Python does: ``pip install python-snap7``, then ``s7 server --port 1102`` (or ``snap7.server.Server().start(tcp_port=1102)`` in Python). Used by the PEAT tests when it's installed. Good for developing the protocol handling. Scan it with ``peat scan -d S7 -i 127.0.0.1``, after setting the ``s7comm`` port to ``1102`` in the configuration file.
   * - `Snap7 <https://snap7.sourceforge.net/>`__ C server
     - LGPL-3.0, free
     - Low to medium. Emulates a S7-300 with standard-format SZL responses.
     - The original Snap7 C library includes a server that can be run with ``python-snap7`` 1.x or the Snap7 examples.
   * - `Conpot <https://github.com/mushorg/conpot>`__
     - GPL-2.0, free
     - Low. Answers S7comm identification (SZL) reads with configurable values. The default template describes a S7-200, which PEAT doesn't support, so the template needs to be changed to look like a S7-300/400/1200/1500.
     - ICS honeypot, also emulates Modbus, HTTP, SNMP, and other protocols. Useful for testing scans of a "realistic looking" device with multiple services.
   * - S7-PLCSIM (TIA Portal)
     - Included with STEP 7 Professional (trial license available)
     - High for program logic, but no real network access by default
     - Simulates S7-1200/1500 (and S7-300/400) CPUs on the engineering PC, for testing programs. Communication is through the TIA Portal "PLCSIM" interface, not a network interface. For STEP 7 V5.x, the free third-party `NetToPLCsim <https://nettoplcsim.sourceforge.net/>`__ tool exposes S7-PLCSIM V5.4/V5.5 on TCP 102.
   * - S7-PLCSIM Advanced
     - Commercial license (trial license available)
     - High. A virtual S7-1500 or ET 200SP CPU using the real firmware.
     - Communicates over a real network using the "Siemens PLCSIM Virtual Ethernet Adapter", supporting S7comm, S7comm-plus, OPC UA, and the web server. **The best option for developing and validating the scan and pull functions** before testing against physical PLCs. Runs on Windows.
   * - SIMATIC S7-1500 Software Controller (CPU 1507S, 1508S)
     - Commercial license, runs on Siemens industrial PCs
     - High. A real S7-1500 CPU running in a hypervisor next to Windows.
     - Not practical for development unless the hardware is already available.
   * - SIMATIC S7-1500V
     - Commercial license
     - High. Siemens' virtual PLC, released in 2023, which runs on servers and industrial PCs managed with SIMATIC Industrial Edge.
     - Fail-safe support was announced later. Could be an option for testing in virtualized lab environments.
   * - WinAC RTX
     - Commercial, discontinued
     - High. A S7-400 compatible software PLC for Windows.
     - Legacy. May still be found in older installations.

S7-PLCSIM Advanced or a physical S7-1200/1500 is recommended for raising the TRL of the module, and one of the Snap7 servers for automated tests and CI.

Limitations and future work
^^^^^^^^^^^^^^^^^^^^^^^^^^^
- Pull logic: upload blocks from S7-300/400 PLCs with S7comm (the "upload" functions), and convert the MC7 code to STL. Uploading blocks from S7-1200/1500 requires S7comm-plus.
- Parse the HW Config data (``hOmSave7/``) in STEP 7 V5.x projects, which has the station configuration, module order numbers, and IP addresses.
- Parse the block interfaces and MC7 code in STEP 7 V5.x projects, as DotNetSiemensPLCToolBoxLibrary does.
- Reverse engineer more of the TIA Portal ``PEData.plf`` format, or parse projects exported with TIA Portal Openness.
- Add identification methods using HTTP (web server), SNMP, and PROFINET DCP (broadcast).
- Support STEP 7 V5.x libraries (``.s7l``), TIA Portal libraries (``.alNN``), SIMATIC SD (``.s7dcl``) files, and tag table ``.xlsx`` exports.
