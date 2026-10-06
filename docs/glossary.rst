********
Glossary
********
Terms and abbreviations used in the PEAT documentation and in :term:`OT` work generally.
Terms link here from the pages that use them.

.. glossary::
   :sorted:

   ACL
      Access Control List. Common form of firewalling. Is often used in a network context to refer to firewalls in general.

   AcSELerator QuickSet
      :term:`SEL`'s engineering software (SEL-5030) for configuring relays. Stores device settings in ``.rdb`` project databases, which PEAT can parse.

   Alias
   Module alias
      An alternative name for a :term:`device module <Device module>` accepted by the ``-d`` argument and the module API, such as a vendor name (``sel``), a device class (``plc``), a short name (``clx``), or ``all``. See :ref:`selecting-modules`.

   API
      Application Programming Interface. Generic term that can refer to programming libraries (e.g. a Python package), :term:`HTTP` server endpoints, and other sorts of interfaces to a program or library.

   APX
      The project file format a Schneider Electric Modicon M340 :term:`PLC` stores and serves (``.apx``), also exported by Unity Pro / Control Expert. PEAT pulls and parses it.

   ARP
      Address Resolution Protocol. :term:`OSI Model` Layer 2 protocol used to resolve an :term:`IP` address to a :term:`MAC` address. PEAT uses ARP requests to check whether hosts on the local subnet are online.

   Artifact
      Chunk of data of interest collected by :term:`PEAT`, such as a device configuration file, firmware binary image, process logic, or log file. Commonly used in the forensics field to refer to potentially useful data extracted from collected evidence.

   ASCII
      American Standard Code for Information Interchange. Character encoding standard for electronic communication. ASCII codes represent text in computers, telecommunications equipment, and other devices.

   BAC
      Building Automation Control

   BACnet
      Building Automation Control network communications protocol

   BAS
      Building Automation System

   Baud rate
      The signaling rate of a serial link, in symbols per second (for RS-232, bits per second): 9600, 19200, 57600, and so on. Both ends must agree; PEAT tries a configurable list when scanning serial ports.

   Broadcast scan
      Discovering devices by sending a request to a subnet's broadcast address and listening for responses, instead of probing every address. Supported for :term:`CIP` devices. See :ref:`broadcast-scanning`.

   CASCII
      :term:`SEL` Compressed :term:`ASCII` protocol. :term:`SEL` proprietary protocol for communicating to devices.

   CI/CD
      Continuous Integration/Continuous Deployment, a modern software development and testing methodology. PEAT uses GitHub Actions; see :doc:`/contributing/ci`.

   CID
      Configured :term:`IED` Description. An :term:`IEC 61850` :term:`SCL` file describing a device's communication configuration, found on :term:`SEL` relays as ``SET_61850.CID`` (zlib-compressed XML).

   CIDR
      Classless Inter-Domain Routing. CIDR notation is a compact representation of an IP address and its associated routing prefix. The notation is constructed from an IP address, a slash ('/') character, and a decimal number. The trailing number is the count of leading 1 bits in the routing mask, traditionally called the network mask. (Source: `Wikipedia - Classless Inter-Domain Routing <https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#CIDR_notation>`__)

   CIP
      Common Industrial Protocol. The application protocol of :term:`EtherNet/IP`, used by Rockwell Automation / Allen-Bradley devices and others, on TCP and UDP port 44818.

   CLI
      Command Line Interface

   clx
      Shorthand referring to a Rockwell Automation/Allen-Bradley ControlLogix :term:`PLC`, and an alias for the ControlLogix module.

   Config builder
      The interactive terminal interface (``peat config-builder``) for assembling a PEAT configuration file. See :doc:`/user_guide/config_builder`.

   Container
      Containers are a form of operating system virtualization. A single container might be used to run anything from a small microservice or software process to a larger application. Inside a container are all the necessary executables, binary code, libraries, and configuration files. PEAT is distributed as a container image for :term:`Docker` and :term:`Podman`.

   Conventional Commits
      A convention for commit messages (``type(scope): subject``) that PEAT requires for commits and pull request titles. See :doc:`/contributing/index`.

   CPU
      Central Processing Unit. In a desktop computer, this is the primary processor. In a modular :term:`PLC`, this is usually the controller module in the rack, which other modules (communication, I/O) attach to.

   CSV
      Comma Separated Values. Commonly used table-structured data format.

   Datastore
      PEAT's registry of :term:`device data <Device data>` objects for a run (:data:`peat.datastore`). Devices are looked up by identifier, and duplicates are merged before export.

   db
      Database, used generally (though often referring to :term:`Elasticsearch`)

   DCS
      Distributed Control System

   Device data
      Everything PEAT knows about one device, held in a :class:`~peat.data.models.DeviceData` object and written out as ``device-data-full.json`` and ``device-data-summary.json``. The structure is PEAT's :doc:`data model </developer/data_model>`.

   Device ID
      The identifier PEAT uses for a device's output directory and documents: usually its :term:`IP` address, otherwise a serial port, a name parsed from a file, or the source file name.

   Device module
   PEAT module
      A Python class, subclassing :class:`~peat.device.DeviceModule`, that implements PEAT's support for a kind of device: how to identify it, pull from it, parse its files, and push to it. Modules can be built in or imported at runtime. See :doc:`/developer/module_developer_guide`.

   Devcontainer
      A development environment defined in ``.devcontainer/`` and run in a container by VS Code, giving every contributor the same tools. See :doc:`/contributing/development_environment`.

   DGA
      Dissolved Gas Analyzer. A transformer monitoring device; the Camlin Totus is one.

   dict
      :term:`Python` dictionary

   dir
      Filesystem directory

   DNP3
      Distributed Network Protocol 3.0. :term:`SCADA` communication protocol commonly seen in the electric power industry in the U.S.

   DNS
      Domain Name System

   DPI
      Deep Packet Inspection

   Docker
      Docker is a system for building and running containers. Docker is a set of platform as a service products that use OS-level virtualization to deliver software in packages called containers. Containers are isolated from one another and bundle their own software, libraries and configuration files. Similar to :term:`Podman`. Further reading: `Docker documentation <https://docs.docker.com/>`__

   Dry run
      Running a PEAT command with ``--dry-run``: configuration, modules, and targets are processed and logged, but no packets are sent and no device is touched. See :doc:`/user_guide/cli`.

   ECS
      Elastic Common Schema. ECS defines a common set of fields to be used when storing event data in :term:`Elasticsearch`. PEAT's :doc:`database schema </reference/database_schema>` follows it. Refer to the `ECS documentation <https://www.elastic.co/docs/reference/ecs>`__ for further details.

   ES
      Elasticsearch

   Elasticsearch
      NoSQL schemaless database that stores data in a :term:`JSON`-like structure. Used for integration of PEAT with other tools; see :doc:`/user_guide/elasticsearch`.

   elastic
      Refers to an :term:`Elasticsearch` database

   Engineering workstation
   EWS
      The computer (usually Windows) with the vendor engineering software used to program and configure the control devices on a network. Holds project files that PEAT can find with :term:`pillage <Pillage>` and parse.

   ethip
   EtherNet/IP
      EtherNet/IP industrial communications protocol, which carries :term:`CIP` over Ethernet (not to be confused with Ethernet and TCP/IP).

   FCD
      Field Control Device

   FD
      Field Device. :term:`SCEPTRE` terminology for :term:`OT` devices.

   FID
      Firmware Identification string of an :term:`SEL` device, such as ``SEL-351S-6-R516-V2-Z004004-D20190111``, which encodes the model, release, point release, settings version, and release date. See :ref:`sel-firmware-ids`.

   File signature
      A description of a file type by its contents (magic bytes, XML tags, substrings, or a custom check) that a :term:`device module <Device module>` uses to recognize files it can parse, regardless of file name. See :ref:`file-signatures`.

   Fingerprinting
   Identification
   Verification
      Determining what a device is (vendor, model, type) by probing it with a module's identification methods. A device that has been identified is *verified*. See :doc:`/design/scanning`.

   Firmware
      The software embedded in a device that implements its functionality. PEAT records firmware versions and identifiers, and for some devices can pull or push the firmware image itself.

   FQDN
      Fully Qualified Domain Name

   FTP
      File Transfer Protocol. Plain-text file transfer protocol still common on :term:`OT` devices (:term:`SEL` relays, :term:`PLCs <PLC>`); PEAT uses it to download and upload files.

   Furo
      The Sphinx theme used by the PEAT documentation. See :doc:`/contributing/documentation`.

   GE
      General Electric

   GOOSE
      Generic Object Oriented Substation Event. An :term:`IEC 61850` protocol for fast peer-to-peer messaging between substation devices.

   GUI
      Graphical User Interface

   GUID
      Globally Unique Identifier

   Golden Image
      General term for a known-good ("golden") device configuration or firmware image. Derives from the :term:`IT` term for a :term:`VM` base-image that is used to create many instances of the same virtual machine.

   HEAT
      High-fidelity Extraction of Artifacts from Traffic. Name of the PEAT capability for extracting and parsing artifacts from network captures (e.g. PCAP file). Refer to :doc:`/user_guide/heat` for more details.

   HMI
      Human-Machine Interface. The operator's screen for a process, often a Windows or Windows CE panel.

   HTML
      Hyper-Text Markup Language. Format used to render data in a browser.

   HTTP
      Hyper-Text Transfer Protocol. Plaintext protocol commonly used for transferring web information or making requests to a :term:`REST` :term:`API`. Many :term:`OT` devices have web interfaces PEAT scrapes.

   HTTPS
      :term:`HTTP` over :term:`TLS`.

   ICMP
      Internet Control Message Protocol. :term:`OSI Model` Layer 3 protocol commonly used to determine if a host is alive and responding ("ping").

   ICS
      Industrial Control System(s)

   IDS
      Intrusion Detection System. In the context of PEAT this usually refers to a network-based IDS, which PEAT's scans tend to alert.

   IEC 61850
      International standard for communication in substation automation, including the :term:`SCL` configuration language, :term:`GOOSE`, and MMS.

   IED
      Intelligent Electronic Device. Generic term for microprocessor-based substation devices such as protection relays.

   INI
      File format, often used for software configurations

   Intensive scan
      A scan mode (``--intensive-scan``) that runs every identification method against every target regardless of open ports and doesn't stop at the first success. Thorough, slow, and hard on devices. See :doc:`/user_guide/scan`.

   ION
      The Schneider PowerLogic ION family of smart power meters, and their proprietary protocol on port 7700.

   I/O
      Input/Output. The physical signals a device reads (inputs) and drives (outputs).

   IP
      Internet Protocol. The network address of a device, e.g. "IP address". In PEAT, references to "IP" without a version can be assumed to refer to version 4 of the protocol, IPv4. References to version 6 will be explicitly called out, e.g. "IPv6". Example IPv4 address: ``192.168.0.1``

   IT
      Information Technology. In the context of PEAT, this refers to systems and technologies that are not :term:`OT`-specific, such as Windows, anti-malware, firewalls, etc.

   JSON
      JavaScript Object Notation. Commonly used standard for structuring and formatting data. PEAT's results are JSON.

   JSON Lines
   JSONL
      A text format with one JSON object per line (``.jsonl``), used by PEAT for its JSON log and for the per-type ``device-data-*.jsonl`` files.

   Kibana
      The web interface for :term:`Elasticsearch`, used for searching PEAT data and building dashboards. OpenSearch Dashboards is its counterpart for :term:`OpenSearch`.

   L5X
      The XML export format of Rockwell Studio 5000 / RSLogix 5000 projects (``.L5X``), which PEAT parses.

   Ladder logic
      A graphical PLC programming language resembling relay wiring diagrams; one of the IEC 61131-3 languages. PEAT decompiles ControlLogix ladder logic to text.

   "layer <x>"
      Layer in the :term:`OSI Model` commonly used by network engineers (ex: "Layer 3" is the "network" or IP layer).

   LDRD
      Laboratory-Directed Research and Development

   Loguru
      The Python logging library PEAT uses. See :doc:`/contributing/logging`.

   MAC
      Media Access Control. :term:`OSI Model` Layer 2 communication between devices on the same local network (e.g. the same switch). Example MAC address: ``01:02:03:FA:FB:FC``. The first three bytes (the :term:`OUI`) identify the manufacturer.

   Malcolm
      An open-source network traffic analysis suite from CISA and Idaho National Laboratory, built on :term:`OpenSearch`, widely used on :term:`OT` networks. PEAT can export directly to it. See :doc:`/user_guide/opensearch`.

   MBAP
      Modbus Application. Often seen in Nmap or Wireshark as "mbap" or sometimes as "mbam".

   MIB
      Management Information Base. :term:`SNMP` flat-file, nonrelational database that describes devices being monitored.

   Modbus
      A simple, ubiquitous industrial protocol for reading and writing registers and coils, over serial (Modbus RTU) or TCP port 502 (Modbus/TCP). Schneider's :term:`UMAS` rides on top of it.

   MR
      Merge Request, used when talking about GitLab

   MTU
      Maximum Transfer Unit

   NIC
      Network Interface Card. Often used to refer generally to network interfaces on a host, both physical and virtual.

   NTP
      Network Time Protocol

   Nmap
      The Network Mapper. Open-source tool for active mapping of IP networks. PEAT's scan is a gentler, :term:`OT`-specific analogue. Further reading: `Nmap website <https://nmap.org/>`__

   Online
      A host that responded to PEAT's online check (:term:`ARP`, :term:`ICMP`, or a TCP connection) but was not necessarily identified. Compare :term:`verified <Verification>`.

   OpenPLC
      Open-source software ("soft") :term:`PLC`. PEAT supports OpenPLC Runtime v4 through its REST API; see :doc:`/reference/devices/openplc`.

   OpenSearch
      An open-source search and analytics database forked from :term:`Elasticsearch`, used by :term:`Malcolm`. PEAT exports to it transparently; see :doc:`/user_guide/opensearch`.

   OS
      Operating System. Examples are Windows, Linux, and MacOS; on devices, VxWorks, ThreadX, or Linux.

   OSI
      Open Systems Interconnection. Generally used to reference the :term:`OSI Model`.

   OSI Model
      Open Systems Interconnection Model. The Open Systems Interconnection model is a conceptual model that characterises and standardises the communication functions of a telecommunication or computing system without regard to its underlying internal structure and technology.

   OT
      Operational Technology. Umbrella term for technology that run critical operations, including :term:`ICS`/:term:`SCADA` and Building Automation Systems.

   OUI
      Organizationally Unique Identifier. 24-bit number that uniquely identifies a vendor, manufacturer, or other organization; the first half of a :term:`MAC` address. PEAT resolves OUIs to vendor names with the Wireshark ``manuf`` database.

   out_dir
      Output directory. ``./peat_results/`` by default; see :doc:`/user_guide/output`.

   Parse
      PEAT's offline operation: extracting information from device files and project files without touching a device. See :doc:`/user_guide/parse`.

   PCAP
      Packet Capture. Used interchangeably as a general term for capturing network traffic or to refer to the ``.pcap`` file format used by ``tcpdump``, ``libpcap``, and many other tools.

   PCCC
      Programmable Controller Communication Command. In the context of PEAT, this is usually referring to the Rockwell PCCC protocol.

   PDM
      The Python project and dependency manager PEAT uses for its environment, lock files, and task scripts (``pdm run ...``). See :doc:`/contributing/development_environment`.

   PEAT
      Process Extraction and Analysis Tool. PEAT is a multifunction utility and library for interrogating and mapping :term:`ICS` and :term:`OT` devices, including network discovery, acquiring and parsing artifacts (firmware, logic, etc.), uploading artifacts, and sending commands.

   pickle
      Python's Pickle protocol, which serializes arbitrary :term:`Python` objects into a stream of bytes. Further reading: :mod:`pickle`

   Pillage
   Pillager
      :term:`PEAT` capability (``peat pillage``) to collect artifacts (e.g. device configs or project files) from engineering workstation disk images or live machines. Refer to :doc:`/user_guide/pillage` for details.

   PLC
      Programmable Logic Controller. An industrial computer that runs control logic against physical I/O.

   PLCOpen
      An industry association behind the IEC 61131-3 programming standards and the :term:`TC6` XML exchange format; also the name of the open-source graphical logic editor PEAT's TC6 parsing code originates from.

   Podman
      Red Hat's container solution. Similar to :term:`Docker`. Further reading: `Podman documentation <https://docs.podman.io/en/latest/>`__

   Port
      Commonly used to refer to network ports. It is an integer used by :term:`TCP` and :term:`UDP` to address applications on a host over a :term:`IP` network.

   PR
      Pull Request, used when talking about GitHub

   Project file
      A file saved by vendor engineering software containing a device's program and configuration (SEL ``.rdb``, Rockwell ``.L5X``/``.ACD``, Schneider ``.apx``/``.stu``, Woodward ``.wset``). Often richer than what can be pulled from the device; PEAT parses several formats.

   Pull
      PEAT's active collection operation: logging into identified devices and retrieving configuration, logic, firmware, logs, and other :term:`artifacts <Artifact>`. See :doc:`/user_guide/pull`.

   Push
      PEAT's upload operation: sending configuration or firmware to a device, typically for recovery. Also known as :term:`REPEAT`. See :doc:`/user_guide/push`.

   Pydantic
      The data validation library PEAT's data model is built on (version 1.x).

   PyInstaller
      The tool that bundles PEAT and its Python runtime into single-file executables. See :doc:`/contributing/building`.

   Python
      The Python programming language. This is the language :term:`PEAT` is implemented in.

   py
      Shorthand for "Python", e.g. "py3" for "Python 3", "py312" for "Python 3.12"

   RAM
      Random-access Memory

   RDB
      The ``.rdb`` project database format of :term:`SEL`'s :term:`AcSELerator QuickSet` (an OLE compound file), which PEAT parses.

   REPEAT
      Term used to refer to the device recovery (aka "push") capabilities of :term:`PEAT`. May also be written as "rePEAT".

   REPL
      Read Eval Print Loop. Often used to refer to the :term:`Python` command line interpreter interface. Further reading: `Wikipedia - Read-eval-print loop <https://en.wikipedia.org/wiki/Read%E2%80%93eval%E2%80%93print_loop>`__ and the `Python interpreter documentation <https://docs.python.org/3/tutorial/interpreter.html>`__

   REST
      Representational State Transfer. Type of :term:`HTTP` :term:`API` architecture that is stateless and well-defined.

   RHEL
      Red Hat Enterprise Linux. Enterprise-focused distribution of Linux developed by Red Hat, Inc. Widely used in Government and industry and the de facto distribution for critical servers or core infrastructure. Well-known for its long term support and robust security.

   RS-232
      The common serial communication standard (EIA-232) used by many :term:`OT` devices for engineering access; the only serial physical layer PEAT currently supports.

   RTAC
      Real-Time Automation Controller. :term:`SEL`'s substation controller and protocol gateway family (SEL-3530, 3350, 3555).

   RTU
      Remote Terminal Unit. A device that collects I/O and communicates with a :term:`SCADA` master, common in utilities.

   Run
   Run directory
      One invocation of a PEAT command, identified by a run ID and recorded in a run directory under the output directory with the results, summaries, logs, and configuration. See :doc:`/user_guide/output`.

   Scan
      PEAT's discovery operation: finding devices on a network or serial ports and identifying them, without pulling data. See :doc:`/user_guide/scan`.

   SCADA
      Supervisory Control and Data Acquisition

   SCEPTRE
      SCEPTRE is a comprehensive :term:`OT` modeling and simulation platform developed by :term:`SNL`, which includes virtual field devices PEAT supports. Further reading: `phenix documentation <https://phenix.sceptre.dev/>`__

   SCL
      Substation Configuration Language, the :term:`IEC 61850` XML schema for describing devices and substations (``.ICD``, ``.CID``, ``.SCD``, ``.SSD`` files).

   SEL
      Schweitzer Engineering Laboratories, a manufacturer of protection relays, :term:`RTACs <RTAC>`, and other power system devices. See :doc:`/reference/devices/sel`.

   SER
      Sequential Event Recorder. The event log of an :term:`SEL` relay.

   ServLink
      Woodward's proprietary protocol for communicating with its controllers (easYgen, 2301E, MicroNet) over serial or TCP (port 666 or 667).

   SIS
      Safety Instrumented System

   SIEM
      Security Information and Event Management. A cybersecurity solution that enables real-time visibility, detection, and threat hunting by aggregating log and event data from across :term:`IT` infrastructure. Examples of SIEMs include Splunk Enterprise Security and Elastic Security.

   SLC
      Small, chassis-based, modular programmable controller by Rockwell Automation and part of the Allen-Bradley product line.

   Sneakypeat
      A lightweight, standalone scanner built from the PEAT repository (``distribution/sneakypeat.py``) for red team exercises where a small footprint matters.

   SNL
      Sandia National Laboratories

   SNMP
      Simple Network Management Protocol. UDP port 161; PEAT reads device information from it where supported.

   SNTP
      Simple Network Time Protocol

   SOE
      Sequence of Events log. Refers to the system log from SEL RTAC devices aka ``soe.csv``.

   Sphinx
      The documentation generator that builds these pages from reStructuredText. See :doc:`/contributing/documentation`.

   SSH
      Secure Shell protocol

   SFTP
      SSH File Transfer Protocol. Basically :term:`FTP` over a SSH connection.

   StaticX
      A tool that bundles system shared libraries into a :term:`PyInstaller` executable, making the Linux ``peat`` executable portable across distributions. See :doc:`/contributing/building`.

   str
      :term:`Python` string

   Structured Text
      A textual IEC 61131-3 PLC programming language resembling Pascal. PEAT extracts Modicon logic as Structured Text.

   Summary
      The :term:`JSON` result of a scan, pull, or parse: metadata about the operation plus the device data. See :doc:`/reference/summaries`.

   TC6
      TC6 XML. :term:`XML`-based standard from :term:`PLCOpen` for storing graphical representations of process logic in a portable and implementation-independent manner. PEAT converts TC6 to :term:`Structured Text`.

   TCP
      Transmission Control Protocol

   TLS
      Transport Layer Security. The encryption layer under :term:`HTTPS`.

   Towncrier
      The tool that assembles PEAT's changelog from per-change news fragments. See :doc:`/contributing/releases`.

   TRL
      Technology Readiness Level. A 1 to 9 scale of maturity (1: basic principles, 9: proven in operation). PEAT uses it to estimate how mature each :term:`device module <Device module>` is; see :doc:`/getting_started/supported_devices`.

   TXT
      Text file or text data (e.g. ".txt")

   UDP
      User Datagram Protocol

   UEFI
      Unified Extensible Firmware Interface, the firmware of modern PCs and some embedded systems. PEAT parses the output of a UEFI SPI flash extraction.

   UMAS
      UMAS is a Schneider Electric proprietary protocol that rides on top of Modbus/TCP. It uses the reserved proprietary Modbus/TCP function code 90 (0x5A), and is sometimes referred to as "Function Code 90" or "Func90". Used to transfer project files to and from Modicon :term:`PLCs <PLC>`.

   Unicast scan
      The normal scan: probing each target address individually. Compare :term:`broadcast scan <Broadcast scan>`.

   USB
      Universal Serial Bus

   UTC
      Coordinated Universal Time. All PEAT timestamps are in UTC.

   UUID
      Universally Unique Identifier

   VFD
      Variable Frequency Drive

   VM
      Virtual Machine

   VPN
      Virtual Private Network

   VxWorks
      Wind River's real-time operating system, found on many :term:`PLCs <PLC>` and :term:`RTUs <RTU>` (ControlLogix, M340, Sage, Woodward).

   WCAG
      Web Content Accessibility Guidelines, the W3C standard the documentation aims to meet (2.1 AA). See :doc:`/contributing/documentation`.

   Wireshark
      Open-source network traffic analysis tool. Further reading: `Wireshark website <https://www.wireshark.org/>`__, `Wireshark User Guide <https://www.wireshark.org/docs/wsug_html_chunked/>`__, `Wireshark Wiki <https://gitlab.com/wireshark/wireshark/-/wikis/home>`__

   WSL
      Windows Subsystem for Linux. Also known as Bash for Windows. Further reading: `About WSL <https://learn.microsoft.com/en-us/windows/wsl/about>`__ and `WSL installation guide <https://learn.microsoft.com/en-us/windows/wsl/install>`__

   XML
      Extensible Markup Language. Commonly used hierarchical data format, similar to HTML.

   YAML
      YAML Ain't Markup Language. Format commonly used for software configuration files (".yml" or ".yaml"), including PEAT's. Further reading: `YAML 1.2 specification <https://yaml.org/spec/1.2.2/>`__

   YMODEM
      A serial file transfer protocol. Needed to download files from some :term:`SEL` relays over serial; PEAT uses the ``rz``/``sz`` tools from ``lrzsz`` for it (Linux and macOS).

   yml
      File extension commonly used for :term:`YAML` files

   Zeek
      An open-source network security monitor (formerly Bro) that parses traffic into logs and can extract transferred files. :term:`HEAT`'s FTP extractor uses it.
