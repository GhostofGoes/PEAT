*****************
Example artifacts
*****************
Where to find example files to try PEAT's parsers on, test changes against, and learn
what each device's artifacts look like. Real device artifacts are hard to come by in
public: vendor project files are proprietary formats, and configurations from production
systems are sensitive. This page lists what is in the repository, what is publicly
available elsewhere, and what we're still looking for.

.. note::
   Contributions of sanitized, synthetic, or lab-generated example files are very
   welcome, especially for the devices marked *wanted* below. Files must be free of real
   credentials, addresses, and site information, and binary or large files are only
   accepted from trusted contributors with verified provenance (see
   :doc:`/contributing/testing`). Open an issue or a pull request.

In the repository
=================
.. list-table::
   :header-rows: 1
   :widths: 26 34 40

   * - Device / module
     - Files
     - Where
   * - SCEPTRE virtual field devices
     - Modbus, DNP3, BACnet, IEC 60870-5-104, SunSpec, and serial device XML
       configurations from `sceptre-bennu <https://github.com/sandialabs/sceptre-bennu/tree/main/data/configs>`__
       and the ``soap`` topology in `sceptre-phenix-topologies <https://github.com/sandialabs/sceptre-phenix-topologies>`__
       (GPLv3, like PEAT)
     - ``examples/devices/sceptre/{bp,ep,soap}/``; used by ``tests/modules/sandia/``
   * - OpenPLC Runtime v4
     - A compiled program archive (``Relay_Blink_PLC.zip``) for pushing; example scan and
       pull summaries
     - ``tests/modules/openplc/data_files/``, ``examples/example-openplc-*-summary.json``
   * - Example module (AwesomeTool)
     - Input JSON, expected device data, and a device web page for the scan example
     - ``examples/example_peat_module/``
   * - Rockwell ControlLogix
     - Disassembled logic samples (ladder, structured text, function block, sequential
       function chart) used by the parser tests
     - ``tests/modules/rockwell/data_files/``
   * - Certificates (SEL-3530, SEL-2730M, Sage)
     - X.509 certificates and their expected parsed form
     - ``tests/protocols/data_files/``
   * - Linux command output
     - ``/proc`` files, ``sshd_config``, ``arp -a``, and similar, with expected output
     - ``tests/parsing/data_files/``
   * - Summaries and configurations
     - Example scan, pull, and parse summaries; all example configuration files
     - ``examples/``

Public sources by device
========================
These are external resources we're aware of. Links were checked when this page was
written; formats change and sites move, so treat them as starting points. Nothing here is
endorsed by or affiliated with PEAT.

Rockwell Automation (ControlLogix, L5X)
---------------------------------------
- **L5X exports** are plentiful on GitHub, since L5X is XML and commonly version
  controlled. Examples: `LogixLibraries <https://github.com/JeremyMedders/LogixLibraries>`__
  (add-on instructions, UDTs, and sample programs),
  `RSLogix_AOI_Examples <https://github.com/harryse7en/RSLogix_AOI_Examples>`__ (AOI
  exports such as ``AOI_AVERAGE.L5X``), and the GitHub
  `l5x topic <https://github.com/topics/l5x>`__. Partial exports (a single AOI or
  routine) parse with the L5X module, but a full controller export exercises more of it.
- **Rockwell's Sample Code Library** (https://www.rockwellautomation.com/en-us/support/product/product-downloads.html,
  search "sample code") provides complete projects as ``.ACD`` files, which Studio 5000
  can export to ``.L5X``. A Studio 5000 license is required to export.
- **Firmware** (``.dmk`` Device Management Kits) is distributed through Rockwell's Product
  Compatibility and Download Center and requires an account. PEAT pushes but does not
  parse ``.dmk`` files.
- **Network traffic**: EtherNet/IP and CIP captures are in the collections below, which
  is how the ControlLogix scanning code is exercised offline.

Schweitzer Engineering Laboratories (relays, RTAC)
--------------------------------------------------
- *Wanted*: ``SET_ALL.TXT``/``CFG.TXT`` settings files and ``.rdb`` QuickSet databases.
  We haven't found public examples; relay settings are site-specific and rarely shared.
  SEL instruction manuals (https://selinc.com/products/, per model, "Documents") describe
  the settings format and the virtual file interface in detail, and are the best
  reference for writing synthetic examples.
- `SEL_RDB <https://aoufnihed.github.io/SEL_RDB/>`__ is an independent project that reads
  and writes ``.rdb`` files from text settings and documents the format; useful for
  generating test databases.
- AcSELerator QuickSet is free to download from SEL (account required) and can save
  ``.rdb`` files for any relay model without a device, with default settings.
- RTAC project exports: *wanted*. AcSELerator RTAC (free, account required) can export a
  project from a template without hardware.

Schneider Electric (Modicon M340, Sage RTU)
-------------------------------------------
- Schneider ships demo projects with Control Expert / Unity Pro (for example
  ``demo_ControlExpert_M340.sta``; see Schneider FAQ FA364303 at https://www.se.com/).
  These are ``.sta``/``.stu`` archives, not the ``.apx`` the PLC stores; opening a demo in
  Control Expert and building it produces an ``.apx``, which PEAT parses. A Control Expert
  license is required.
- Sage RTU: *wanted*. ``config@WEB`` configuration exports (``*_Config*.tar.gz``) and
  firmware archives. Documentation and tools are at https://www.sage-rtu.com/downloads.html.
- **Network traffic**: Modbus/TCP captures are common in the collections below; captures
  containing :term:`UMAS` project transfers (function code 90) are rarer but exist in
  Schneider-focused research datasets.

GE (Multilin UR relays, D25 RTU)
--------------------------------
- *Wanted*: EnerVista UR Setup ``.urs`` settings files and D25 configurations. EnerVista
  UR Setup is a free download from GE Vernova Grid Solutions and can create settings
  files offline for any UR model. The GERelay module parses pages pulled from a relay's
  web interface rather than ``.urs`` files, so saved web pages from a lab relay are the
  most useful contribution.

Siemens (SIPROTEC 4)
--------------------
- *Wanted*: DIGSI 4 projects and SNMP walks of SIPROTEC relays. DIGSI 4 includes demo
  projects; the Siprotec module currently pulls network configuration over HTTP and SNMP
  and does not parse project files.

Woodward (easYgen 3500XT, 2301E, MicroNet)
------------------------------------------
- Woodward's ToolKit software exports ``.wset`` settings files; configuration files for
  each controller are published on Woodward's support site (account required). *Wanted*:
  ``.wset`` and ``.tc`` samples, since parsing of these formats is partial and needs test
  coverage.

OpenPLC
-------
- The `OpenPLC Runtime v4 <https://github.com/Autonomy-Logic/openplc-runtime>`__ and
  `OpenPLC Editor <https://github.com/Autonomy-Logic/openplc-editor>`__ repositories, the
  `CONTROLLINO OpenPLC examples <https://github.com/CONTROLLINO-PLC/OpenPLC_examples>`__,
  and `OpenPLC Tutorials <https://github.com/virajdesai0309/OpenPLC_Tutorials>`__ provide
  example programs. Programs compiled by the editor can be pushed to a runtime; the
  :doc:`/tutorials/openplc_lab` tutorial uses the archive in the repository.

Fortinet (FortiGate)
--------------------
- FortiGate configuration backups (``.conf``) appear in several public tools' test data,
  for example the sample configuration in
  `forti_rule_police <https://github.com/cumakurt/forti_rule_police>`__ and the fixtures of
  `fgtconfig <https://github.com/cgustave/fgtconfig>`__. Fortinet's documentation
  describes the format (``config system global`` and friends). The Fortigate module
  expects a backup named like ``*Fortigate*.conf`` or logs named ``FG100F*.log``; rename
  samples or pass ``-d fortigate``.

iDirect, Camlin Totus, Windows CE, UEFI
---------------------------------------
- *Wanted*. iDirect modem options files, Camlin Totus web interface pages, output of the
  ``wince_pillage`` tool (which is not publicly released), and UEFI SPI flash extraction
  output (``spi*.txt``, ``*hashes*.json``). For UEFI, a dump of any PC's SPI flash
  processed with the extraction tooling the module expects would do; the module's
  docstring describes the input.

Network traffic captures (for HEAT and scanning)
================================================
Public :term:`PCAP` collections with :term:`ICS` protocol traffic, useful for
:doc:`/user_guide/heat` (the FTP extractor needs captures containing file transfers) and
for offline work on identification methods:

- `automayt/ICS-pcap <https://github.com/automayt/ICS-pcap>`__: a large collection organized
  by protocol (BACnet, DNP3, EtherNet/IP, Modbus, S7, and more)
- `ITI/ICS-Security-Tools <https://github.com/ITI/ICS-Security-Tools/blob/master/pcaps/README.md>`__:
  a curated list of ICS captures and where to get them
- `tjcruz-dei/ICS_PCAPS <https://github.com/tjcruz-dei/ICS_PCAPS>`__: Modbus/TCP SCADA
  captures from the ATENA project, including attack scenarios
- `Netresec's public PCAP list <https://www.netresec.com/?page=PcapFiles>`__ (see the
  "SCADA/ICS Network Captures" section), including the 4SICS ICS Lab captures
- Wireshark's `sample captures <https://wiki.wireshark.org/SampleCaptures>`__ have small
  Modbus, DNP3, and EtherNet/IP examples

Captures with FTP transfers of :term:`SEL` settings files or UMAS project downloads are the
ones HEAT can reconstruct files from; most public collections contain polling traffic
rather than file transfers, so expect to generate your own in a lab for a full HEAT
exercise.

Generating your own
===================
When no public sample exists, the most reliable sources are:

- **Vendor engineering software in demo mode**: most packages (QuickSet, AcSELerator
  RTAC, EnerVista, Control Expert, Studio 5000, ToolKit, DIGSI) can create and save a
  project without a device, producing a project file with default settings.
- **A lab device**: a ``peat pull`` against a device you own yields the exact files PEAT
  expects, and ``peat_results/<run>/devices/<ip>/`` is then a complete example set.
  Sanitize before sharing: credentials, addresses, site names.
- **Software PLCs and simulators**: OpenPLC, and the bennu virtual devices in
  :term:`SCEPTRE`, for repeatable, shareable examples.
- **Captures in a lab**: a ``peat pull`` from a lab relay while capturing with
  ``tcpdump`` produces a PCAP with exactly the FTP and Telnet traffic HEAT reconstructs.

Where example files are used
============================
Example files feed three things, and a good contribution touches all of them:

- **Tests**: ``tests/**/data_files/`` with expected outputs, so parsers can't regress.
- **Documentation**: ``literalinclude`` of inputs and outputs in the device reference
  pages and tutorials.
- **The supported devices table**: notes on which firmware or software versions produced
  the files PEAT was tested with (``docs/getting_started/supported_devices.csv``).
