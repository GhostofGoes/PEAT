************
Introduction
************

PEAT (Process Extraction and Analysis Tool) is a multifunction utility and
:term:`Python` library for interrogating and mapping :term:`ICS` and :term:`OT` devices,
such as :term:`PLCs <PLC>`, protection relays, :term:`RTUs <RTU>`, power meters, and
:term:`HMIs <HMI>`. It discovers devices on a network, acquires :term:`artifacts <Artifact>`
(configuration, process logic, firmware, logs, memory) from them, parses artifacts and vendor
project files into a :doc:`standard data model </developer/data_model>`, and can push
configuration or firmware back to a device for recovery.

PEAT is a command line program first (``peat``), and a Python package second
(``import peat``). It runs on Linux, Windows, and macOS, and as a :term:`Docker` or
:term:`Podman` :term:`container <Container>`. It is developed by
:term:`Sandia National Laboratories <SNL>` and released as open source under the GPLv3.

What PEAT does
==============
Each capability is a sub-command of the ``peat`` program (a "verb"):

.. list-table::
   :header-rows: 1
   :widths: 14 60 26

   * - Command
     - What it does
     - Learn more
   * - ``scan``
     - Discover and identify ("fingerprint") supported devices on a network or on serial
       ports, carefully, with a focus on minimizing impact to field devices and processes.
     - :doc:`/user_guide/scan`
   * - ``pull``
     - Actively interrogate devices to retrieve detailed information and artifacts
       (configuration, logic, firmware, logs, memory, and so on) over Ethernet or serial.
       A pull implicitly scans first and only pulls from devices it has identified.
     - :doc:`/user_guide/pull`
   * - ``parse``
     - Extract information from device artifacts offline. The input can be a file pulled
       from a device or a *project file* exported from the vendor's engineering software.
       The amount of information extracted varies by device.
     - :doc:`/user_guide/parse`
   * - ``push``
     - Upload configuration or firmware to a device, for example to restore a known-good
       state. Also known as :term:`REPEAT`.
     - :doc:`/user_guide/push`
   * - ``pillage``
     - Search a disk image, mounted drive, or directory (for example an engineering
       workstation) for OT project and configuration files worth parsing.
     - :doc:`/user_guide/pillage`
   * - ``heat``
     - :term:`HEAT` reconstructs artifacts from network traffic captures
       (:term:`PCAP` files or packet data in Elasticsearch) and parses them.
     - :doc:`/user_guide/heat`

Supporting commands build configuration files interactively (``config-builder``) and
encrypt or decrypt configuration files and result directories (``encrypt-config``,
``decrypt-config``, ``encrypt-results``, ``decrypt-results``). The complete list of
devices PEAT supports, and what it can do with each, is on the :doc:`supported_devices`
page.

High-level flow
===============
The diagram below shows how the commands fit together. Inputs on the left are turned
into :term:`device data <Device data>` by the commands in the middle, which is written to
the outputs on the right. A pull implicitly scans; parse operates on files from a pull,
pillage, HEAT, or a vendor's project file; every command produces a
:term:`run directory <Run directory>` of :term:`JSON` results and log files, and can
additionally export to Elasticsearch or OpenSearch.

.. raw:: html
   :file: ../images/peat_high_level_flow.svg

.. only:: not html

   Inputs (network targets, serial ports, files and project files, disk images, packet
   captures, and a YAML configuration) are processed by the PEAT commands (scan, pull,
   parse, push, pillage, heat) into the device data model, which is written to the run
   directory as JSON files and artifacts, printed to the terminal, and optionally exported
   to Elasticsearch or OpenSearch.

Why use PEAT?
=============

Use cases
---------
- **Network inventory and discovery.** Going into an unknown network, what's here? Even on
  a known system, documentation is often out of date. A scan or pull produces an inventory
  with vendor, model, firmware, and services for every device PEAT recognizes.
- **Forensics and incident response.** After an incident, run a pull to collect logs, file
  artifacts, hashes, and memory reads. Was the firmware modified? The logic? Is the
  configuration what it should be? What do the device logs say?
- **Change monitoring.** Regular pulls over time, compared against each other (or ingested
  into analytics such as Sandia's Hipparchus and Archimedes tools), reveal configuration,
  logic, and firmware changes.
- **Backups.** Point a pull at 100 relays and have a backup of every configuration in
  minutes, instead of connecting to each one with the vendor's software.
- **Health monitoring.** Check that devices are healthy and that there are no errors in
  their logs, filling gaps where vendor capabilities are lacking.
- **Recovery.** A push can upload a known-good configuration or firmware image to bring a
  device back to a trusted state.
- **Red team and exercises.** PEAT is a reconnaissance tool for red team engagements, and
  :term:`Sneakypeat` is a lighter-weight build designed for exercises.

Why not vendor software or other tools?
---------------------------------------
- Vendor engineering software is difficult or impossible to automate, usually requires a
  Windows :term:`GUI` (often a licensed Windows :term:`VM` as well), and may cost thousands of
  dollars per seat. Automating a GUI is brittle and expensive to maintain.
- Vendors typically support only their latest devices; older devices need older software,
  resulting in a collection of bespoke VMs to maintain.
- The data is limited to what the vendor chose to expose. PEAT collects what is *possible*
  to obtain: raw files and file hashes, memory, running processes, network state, and more.
- Vendor tools don't scale. Pulling from ten power meters at once with PEAT is one command.
- PEAT is portable and lightweight: a single executable or container, no virtualization.
- PEAT lets you limit what is collected, keeping load on sensitive devices under control.
- **Standardized output.** PEAT normalizes data from every vendor into one
  :doc:`data model </developer/data_model>` and :doc:`schema </reference/database_schema>`
  so downstream tools and :term:`SIEM` platforms can ingest it, and it integrates
  directly with Elasticsearch and OpenSearch.
- **Automation.** PEAT is trivial to script and has been automated many times.

Where to go next
================
- New to PEAT? Check the :doc:`requirements`, :doc:`install` it, then follow the
  :doc:`quickstart`.
- Looking for a worked example that matches your situation? See the :doc:`/tutorials/index`.
- Need details on a command or option? See the :doc:`/user_guide/index` and
  :doc:`/reference/index`.
- Want to add support for a device? Start with the
  :doc:`/developer/module_developer_guide`.
