************
Architecture
************
PEAT is organized in layers: entry points, high-level APIs, core services, device
modules, and the protocol library, with the data model running through all of them. This
page describes each layer and the components in it, and how data flows from a device to
the outputs.

System diagram
==============
.. raw:: html
   :file: ../images/peat_system_diagram.svg

.. only:: not html

   Entry points (the ``peat`` command line, the container image, Python scripts, and
   Sneakypeat) call the high-level APIs in ``peat.api`` (scan, pull, parse, push, pillage,
   heat, crypto, config builder). The APIs use the core services (module manager,
   datastore and data model, settings, logging, Elasticsearch export, utilities) and the
   device modules in ``peat.modules``, which communicate with field devices through the
   protocol library in ``peat.protocols``. Results flow into the device data model and
   out to the run directory, the terminal, and Elasticsearch or OpenSearch.

Entry points
============
- **Command line** (``peat``): :mod:`peat.__main__` builds the argument parser
  (:func:`peat.cli_args.build_argument_parser`) and hands the parsed arguments to
  :func:`peat.cli_main.run_peat`, which drives a run (see :doc:`run_lifecycle`). The
  executables built with PyInstaller and the container image (``ENTRYPOINT python -m
  peat``) are this entry point in different packaging.
- **Python package** (``import peat``): :func:`peat.initialize_peat` performs the same
  initialization as the CLI, and the high-level functions (:func:`peat.scan`,
  :func:`peat.pull`, :func:`peat.parse`, :func:`peat.push`, :func:`peat.pillage`) and the
  module classes are importable directly. ``peat/__init__.py`` is where the public
  interface is assembled; the import order in it matters (see
  :doc:`/contributing/codebase_tour`).
- **Sneakypeat** (``distribution/sneakypeat.py``) is a separate, minimal scanner for red
  team exercises, built into its own executable. It shares PEAT's protocol knowledge but
  not its code paths.

The ``consts.EntrypointType`` recorded in :attr:`state.entrypoint <peat.settings.State.entrypoint>`
(``CLI`` or ``Package``) lets the core behave slightly differently per entry point, for
example whether to write state and configuration dumps on exit.

High-level APIs (``peat.api``)
==============================
Each verb is a function in its own module that orchestrates modules, the datastore, and
exports, and returns a :doc:`summary </reference/summaries>` dictionary:

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Module
     - Responsibility
   * - :mod:`peat.api.scan_api`
     - Target expansion, host online checks, port checks, and running modules'
       identification methods for unicast, broadcast, and serial scans. Produces the scan
       summary. See :doc:`scanning`.
   * - :mod:`peat.api.pull_api`
     - Scans (unless ``--skip-scan``), de-duplicates the datastore, calls each verified
       device's module :meth:`~peat.device.DeviceModule.pull`, exports, and produces the
       pull summary.
   * - :mod:`peat.api.parse_api`
     - Resolves which modules can parse which paths (by file name pattern, file
       signature, or directory support), parses each file with
       :meth:`~peat.device.DeviceModule.parse`, and produces the parse summary.
   * - :mod:`peat.api.push_api`
     - Scans and verifies targets (unless skipped), then calls
       :meth:`~peat.device.DeviceModule.push` with the file and push type.
   * - :mod:`peat.api.pillage_api`
     - Mounts disk images (``qemu-nbd``) and searches filesystems for files matching the
       pillage configuration.
   * - :mod:`peat.api.heat_api` and :mod:`peat.heat`
     - Selects HEAT extractors, connects to the packet data source, and runs each
       extractor, which reconstructs files and parses them with the modules.
   * - :mod:`peat.api.crypto_api`
     - Encryption and decryption of configuration files (:mod:`peat.config_crypto`) and
       result archives (:mod:`peat.results_crypto`).
   * - :mod:`peat.api.config_builder_api` and :mod:`peat.config_builder`
     - Generating configuration files, and the Textual-based interactive builder.
   * - :mod:`peat.api.identify_methods`
     - The :class:`~peat.api.identify_methods.IPMethod` and
       :class:`~peat.api.identify_methods.SerialMethod` models that modules use to declare
       how they identify devices.

Core services
=============

Module manager
--------------
:class:`~peat.module_manager.ModuleManager`, available as :data:`peat.module_api`, is the
registry of device modules. At import it collects every :class:`~peat.device.DeviceModule`
subclass exposed by :mod:`peat.modules`, and it can import additional modules at runtime
from files, directories, or class objects (``-I``). It resolves the names and aliases users
type (``-d sel``, ``-d plc``) to module classes, and filters modules by capability
(``filter_attr="ip_methods"`` for modules that can scan, ``"filename_patterns"`` for
modules that can parse). Aliases come from each module's ``module_aliases``, its vendor,
device type, and the catch-all ``all``.

Data model and datastore
------------------------
:class:`~peat.data.models.DeviceData` (:mod:`peat.data.models`) is a Pydantic model that
holds everything known about one device: identity, description, firmware, OS, hardware,
logic, interfaces and services, files, registers, tags, I/O, events, memory, users, and
module-specific extras. Its sub-models (``Interface``, ``Service``, ``File``, ``Event``,
...) mirror the :doc:`Elasticsearch schema </reference/database_schema>`, and its methods
export the data as a dictionary, JSON, Elasticsearch documents, or files. Each
``DeviceData`` also carries private runtime state: the module that identified it
(``_module``), whether it is active and verified, its output directory, and its merged
options.

The :class:`~peat.data.store.Datastore` (:data:`peat.datastore`) is the registry of
``DeviceData`` instances for a run. Modules and APIs look devices up by identifier
(``datastore.get("192.0.2.22")``), and the datastore merges duplicates (the same device
seen at several addresses or by several methods) before export.

Settings
--------
:data:`peat.config` (:class:`~peat.settings.Configuration`) and :data:`peat.state`
(:class:`~peat.settings.State`) are singletons built on
:class:`~peat.settings_manager.SettingsManager`. They merge values from defaults, a
configuration file, environment variables, and runtime assignments (including CLI
arguments) with a defined precedence, type-check values loaded from text, and can be read
or written from anywhere in PEAT. :doc:`configuration_and_state` covers them in depth.
:mod:`peat.consts` holds values fixed at start-up (platform, start time, run ID) and must
not import other PEAT modules.

Initialization
--------------
:func:`peat.init.initialize_peat` turns raw options into a ready-to-run PEAT: it loads
and (if needed) decrypts the configuration file, applies runtime options, imports
third-party modules, computes the output and run directories, sets up logging, pushes
module and host options into the datastore, registers the exit handlers that write the
configuration and state dumps, and connects to Elasticsearch. Both the CLI and library
use go through it.

Logging
-------
PEAT uses `Loguru <https://loguru.readthedocs.io/>`__ (``from peat import log``) with
custom ``TRACE2``-``TRACE4`` levels for the ``-VV`` to ``-VVVV`` debugging levels.
:mod:`peat.log_utils` configures the sinks: the terminal (standard error), ``peat.log``,
``json-log.jsonl``, protocol transcript files, and an Elasticsearch sink for the
``peat-logs`` index. Standard-library loggers used by dependencies (Scapy, requests,
elasticsearch) are intercepted and routed through Loguru. Each module class gets a
``log`` bound with its name, so messages are attributable. Conventions are in
:doc:`/contributing/logging`.

Elasticsearch export
--------------------
:class:`peat.elastic.Elastic` wraps the Elasticsearch and OpenSearch clients (detecting
which one a server is), creates indices with the mappings in :mod:`peat.es_mappings`, and
pushes documents, serializing PEAT's types (bytes, paths, IP addresses, sets) along the
way. Every document pushed is also written under ``elastic_data/`` in the run directory.
Details: :doc:`/developer/elastic_implementation`.

Other core components
---------------------
- :mod:`peat.utils`: file writing with safe names and numbered duplicates, hashing,
  formatting, and other helpers used throughout.
- :mod:`peat.file_signature`: :class:`~peat.file_signature.FileSignature`, which
  identifies file types by magic bytes, XML tags, substrings, or custom checks (used by
  ``parse`` to pick modules and name files).
- :mod:`peat.exit_handler`: ordered registration of functions to run at exit (closing
  device connections before writing files, fixing file ownership last).
- :mod:`peat.parsing`: shared parsers, notably the PLCopen :term:`TC6` XML to Structured
  Text generator used for PLC logic, parsers for common Linux command output and ``/proc``
  files (:mod:`peat.parsing.command_parsers`), and ARM CPU ID decoding.

Device modules (``peat.modules``)
=================================
A device module is a subclass of :class:`~peat.device.DeviceModule` in a vendor package
(``peat/modules/<vendor>/``), together with the helper modules it needs: protocol
wrappers specific to the device (for example :class:`~peat.modules.sel.sel_telnet.SELTelnet`),
parsers for its file formats, constants, and resources such as MIBs. The module declares
*what it is* (vendor, brand, model, device type, aliases), *how to find it* (``ip_methods``,
``serial_methods``), *what files it understands* (``filename_patterns``,
``file_signatures``), and *its options* (``default_options``), and implements the verbs
it supports: ``_pull``, ``_parse``, ``_push``. The base class wraps these with validation,
logging, and post-processing (:meth:`~peat.device.DeviceModule.update_dev`, duplicate
purging). The :doc:`/developer/module_developer_guide` explains how to write one, and
:doc:`/developer/device_modules` documents the ones included.

Protocol library (``peat.protocols``)
=====================================
Reusable protocol clients and networking utilities shared by modules:

- **Discovery and addressing**: :mod:`~peat.protocols.discovery` (ARP, ICMP, and TCP
  host checks, port checks, with the raw-socket permission logic),
  :mod:`~peat.protocols.addresses` (parsing targets: hosts, networks, ranges, files,
  labels), :mod:`~peat.protocols.interfaces` (local interface enumeration), and the
  bundled ``manuf`` database for :term:`MAC` :term:`OUI` lookups.
- **Clients**: :class:`~peat.protocols.ftp.FTP`, :class:`~peat.protocols.telnet.Telnet`
  (on a forked ``telnetlib``, since the standard library module was removed in Python
  3.13), :class:`~peat.protocols.http.HTTP`, SSH and SCP (Paramiko), SNMP (pysnmp with
  bundled MIBs), :mod:`~peat.protocols.serial`, :class:`~peat.protocols.mysql.MySQL`,
  and PostgreSQL via psycopg2 (used by the SEL RTAC module).
- **Industrial protocols**: EtherNet/IP and :term:`CIP` (:mod:`peat.protocols.enip`,
  :mod:`peat.protocols.cip`, with the vendor ID table), :term:`PCCC`, and
  :term:`UMAS`/Modbus (in the M340 module). :term:`ServLink` lives in the Woodward modules.

Modules may use these directly or wrap them (SEL's transport-agnostic ASCII command layer
is a good example of a wrapper).

Data flow
=========
#. **Targets in.** The CLI or API caller provides targets (hosts, networks, serial ports,
   files, images, captures) and options.
#. **Devices are created in the datastore** as ``DeviceData`` objects keyed by an
   identifier (IP, serial port, or a name or file name for parsed files).
#. **Modules fill the data model.** Identification methods set the description and
   services; pulls add firmware, logic, files, events, and so on; parsers add what they
   extract from files. Modules store list-type data through
   :meth:`DeviceData.store() <peat.data.models.DeviceData.store>`, which merges
   duplicates, and write artifacts next to the data with
   :meth:`DeviceData.write_file() <peat.data.models.DeviceData.write_file>`.
#. **Post-processing.** The base class annotates known fields (``annotate_fields``),
   fills derived fields (``description.full``, ``related.*``), and the datastore merges
   duplicate devices.
#. **Export.** Each device is written as ``device-data-full.json``,
   ``device-data-summary.json``, and ``.jsonl`` files, and pushed to Elasticsearch as a
   device document plus one document per file, register, tag, I/O point, event, and
   memory read. The API returns the summary, which is also saved and optionally printed.
#. **Run metadata.** On exit, the configuration and state are written to
   ``peat_metadata/`` (and Elasticsearch), empty directories are removed, and file
   ownership is fixed when PEAT ran under ``sudo``.

Outputs
=======
- The **run directory** (see :doc:`/user_guide/output`): the primary output, usable
  offline and self-describing.
- **Standard output**: JSON summaries with ``--print-results``, for pipelines. Logs go to
  standard error so the two never mix.
- **Elasticsearch/OpenSearch**: for dashboards, long-term storage, and other tools, with
  local copies of every document.
- **Exit code**: 0 for success, 1 if any error occurred, so automation can react.

Where things live
=================
The repository layout, file by file, is described in :doc:`/contributing/codebase_tour`.
