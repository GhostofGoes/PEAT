****************
Design documents
****************
How PEAT works internally and why it is built the way it is. These pages are for
developers extending PEAT, integrators embedding it, and anyone who wants to understand
what happens between typing a command and reading the results. They describe the current
state of the code, with references to the modules involved; the API reference itself is
in the :doc:`/developer/index`.

.. toctree::
   :maxdepth: 1

   architecture
   run_lifecycle
   scanning
   pull_parse_push
   configuration_and_state

Overview
========
PEAT (Process Extraction and Analysis Tool) gathers information from field control devices
such as programmable logic controllers (:term:`PLCs <PLC>`), protection relays, remote
terminal units (:term:`RTUs <RTU>`), and power meters. Its capabilities are:

- Device discovery and verification ("scanning")
- Retrieval of device configuration, firmware, logic, logs, and other information
  ("pulling")
- Parsing acquired files ("artifacts") into a common, documented data model
- Uploading configuration and firmware to devices ("pushing"), and collecting artifacts
  from workstation disk images ("pillaging") and network traffic (:term:`HEAT`)

Architecturally, PEAT is a **modular library with a command line interface on top**:

- Each supported device is a **device module**, a Python class implementing a class-based
  API (:class:`~peat.device.DeviceModule`). Modules catalog an extensive set of
  characteristics of a device and are written by subject-matter experts who characterize
  and reverse-engineer each device. Modules are independent, so devices can be developed
  in parallel, and they can be imported at runtime, so sensitive or third-party modules
  can be used without changing PEAT.
- A **data model** (:class:`~peat.data.models.DeviceData`) normalizes what every module
  collects into one structure, which is what makes PEAT's output comparable across vendors
  and ingestible by other tools.
- **High-level APIs** (:mod:`peat.api`) implement the verbs (scan, pull, parse, push,
  pillage, heat) on top of the module API. The separation lets the module API evolve
  without affecting consumers of the high-level API, which include the CLI and other
  :term:`SNL` tools.
- A **protocol library** (:mod:`peat.protocols`), **settings system**
  (:mod:`peat.settings`), **logging**, and **Elasticsearch export** support everything
  else.

:doc:`architecture` describes these components and how they fit together;
:doc:`run_lifecycle` follows a command from start to finish; :doc:`scanning` and
:doc:`pull_parse_push` detail the core algorithms; and :doc:`configuration_and_state`
explains the settings singletons.

Design goals
============
The choices above serve a few goals that come up repeatedly in the code:

- **Safety first.** PEAT is deployed on sensitive networks where a misbehaving tool can
  affect life safety and critical infrastructure. Scans probe only the ports modules need,
  stop at the first identification, check whether hosts are online with the gentlest
  method available, and pulls only touch devices that were positively identified. Dry
  runs exist for every active command.
- **Get as much data as possible, and fail safely.** When one method of collecting data
  fails, log it and try the next; when one device fails, continue with the others. This
  is why exceptions are broadly caught in modules (see
  :doc:`/contributing/code_guidelines`).
- **Standardized, documented output.** One data model and one Elasticsearch schema for
  every vendor (see :doc:`/reference/database_schema`).
- **Portability.** PEAT must run wherever it's needed: a single self-contained executable
  for old and new Linux and Windows systems, a container, or a Python package, with
  minimal dependencies on the host. The build and distribution design is described in
  :doc:`/contributing/building`.
- **Reproducibility.** Every run records its complete configuration, its internal state,
  and its version, and can be replayed from them.
