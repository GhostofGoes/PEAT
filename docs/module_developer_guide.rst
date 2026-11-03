**********************
Module developer guide
**********************

.. seealso::

   :doc:`data_model`

   :doc:`device_api`

   :doc:`general_apis`

   :doc:`baselines`

   :doc:`Python code examples <python_examples>`

   :ref:`scanning-process`


Introduction
============
Each OT device that PEAT supports is implemented as a PEAT device "module", which is a Python class that encapsulates the functionality for the device. The PEAT device module API is class-based, and provides an interface for interaction with specific devices. Subclasses of :class:`~peat.device.DeviceModule` are known as "PEAT modules" and provide a set of methods to interact with a device.  A module consists of a directory in ``/peat/modules/`` containing a subclass of :class:`~peat.device.DeviceModule` with the "public" functions for that device model, various code files implementing the functionality the class provides, and any resources the module needs (e.g. :term:`SNMP` MIBs, :term:`XML` specs, special binaries, etc.).

The core logic of the module is implemented by subclassing :class:`~peat.device.DeviceModule` and overriding (implementing) the appropriate methods, :meth:`~peat.device.DeviceModule.pull_project` or :meth:`~peat.device.DeviceModule._parse`. The methods (functions) of :class:`~peat.device.DeviceModule` take an instance of :class:`~peat.data.models.DeviceData` as an argument. The :class:`~peat.data.models.DeviceData` instance contains information about a specific device being interacted with and manages the data and state for that device. In other words, :class:`~peat.device.DeviceModule` is the implementation of methods to interact with a *type of device* (e.g. a Rockwell Allen-Bradley ControlLogix PLC), and :class:`~peat.data.models.DeviceData` stores and manages data from a *specific physical device* (e.g. the ControlLogix on a factory floor you're doing a forensic pull from).

:class:`~peat.data.models.DeviceData` manages device data and state and is the implementation of the PEAT "data model". It contains a set of defined structures for storing device information and state, such as config, logic, firmware, status, and other information or artifacts. Module configuration is stored in :attr:`~peat.data.models.DeviceData.options`, which is simply a dictionary of key-value pairs with configurations for the module, such as credentials or ports to use for services (e.g. FTP). If no options are given, then the defaults for that device are used.

When you do a scan with the API, it returns a :class:`dict` :class:`~peat.data.models.DeviceData` objects. Each :class:`~peat.data.models.DeviceData` object contains information about the device, while the corresponding :class:`~peat.device.DeviceModule` class provides methods to perform actions on that :class:`~peat.data.models.DeviceData` object, such as :meth:`~peat.device.DeviceModule.pull_project`, :meth:`~peat.device.DeviceModule.parse`, etc.

The design and architecture is explained in more detail in :doc:`design_documents`.


The module API
==============
The device module model is powered by the PEAT Module API (:class:`~peat.module_manager.ModuleManager`). The system serves two purposes:

#. Runtime *lookup* of imported modules by a alias and/or filter
#. Runtime *import* of 3rd-party modules (via directory, file, or passed as a Python object)

Using the API, it is possible to lookup a module at runtime using a wide variety of identifiers, such as vendor, device class (e.g. "PLC" or "RTU"), brand, or aliases added by the device module. The lookup also enables filtering of devices based on attribute, such as if it supports broadcasts or has a special attribute that may not be a part of the base :class:`~peat.device.DeviceModule` class.

The API also supports the runtime import of additional external "3rd-party" device modules that implement the :class:`~peat.device.DeviceModule` class. They can be imported as a folder containing the module or as a Python class object. This enables scenarios such as customer-created modules, as well as making PEAT more extensible in general.

.. note::
   The bundled "executable" version of PEAT needs to know what Python libraries are being used by your module. If you are using a library module (e.g. ``import csv``) that isn't already used elsewhere in PEAT you will need to tell PyInstaller about it. Edit ``distribution/peat.spec`` and add the module name(s) to the ``hidden_imports`` list. This is the cause of the error ``"Failed to import mypackage.mymodule: No module named 'csv'``.


.. _writing-device-class:

Example of writing a PEAT module
================================
A module is a Python file containing a Python class that implements the desired PEAT interfaces, such as the data model and parsing. The steps are:

- Create the module boilerplate code (including creating a subclass of :class:`~peat.device.DeviceModule`)
- Implement a parser for the vendor output format, overriding ``_parse()``
- Store the results in an instance of :class:`~peat.data.models.DeviceData`, following the format as documented in the :doc:`data_model`

The best example of parsing is the SCEPTRE PEAT module (:class:`peat.modules.sandia.sceptre_fcd.SCEPTRE`), in ``peat/modules/sandia/sceptre_fcd.py``. Look at the :meth:`~peat.modules.sandia.sceptre_fcd.SCEPTRE._parse` and :meth:`~peat.modules.sandia.sceptre_fcd.SCEPTRE.parse_config` implementations for examples of how parsing is structured and the results are formatted and stored.

Walkthrough
-----------
.. note::
   The source code for classes and functions in this documentation is available by clicking the ``source`` to the right of the documentation for the class or function. This can save some time if you don't have the source code handy.

.. note::
   Refer to the :doc:`API documentation <peat_api>` for details about global variables (e.g. :attr:`config.OUT_DIR <peat.settings.Configuration.OUT_DIR>` and :attr:`state.elastic <peat.settings.State.elastic>`), constants (e.g. :data:`consts.START_TIME_UTC <peat.consts.START_TIME_UTC>`), and exception classes.

.. note::
   Refer to :ref:`config-state-deepdive` for a detailed explanation and discussion on PEAT's global configuration and state, including how to add new variables

This guide will walk you though the creation of a PEAT device module. You should be relatively proficient in Python and understand classes and inheritance. You will create the module for the fictional tool, "Awesome Tool". Awesome Tool is a command-line program that pulls information from Programmable Logic Controllers (PLCs) over a network. If it existed, you would use it by running  ``awesome-tool``, and get the results of the tool from ``awesome_output.json``. The finished example AwesomeTool module (``awesome_module.py``), an example input file (``awesome_output.json``), and the expected PEAT output from running the module (``awesome_output_expected_device-data-*.json``) are in ``examples/example_peat_module``.

Input data the module will process:

.. literalinclude:: ../examples/example_peat_module/awesome_output.json
   :name: awesome_output_json
   :caption: awesome_output.json
   :language: json

To begin, create a new file ``awesome_module.py`` and open it in your preferred text editor or development environment. Then, create the boilerplate:

.. literalinclude:: ../examples/example_peat_module/awesome_module.py
   :name: awesome_module_py
   :caption: awesome_module.py
   :language: python

Using the created module
------------------------
Since this is a fictional example and ``awesome-tool`` does not exist, assume it has been run and generated ``awesome_output.json`` (this can be found in ``examples/example_peat_module/``).

How to run the AwesomeTool module:

.. code-block:: bash

   # "-d AwesomeTool" : the "AwesomeTool" module you created (this matches the name of the Python class)
   # "-I awesome_module.py" : import the module code so it's usable by PEAT
   # "-- ./awesome_output.json" : the file to parse
   peat parse -d AwesomeTool -I awesome_module.py -- ./awesome_output.json

Example terminal output from running the included example module:

.. code-block:: bash

   $ pdm run peat parse --no-logo -d AwesomeTool -I ./examples/example_peat_module/awesome_module.py -- ./examples/example_peat_module/awesome_output.json
   17:01:21.039 INFO    log_utils        Log file: peat_results/parse_default-config_2024-06-26_17-01-20_171942128019/logs/peat.log
   17:01:21.040 INFO    peat.init        Run directory: parse_default-config_2024-06-26_17-01-20_171942128019
   17:01:21.041 INFO    parse_api        Parsing 1 filepaths
   17:01:21.042 INFO    parse_api        Parsing AwesomeTool file '/home/cegoes/peat/examples/example_peat_module/awesome_output.json'
   17:01:21.050 INFO    utils            Saved parse summary to peat_results/parse_default-config_2024-06-26_17-01-20_171942128019/summaries/parse-summary.json
   17:01:21.050 INFO    parse_api        Completed parsing of 1 files in 0.01 seconds
   17:01:21.051 INFO    peat.cli_main    Finished run in 0.02 seconds at 2024-06-26 17:01:21.051042+00:00 UTC


The results are in ``device-data-full.json``:

.. literalinclude:: ../examples/example_peat_module/awesome_output_expected_device-data-full.json
   :name: awesome_module_output_example
   :caption: Output of the example PEAT module AwesomeTool
   :language: json


Adding a module to PEAT
=======================
Contributing a new module to be included in PEAT's codebase.

#. Create a vendor directory for the device in ``peat/modules/``, and potentially a sub-directory if the device will have a lot of source modules (in other words, more than one ``.py`` file). Note: if the vendor already exists, just use the existing directory.

   - Example: the SELRelay device module is in ``peat/modules/sel/``, and the ION module is in ``peat/modules/schneider/ion/``

#. Create the :class:`~peat.device.DeviceModule` class in a ``.py`` file with the name of the class in lower-case, e.g. ``peat/modules/<vendor>/<device>.py`` (see :ref:`writing-device-class`)

   - Example: the ION module is in ``peat/modules/schneider/ion/ion.py``

#. Add the module import to the ``__init__.py`` files for each package and sub-package. This will need to be done in each nested directory, for example the ION module will need to be imported in ``peat/modules/__init__.py``, ``peat/modules/schneider/__init__.py``, and ``peat/modules/schneider/ion/__init__.py``. Example of an import:

   .. code-block:: python

      # peat/modules/schneider/ion/__init__.py
      from .ion import ION

      # peat/modules/schneider/__init__.py
      from .ion import ION

      # peat/modules/__init__.py
      from peat.modules.schneider import ION

#. Add command line usage examples to the docstrings for the relevant commands in ``peat/cli_args.py``, for example if your module supports scanning and pulling then you should add examples to ``scan_examples`` and ``pull_examples`` in ``peat/cli_args.py``.
#. (Optional) If there are any device-specific configuration options needed (like a special username or whatever that needs to be configurable by the user), then do the following:

   #. Add a ``default_options`` class attribute to your module and populate it with options for your module. Options specific to your module should be nested under a key with the name of your module, e.g. ``"sel"`` for options specific to SEL devices, and general options like protocols should go under a separate key. For example:

      .. code-block:: python

         class SELRelay(DeviceModule):
            default_options = {
               "ymodem": {
                  "baudrate": 57600,
               },
               "web": {
                     "user": "",
                     "pass": "",
               },
               "sel": {
                     # If the relay should be restarted after the push completes
                     "restart_after_push": False
               }
            }

   #. Add the options to the example YAML config file ``examples/peat-config.yaml``, including default values and detailed descriptions of the options and how they should be used. This will serve as documentation for the options. It's also the only way for users to know how to configure your module, so don't be afraid to go into detail!

#. Add the device information (vendor, model, known tested, firmware, etc.) to the table of supported devices in Introduction section of the PEAT documentation
#. Write a basic set of tests for your module (refer to the existing tests as well as the :ref:`test-docs`)
#. (Optional) Create a dedicated documentation page with details on the device in the documentation. A few examples of this are ``sel.rst`` and ``siemens.rst``.


.. _module-data-conventions:

Data conventions
================
Follow these conventions when storing data, so the data of different modules can be searched, compared and correlated together. The fields are documented in :doc:`data_model`.

- Store list items with :meth:`~peat.data.models.DeviceData.store` (e.g. ``dev.store("service", Service(...))``), not ``list.append()``: ``store()`` merges the item with an existing item with the same identity (e.g. a service with the same protocol and port).
- When data has a first-class field, use it and remove the old key from ``dev.extra`` (or ``*.extra``) in the same change. ``extra`` is for data with no field.
- Aggregate high-volume observations (log lines, connection logs, ARP refreshes) per peer BEFORE storing them: one :class:`~peat.data.models.Relationship` per peer with ``count``, ``first_seen`` and ``last_seen``. Do not compute relationship IDs, and leave ``direction``, ``protocol`` and ``local.interface`` empty if the source does not say: :meth:`Relationship.annotate() <peat.data.models.Relationship.annotate>` infers them.
- Group observations by the identity of the relationship (:meth:`Relationship.key() <peat.data.models.Relationship.key>`), not by your own key: records with the same identity are merged by ``store()``, which keeps the first record's names and ``extra``. Combine several logical peers configured behind one edge (e.g. remote devices behind one gateway IP address and port, or several sessions of one master) into one relationship, with the details of each in ``extra``. Set the protocol of an edge without a port (e.g. ``ocsp`` for an OCSP responder) so that different services of one host stay separate.
- Device-reported times without a timezone stay naive (device-local time). Never guess UTC.

Protocol names
--------------
Use the canonical lowercase protocol names (with underscores) in :attr:`Service.protocol <peat.data.models.Service.protocol>`, :attr:`Relationship.protocol <peat.data.models.Relationship.protocol>`, :attr:`NetworkStatistics.protocol <peat.data.models.NetworkStatistics.protocol>` and :attr:`Interface.application <peat.data.models.Interface.application>`, and give a relationship the same protocol as the device's own service. The full table with transports, ports and the roles of each protocol (``RelationshipEndpoint.role``) is in "Canonical vocabularies" in :doc:`data_model`.

.. csv-table::
   :header: "Name", "Protocol"

   "``modbus_tcp``, ``modbus_rtu``", "Modbus TCP, Modbus RTU (serial). Not ``modbus``."
   "``dnp3``", "DNP3 (TCP, UDP or serial)"
   "``iec104``", "IEC 60870-5-104. Not ``iec_104``."
   "``c37_118``", "IEEE C37.118 synchrophasors. Not ``c37.118``."
   "``mms``, ``goose``, ``sv``", "IEC 61850 MMS (tcp/102), GOOSE, Sampled Values. Not ``iec61850``."
   "``cip``, ``enip``", "EtherNet/IP explicit messaging (tcp/44818), EtherNet/IP implicit I/O (udp/2222). Two different services."
   "``mirrored_bits``, ``sel``", "SEL MIRRORED BITS, SEL ASCII/Fast Message"
   "``bacnet``, ``snmp``, ``syslog``", "BACnet/IP, SNMP, Syslog"
   "``ntp``, ``sntp``, ``ptp``", "Time synchronization"
   "``http``, ``https``, ``ssh``, ``telnet``, ``ftp``", "Management protocols"

Known spelling variants (``c37.118``, ``iec_104``) are normalized by the validators, and a service with ``protocol="modbus"`` and ``transport="tcp"`` becomes ``modbus_tcp``. Still use the canonical names in new code.

Statistics and live readings
----------------------------
- Statistics (:class:`~peat.data.models.NetworkStatistics`) are cumulative counters, exactly as read from the device (not rates). Set ``since`` only if the device reports when its counters were last cleared; do not assume the boot time.
- **Always set** :attr:`NetworkStatistics.timestamp <peat.data.models.NetworkStatistics.timestamp>` to the time the counters were read, as timezone-aware UTC (:func:`peat.utils.utc_now`). When device data is merged, a sample with a newer ``timestamp`` replaces the older sample *as a whole*. Counters of two samples are never mixed, and a sample without a timestamp never replaces another one.
- Keep ONE complete sample per scope (device, interface, service). If a second source reports other counters for the same scope during the same pull, put them in a :attr:`DeviceData.protocol_statistics <peat.data.models.DeviceData.protocol_statistics>` entry or in ``statistics.extra``.
- Counters that the device reports as overflowed (e.g. ``$$$$``): leave the field ``None`` and list the field in ``extra["overflowed"]`` (e.g. ``["ingress.packets"]``). Values above the Elasticsearch ``long`` range are moved to ``extra["out_of_range"]`` automatically.
- Live readings also need a timestamp (``utils.utc_now()``): :attr:`Indicator.timestamp <peat.data.models.Indicator.timestamp>` for LED/display/switch states (a definition from a settings file has no timestamp and no state), and :attr:`Clock.observed <peat.data.models.Clock.observed>` when ``Clock.time`` is read from the device.

Health (NE 107)
---------------
Map vendor states to the NAMUR NE 107 categories of :attr:`DeviceData.health <peat.data.models.DeviceData.health>` and :attr:`Indicator.health <peat.data.models.Indicator.health>`. Keep the raw device values in ``status``, ``run_mode`` and ``key_switch``. When several sources apply (e.g. self-tests, alarms and the operating mode), the most severe value wins, in the order of the table. Leave ``health`` empty if the device does not report enough to decide.

.. csv-table::
   :header: "Device state", "``health``"

   "Fault; outputs disabled by a failure; a failed self-test", "``failure``"
   "Program, test or maintenance mode; key switch in PROG; relay disabled for a settings change", "``check_function``"
   "Measurement out of range; deviation from a setpoint", "``out_of_specification``"
   "Minor fault with valid outputs; battery low; wear (e.g. contact or flash wear)", "``maintenance_required``"
   "Running without faults", "``normal``"

Credentials and secrets
-----------------------
**Never store secrets** (passwords, SNMP community strings, private keys, password hashes) in any field, including ``extra``, and never log them. Record credential *facts* in :class:`~peat.data.models.ServiceSecurity` (``Service.security``):

- Declare the vendor's factory-default credentials as the class attribute :attr:`~peat.device.DeviceModule.factory_default_credentials` (``{(user, password), ...}``). It is only used in code; it is never exported.
- After a successful login, check the credential that SUCCEEDED with :meth:`~peat.device.DeviceModule.is_factory_default_credential` (user names are case-insensitive). Set ``default_credentials=True`` only if it returns ``True``. Set ``default_credentials=False`` only if every factory default for that service was tried and rejected. Otherwise (e.g. site credentials from the configuration worked, factory defaults not tried) leave it ``None``.
- An anonymous login (e.g. anonymous FTP) is not a default credential: set ``anonymous_access=True`` and ``authentication_required=False``. Set ``authentication_required=True`` where a password was needed.

.. code-block:: python

   class AwesomeTool(DeviceModule):
       factory_default_credentials = {("admin", "awesome")}

   # after a successful FTP login with (user, password)
   svc = Service(protocol="ftp", port=21, transport="tcp")
   svc.security.authentication_required = True
   if AwesomeTool.is_factory_default_credential(user, password):
       svc.security.default_credentials = True
   dev.store("service", svc)

File paths from a device
------------------------
File names and paths reported by a device (e.g. a FTP listing) are untrusted. :meth:`DeviceData.write_file <peat.data.models.DeviceData.write_file>` keeps them inside the output directory (``..`` components and a leading ``/`` are dropped). To build a local path from a device path yourself, use :func:`peat.utils.safe_join`, never ``Path(local_dir, device_path)``. Convert device file times with :func:`peat.utils.utc_from_timestamp`, which returns ``None`` instead of raising for a corrupt or crafted time.

.. _declaring-known-defaults:

Declaring known defaults
------------------------
Modules can declare the factory defaults and vendor hardening recommendations of the devices they support, as :class:`~peat.data.models.Baseline` objects in the class attribute :attr:`~peat.device.DeviceModule.known_defaults`. ``peat baseline-compare --known-defaults`` and :func:`~peat.api.baseline_api.compare_to_known_defaults` compare devices against them (see :doc:`baselines`). A module declares at most two baselines, both with ``rules`` only (no ``expected`` snapshot):

- ``<module>-factory-defaults`` (``kind="factory_default"``): the factory VALUES, e.g. "Telnet listens on 23", "the device name is ``AWESOME-PLC``". Use severity ``info`` and a reason like "... changed from factory default ...": a failed rule means the setting was changed from the factory default, which is information, not a problem.
- ``<module>-vendor-recommended`` (``kind="vendor_recommended"``): the vendor's hardening guidance, e.g. "Telnet absent", "FTP disabled", "no factory default password accepted", "key switch in RUN". A failed rule is a deviation from the recommendation. Use ``alert=True`` for findings that need action (e.g. accepted factory default passwords).

Do not add rules that are neither factory values nor hardening guidance, e.g. "the firmware is a version PEAT was tested with" or "the OS is VxWorks". Never put passwords or other secrets in rules: check ``service[*].security.default_credentials`` instead.

Guidelines:

- Put the baselines in their own file in the module package (e.g. ``peat/modules/sel/sel_defaults.py``).
- Rule ``id`` values are stable and unique, ``<module>.<area>.<check>`` (e.g. ``awesome.service.telnet.absent``). Paths use the baseline path syntax (:doc:`baselines`) on the exported device data, e.g. ``service[protocol=ftp].enabled``, ``service[*].security.default_credentials``, ``key_switch``.
- Set ``category`` and ``severity`` on each rule, and ``reference`` (manual section, hardening guide) and ``standards`` where they apply. ``reason`` may use ``{expected}``, ``{actual}`` and ``{path}``.
- If ``selector`` is left empty, :meth:`~peat.device.DeviceModule.get_known_defaults` sets it to the module's ``vendor_id`` and ``device_type``, and an empty ``provenance.author`` to the module name. Set the selector explicitly if the baseline only applies to some devices of the module (e.g. ``model="351*"``).
- Test the baselines: every rule path parses (:func:`peat.data.baseline.split_path`), and the rules pass and fail as expected on synthetic :class:`~peat.data.models.DeviceData` objects (:func:`~peat.api.baseline_api.compare_to_baseline`). Print them with ``peat baseline-show --known-defaults -d <module>``.

Example:

.. code-block:: python

   # awesome_defaults.py
   from peat.data.models import Baseline, BaselineProvenance, BaselineRule

   FACTORY_NAMES = ["AWESOME-PLC", "awesome-plc"]
   PROVENANCE = BaselineProvenance(reference="Awesome PLC user manual, section 4.2")

   AWESOME_KNOWN_DEFAULTS = [
       Baseline(
           id="awesome-factory-defaults",
           name="Awesome PLC factory defaults",
           version="1",
           kind="factory_default",
           scope="device_type",
           provenance=PROVENANCE,
           rules=[
               BaselineRule(
                   id="awesome.default.http-port",
                   name="HTTP on factory port",
                   path="service[protocol=http].port",
                   operator="equals",
                   value=80,
                   category="ports_services",
                   severity="info",
                   reason="HTTP port changed from factory default 80 to {actual}",
               ),
               BaselineRule(
                   id="awesome.default.name",
                   name="Factory device name",
                   path="name",
                   operator="in",
                   value=FACTORY_NAMES,
                   category="identity",
                   severity="info",
                   reason="Device name changed from factory default",
               ),
           ],
       ),
       Baseline(
           id="awesome-vendor-recommended",
           name="Awesome PLC hardening",
           version="1",
           kind="vendor_recommended",
           scope="device_type",
           provenance=PROVENANCE,
           rules=[
               BaselineRule(
                   id="awesome.service.telnet.absent",
                   name="Telnet not exposed",
                   path="service[protocol=telnet]",
                   operator="absent",
                   category="ports_services",
                   severity="medium",
                   reason="Telnet (23/tcp, cleartext) is exposed",
               ),
               BaselineRule(
                   id="awesome.accounts.default-credentials",
                   name="No factory default passwords",
                   path="service[*].security.default_credentials",
                   operator="not_equals",
                   value=True,
                   category="accounts",
                   severity="high",
                   alert=True,
                   reason="A factory default password was accepted",
               ),
           ],
       ),
   ]

   # awesome_module.py
   class AwesomeTool(DeviceModule):
       device_type = "PLC"
       vendor_id = "Awesome"
       known_defaults = AWESOME_KNOWN_DEFAULTS
       factory_default_credentials = {("admin", "awesome")}


Development tips and tricks
===========================

When developing a module, a common practice is to create a Python file that directly invokes the module and desired methods instead of running the normal PEAT entrypoint. This has a number of advantages, including faster startup and execution time, less extraneous output, ability to attach a debugger, fine-grained control over what methods get executed, ability to drop into an interpreter prompt (the "Read-Eval-Print-Loop", aka the "REPL") for live development, and the ability to use `Jupyter notebooks <https://realpython.com/jupyter-notebook-introduction/>`_.

Create a file ``mymodule_testing.py`` with the following code:

.. code-block:: python

   from pathlib import Path
   from peat import SELRelay, initialize_peat

   initialize_peat({'VERBOSE': True, 'DEBUG': 1})

   input_path = Path('examples/devices/sel/sel_351/set_all.txt')
   dev = SELRelay.parse(input_path)
   print(dev.export())

Then, invoke it:

.. code-block:: bash

   # Run and exit
   pdm run python mymodule_testing.py

   # Drop into an interpreter for inspecting variables and doing live development
   # Note the "-i" argument to python
   pdm run python -i mymodule_testing.py
   >>> dev
   >>> some_other_dev = SELRelay.parse(Path('some_other_file.txt'))
   >>> from peat import datastore
   >>> pull_dev = datastore.get("192.0.2.22")
   >>> SELRelay.pull_project(pull_dev)
   >>> pull_dev.firmware.version

Debugging from the CLI
----------------------
There are two debugging-specific command line arguments:

- ``--pdb`` (``--launch-debugger``): this will begin the run, then break into the Python Debugger (pdb). This is useful for inspecting program state, and stepping through the program.
- ``--repl`` (``--launch-interpreter``): begin the PEAT run, then break out into the Python interactive interpreter (aka the "Read-Eval-Print-Loop" or "REPL"). This is useful for getting access to the Python API via the executable distribution, checking program state, or testing a hypothesis about how stuff should function in specific conditions.
