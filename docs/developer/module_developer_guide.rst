**********************
Module developer guide
**********************
How to add support for a device to PEAT by writing a *device module*. This guide covers
the concepts, the anatomy of a module, a complete walkthrough using the example module in
the repository, identification methods, file signatures, pulling and pushing, options,
testing, and what to include when contributing a module.

.. seealso::

   :doc:`device_api`
      The :class:`~peat.device.DeviceModule` API reference

   :doc:`data_model`
      The :class:`~peat.data.models.DeviceData` fields your module fills in

   :doc:`general_apis`
      Protocol clients and utilities to use from a module

   :doc:`python_examples`
      Short examples of the API

   :doc:`/design/scanning` and :doc:`/design/pull_parse_push`
      How the APIs call into modules

Concepts
========
Each :term:`OT` device PEAT supports is implemented as a PEAT device module: a
:term:`Python` class that subclasses :class:`~peat.device.DeviceModule` and encapsulates
the functionality for that *type* of device (for example, Rockwell ControlLogix PLCs). A
module lives in a directory under ``peat/modules/<vendor>/`` with any supporting code
(protocol wrappers, parsers, constants) and resources (:term:`SNMP` MIBs, :term:`XML`
schemas, lookup tables), or in a standalone ``.py`` file imported at runtime with ``-I``.

The methods of a module take a :class:`~peat.data.models.DeviceData` instance, which
holds the data and state for one *specific* device (the ControlLogix on the factory floor
you're pulling from). In other words: :class:`~peat.device.DeviceModule` is behavior for
a kind of device, :class:`~peat.data.models.DeviceData` is data about one device.
``DeviceData`` is PEAT's :doc:`data model <data_model>`: a defined set of structures for
configuration, logic, firmware, status, services, files, events, and so on, with a
matching :doc:`Elasticsearch schema </reference/database_schema>`. A module's job is to
get data from a device or a file into those structures.

Modules are managed by the module API (:class:`~peat.module_manager.ModuleManager`,
available as :data:`peat.module_api`), which looks modules up by name, alias, vendor, or
device class (``-d sel``, ``-d plc``), filters them by capability, and imports third-party
modules at runtime from files, directories, or class objects. The high-level APIs
(scan, pull, parse, push) never call modules directly by name; they ask the module API.

Anatomy of a module
===================
A module declares *what it is*, *how to find it*, *what it can read*, and *its options* in
class attributes, and implements the verbs it supports in class methods.

.. list-table:: Class attributes
   :header-rows: 1
   :widths: 26 74

   * - Attribute
     - Purpose
   * - ``device_type``
     - Class of device: ``"PLC"``, ``"Relay"``, ``"RTU"``, ``"RTAC"``, ``"Power Meter"``, ...
       (``host.type``). Also becomes an alias, so ``-d plc`` selects every PLC module.
   * - ``vendor_id``, ``vendor_name``
     - Short and long vendor names (``"SEL"`` and ``"Schweitzer Engineering
       Laboratories"``). The vendor ID becomes an alias (``-d sel``).
   * - ``brand``, ``model``, ``supported_models``
     - Brand (``"ControlLogix"``), the default model when it can't be determined, and the
       models the module is known to work with.
   * - ``module_aliases``
     - Extra names for ``-d`` and the module API (``["clx", "controllogix"]``).
   * - ``ip_methods``, ``serial_methods``
     - How to identify the device on a network or serial port. See
       :ref:`identification-methods`.
   * - ``filename_patterns``, ``file_signatures``, ``can_parse_dir``
     - What the module can parse: case-insensitive file name globs, content signatures,
       and whether it accepts a whole directory. See :ref:`file-signatures`.
   * - ``default_options``
     - Default configuration for the module and the protocols it uses, overridable from
       the configuration file. See :ref:`module-options`.
   * - ``annotate_fields``
     - Fields to set on every device the module handles (for example a known OS name),
       applied by :meth:`~peat.device.DeviceModule.update_dev`.

.. list-table:: Methods to implement
   :header-rows: 1
   :widths: 26 74

   * - Method
     - Implement it to support
   * - ``_pull(cls, dev) -> bool``
     - ``peat pull``. Retrieve artifacts and data from the device and store them on
       ``dev``. Return ``True`` if the pull succeeded.
   * - ``_parse(cls, file, dev=None) -> DeviceData | None``
     - ``peat parse`` (and parsing during pulls). Read ``file`` (a
       :class:`~pathlib.Path`), create or use ``dev``, fill it in, and return it.
   * - ``_push(cls, dev, path, push_type) -> bool``
     - ``peat push``. Upload ``path`` (a file or directory) of type ``"config"`` or
       ``"firmware"``.
   * - identification functions
     - ``peat scan``. Class methods referenced by ``ip_methods``/``serial_methods`` that
       take a ``dev`` and return ``True`` when the device is positively identified.

The public ``pull()``, ``parse()``, and ``push()`` are implemented by the base class and
wrap your underscore methods with validation, logging, file bookkeeping, and
post-processing. Don't override them. Every module class gets a ``cls.log`` logger bound
with the module's name; use it for all messages (see :doc:`/contributing/logging`).

Walkthrough: the AwesomeTool module
===================================
This walkthrough builds a module for a fictional tool, "Awesome Tool", a command line
program that pulls information from PLCs and writes it to ``awesome_output.json``. The
finished module (``awesome_module.py``), an input file (``awesome_output.json``), and the
expected PEAT output (``awesome_output_expected_device-data-*.json``) are in
``examples/example_peat_module/`` in the repository, and the module is exercised by
``tests/test_awesome_module.py`` and by the CI builds of the executables.

.. note::
   Refer to the :doc:`API documentation <peat_api>` for the global variables (e.g.
   :attr:`config.OUT_DIR <peat.settings.Configuration.OUT_DIR>` and
   :attr:`state.elastic <peat.settings.State.elastic>`), constants (e.g.
   :data:`consts.START_TIME_UTC <peat.consts.START_TIME_UTC>`), and exception classes
   available to modules, and to :doc:`/design/configuration_and_state` for how the
   configuration works and how to add options.

The input data the module will process:

.. literalinclude:: ../../examples/example_peat_module/awesome_output.json
   :name: awesome_output_json
   :caption: awesome_output.json
   :language: json

The module. It is heavily commented; read it top to bottom, since the comments are the
guide:

.. literalinclude:: ../../examples/example_peat_module/awesome_module.py
   :name: awesome_module_py
   :caption: awesome_module.py
   :language: python

Things to notice:

- The class attributes describe the device and what the module can do; the parse-related
  ones (``filename_patterns``, ``file_signatures``) are what make ``peat parse`` choose
  this module for a file.
- ``_parse()`` reads the file, gets a ``DeviceData`` from the :data:`~peat.data.store.datastore`
  (or uses the one passed in during a pull), assigns simple fields directly, and uses
  :meth:`~peat.data.models.DeviceData.store` for lists of models (interfaces, services),
  linking services to interfaces with ``interface_lookup``. It always returns the device.
- ``_pull()`` checks the module's ``pull_methods`` option and the service status, verifies
  the device if it hasn't been, retrieves data with the :class:`~peat.protocols.http.HTTP`
  client, writes the raw artifact with :meth:`~peat.data.models.DeviceData.write_file`,
  and reuses ``cls.parse()`` to interpret it. Failures are logged and turned into a
  ``False`` return, never an unhandled exception, so other devices in the run proceed.
- The identification method is attached after the class definition as an
  :class:`~peat.api.identify_methods.IPMethod` with the protocol, default port,
  reliability, and the function to call.

Running the module:

.. code-block:: bash

   # "-d AwesomeTool": the module (matches the class name)
   # "-I awesome_module.py": import the module code
   # "-- ./awesome_output.json": the file to parse
   peat parse -d AwesomeTool -I awesome_module.py -- ./awesome_output.json

Example terminal output from running the included example module:

.. code-block:: console

   $ pdm run peat parse --no-logo -d AwesomeTool -I ./examples/example_peat_module/awesome_module.py -- ./examples/example_peat_module/awesome_output.json
   17:01:21.039 INFO    log_utils        Log file: peat_results/parse_default-config_2024-06-26_17-01-20_171942128019/logs/peat.log
   17:01:21.040 INFO    peat.init        Run directory: parse_default-config_2024-06-26_17-01-20_171942128019
   17:01:21.041 INFO    parse_api        Parsing 1 filepaths
   17:01:21.042 INFO    parse_api        Parsing AwesomeTool file '/home/cegoes/peat/examples/example_peat_module/awesome_output.json'
   17:01:21.050 INFO    utils            Saved parse summary to peat_results/parse_default-config_2024-06-26_17-01-20_171942128019/summaries/parse-summary.json
   17:01:21.050 INFO    parse_api        Completed parsing of 1 files in 0.01 seconds
   17:01:21.051 INFO    peat.cli_main    Finished run in 0.02 seconds at 2024-06-26 17:01:21.051042+00:00 UTC

The results in ``device-data-full.json``:

.. literalinclude:: ../../examples/example_peat_module/awesome_output_expected_device-data-full.json
   :name: awesome_module_output_example
   :caption: Output of the example PEAT module AwesomeTool
   :language: json

To try the scan and pull paths, serve the example directory over HTTP and point PEAT at
it:

.. code-block:: bash

   python3 -m http.server 8090 --directory examples/example_peat_module/
   peat scan -d AwesomeTool -I examples/example_peat_module/awesome_module.py -i localhost
   peat pull -d AwesomeTool -I examples/example_peat_module/awesome_module.py -i localhost

.. _identification-methods:

Identification methods
======================
Scanning is driven by the methods a module declares in ``ip_methods`` (network) and
``serial_methods`` (serial). Each is an :class:`~peat.api.identify_methods.IPMethod` or
:class:`~peat.api.identify_methods.SerialMethod`:

- ``identify_function``: a function taking a ``DeviceData`` and returning ``True`` on a
  positive identification. It should also record what it learned (description, firmware,
  services) on the device; PEAT's philosophy is to extract as much as possible from any
  data acquired.
- ``protocol``, ``transport``, ``default_port``: the service the method talks to. PEAT
  checks that the port is open before calling the method (unless ``--intensive-scan``),
  and the user can override the port per protocol or per host.
- ``type``: ``unicast_ip`` for methods that probe one host, ``broadcast_ip`` for methods
  that send a broadcast and return a *list* of responding hosts (see the ControlLogix
  module), or ``direct`` for serial.
- ``reliability``: 0 to 10. Be honest: 5 or below for methods with some flakiness (a
  Telnet banner), 6 and up for dependable ones (an HTTP or REST endpoint). PEAT runs
  methods from most to least reliable and stops at the first success.
- ``port_function`` (optional): a custom check for whether the port is open, for
  services that need special handling or are prone to toppling over when probed.

Guidelines:

- Prefer methods that are read-only, fast, and indistinguishable from the vendor's own
  software. Never log in or change state to identify a device.
- Use the device's configured port (``dev.options["<protocol>"]["port"]``) and timeout in
  the method, not hard-coded values, so users can override them.
- Catch exceptions inside the method, log at ``debug``/``warning``, and return ``False``.
- Set ``dev.description`` (vendor, brand, model, product), ``dev.firmware``, and
  ``dev.os`` when the identification reveals them, and store the service with status
  ``verified`` (the scan API does this for the method's own service).

.. _file-signatures:

File signatures
===============
``peat parse`` decides which module parses a file by matching the file's name against each
module's ``filename_patterns`` (shell-style globs, case-insensitive) and, if nothing
matches, the file's *contents* against each module's ``file_signatures``. Signatures let
PEAT recognize files with unexpected names, data piped on standard input, and files
carved from disk images or network traffic.

A :class:`~peat.file_signature.FileSignature` has a ``default_filename`` (used to name
the file when the data arrives without a name, for example from standard input) and one
or more checks that must **all** match:

- ``magic_number``: leading bytes as a hex string (``"d0cf11e0a1b11ae1"`` for OLE
  compound files such as SEL ``.rdb`` databases; ``"415058"`` for ``APX`` project files)
- ``xml_tags``: XML tag names that must appear (``("SCEPTRE",)`` or namespaced tags)
- ``substrings``: byte or text substrings that must appear in order (``("[INFO]", "FID")``
  for SEL ``CFG.TXT`` files)
- ``custom_check``: a function receiving the binary stream and returning a boolean, for
  anything else, such as decompressing and inspecting the contents

.. code-block:: python
   :caption: Signatures from the SEL relay module

   from peat.file_signature import FileSignature

   file_signatures = [
       FileSignature(default_filename="sel_relay.rdb", magic_number=olefile.MAGIC.hex()),
       FileSignature(default_filename="cfg.txt", substrings=("[INFO]", "FID")),
       FileSignature(
           default_filename="SET_61850.CID",
           magic_number="7801",        # zlib stream
           custom_check=is_cid,        # decompress and look for IEC 61850 SCL
       ),
   ]

Keep ``filename_patterns`` as well: name matching is cheap, keeps existing behavior, and
takes precedence; signatures are the fallback. Make signatures specific enough not to
claim other modules' files (a bare ``{`` magic number would match every JSON file), and
add a unit test that your signature matches your sample files and rejects others
(``tests/test_file_signature.py`` has examples).

Pulling
=======
A ``_pull()`` typically:

#. Reads its options from ``dev.options``, a merged view of the module's
   ``default_options``, the configuration file's ``device_options``, and the host's
   ``options``. Honor a ``pull_methods`` list so users can restrict which protocols you
   use, and check ``dev.service_status({"protocol": ...})`` before using a protocol whose
   port the scan found closed.
#. Connects with the protocol clients in :mod:`peat.protocols` (:class:`~peat.protocols.ftp.FTP`,
   :class:`~peat.protocols.telnet.Telnet`, :class:`~peat.protocols.http.HTTP`, SSH,
   :mod:`~peat.protocols.serial`, SNMP, :class:`~peat.protocols.mysql.MySQL`, ...) or
   device-specific wrappers, using ``with`` blocks so connections are closed cleanly.
#. Writes every retrieved artifact, unmodified, with
   :meth:`dev.write_file() <peat.data.models.DeviceData.write_file>` and records it with
   ``dev.store("files", File(...))`` so it appears in the data model (with hashes) and
   the ``ot-device-files`` index. Users expect to find the raw files in the device's
   output directory.
#. Parses what it retrieved, ideally by calling ``cls.parse(path, dev)`` so the same
   parser serves ``peat parse``.
#. Records which protocols succeeded in ``dev.successful_pulls`` and returns ``True`` if
   the pull was useful. Log failures at ``warning`` (best-effort data) or ``error``
   (critical data) and keep going; only raise :class:`~peat.consts.DeviceError` when
   continuing could harm the device.

Store list-type data with :meth:`~peat.data.models.DeviceData.store`, which merges
duplicates and can link services to interfaces. Put vendor-specific data that has no
field in the model in ``dev.extra`` (it's exported under ``host.extra.<module>``), rather
than inventing fields. Dates should be timezone-aware :class:`~datetime.datetime` objects
in :term:`UTC`; :func:`peat.utils.parse_date` handles most formats.

Pushing
=======
``_push(dev, path, push_type)`` receives the verified device, the file or directory to
upload, and ``"config"`` or ``"firmware"``. Validate the input (does the file look like
what the device expects?), perform the upload with the device's native mechanism, apply
it if required (for example a restart, behind an option such as
``restart_after_push``), and record the outcome as an :class:`~peat.data.models.Event`
with ``action="file_push"`` and ``outcome="success"`` or ``"failure"``. Pushes change
devices; be conservative, and document the exact behavior in the module's docstring and
options.

.. _module-options:

Options and configuration
=========================
Declare the module's options in ``default_options``. Module-specific options go under a
key named for the module (``"sel"``, ``"openplcv4"``, ``"awesometool"``), and protocol
settings under the protocol name, so that users configure ports and credentials
consistently across modules:

.. code-block:: python

   class SELRelay(DeviceModule):
       default_options = {
           "ymodem": {"baudrate": 57600},
           "web": {"user": "", "pass": ""},
           "sel": {
               "pull_methods": ["http", "ftp", "telnet"],
               "restart_after_push": False,  # Restart the relay after a config push
           },
       }

Protocol defaults that PEAT already knows (``ftp``, ``telnet``, ``http``, ``https``,
``ssh``, ``snmp``, ... ports and timeouts) are in :mod:`peat.data.default_options` and
don't need repeating unless your device uses a non-standard port (OpenPLC declares
``"https": {"port": 8443}``). The scan API uses the configured port for the method's
protocol when checking ports, and reverts it afterwards, so a module's custom port doesn't
affect other modules.

Document every option, with its default and a description, in
``examples/peat-config.yaml`` under ``device_options``. That file is the configuration
reference in the documentation and the only way users find out about your options.
Consider also adding an example configuration (``examples/openplc-config.yaml`` is a good
model) when the module needs credentials to be useful.

Testing a module
================
Modules are tested at three levels; add at least the first for every module.

**Unit tests** in ``tests/modules/<vendor>/`` with sample files in a ``data_files/``
sub-directory: parse known inputs and compare the exported device data against expected
JSON (the ``datapath`` fixture and ``deepdiff`` make this easy; see
``tests/modules/sandia/`` and ``tests/test_awesome_module.py``). Test identification
functions and pulls with mocked protocols (``requests-mock`` for HTTP, ``pytest-mock``
for others). Keep sample files small and free of sensitive data.

**Container-based integration tests** for devices that have a software implementation.
The OpenPLC module's tests (``tests/modules/openplc/test_openplcv4_container.py``) run
the real module against the official OpenPLC Runtime container: they are marked with
``pytestmark = pytest.mark.container``, skipped unless ``pytest --run-container`` is
given, and run in CI by the ``Container Tests`` workflow, which starts the container,
seeds a user through its API, then runs the tests. The MySQL protocol tests use the same
mechanism with a MySQL service container. This is the gold standard when a simulator or
software runtime exists for your device.

**Live tests** against physical devices (``@pytest.mark.gitlab_ci_only``) run only in
Sandia's internal CI against the PEAT device rack, and are skipped on GitHub.

See :doc:`/contributing/testing` for running the tests and the markers.

Adding a module to PEAT
=======================
Contributing a module to PEAT's codebase, step by step. The OpenPLC Runtime v4 module
(`pull request #72 <https://github.com/sandialabs/PEAT/pull/72>`__) is a complete,
recent example of everything below in one change.

#. **Create the vendor directory** ``peat/modules/<vendor>/`` if it doesn't exist, with
   a sub-directory if the device needs many source files (``peat/modules/schneider/m340/``).
#. **Create the module class** in ``peat/modules/<vendor>/<device>.py`` (lower-case file
   name), following the walkthrough above. Add a module docstring with a description,
   usage examples, and the authors (with contact information), per the
   :doc:`/contributing/code_guidelines`.
#. **Export the class** from each ``__init__.py`` up the package tree:

   .. code-block:: python

      # peat/modules/schneider/ion/__init__.py
      from .ion import ION

      # peat/modules/schneider/__init__.py
      from .ion import ION

      # peat/modules/__init__.py
      from peat.modules.schneider import ION

   The module manager discovers modules from :mod:`peat.modules`, so this is what makes
   the module built in.
#. **Add CLI usage examples** to the relevant ``*_examples`` strings in
   :mod:`peat.cli_args` (``scan_examples``, ``pull_examples``, ...), which are shown by
   ``peat <command> --examples`` and included in the documentation.
#. **Document the options** in ``examples/peat-config.yaml`` (and an example configuration
   file if credentials are required).
#. **Add the device** to the supported devices table,
   ``docs/getting_started/supported_devices.csv``: vendor, device, supported functions,
   protocols, tested firmware versions, notes (including the module class reference and
   the device's OS if known), and an honest :term:`TRL` estimate.
#. **Write tests** as described above, and example outputs under ``examples/`` if they
   help users (``examples/example-openplc-scan-summary.json``).
#. **PyInstaller**: if the module imports a Python package or standard library module not
   already used by PEAT, add it to ``hidden_imports`` in ``distribution/peat.spec`` so
   the executable includes it. Otherwise users of the executable get
   ``Failed to import mypackage.mymodule: No module named 'csv'``. New third-party
   dependencies go in ``pyproject.toml`` with a comment saying which module needs them.
#. **Document the device**, optionally, with a page under ``docs/reference/devices/``
   (``sel.rst``, ``siemens.rst``, and ``openplc.rst`` are examples) covering
   communications, data collected, file formats, options, and developer notes, and add it
   to ``docs/reference/devices/index.rst``. Add the module's automodule entry to
   ``docs/developer/device_modules.rst``.
#. **Changelog**: add a news fragment in ``newsfragments/`` (see
   :doc:`/contributing/index`).

Lessons from recent modules
---------------------------
The OpenPLC module contribution surfaced a few things worth knowing before you start:

- **Custom ports need care.** OpenPLC's API lives on HTTPS port 8443. Declaring the port
  in ``default_options["https"]["port"]`` and in the ``IPMethod.default_port`` is correct;
  the scan API now scopes configured ports to ``(protocol, port)`` pairs and restores the
  original value after each check, so one module's port no longer "pollutes" another's
  (a bug fixed in the same pull request).
- **Build identification on a stable, read-only endpoint** (``GET /api/version``), and
  keep authentication for the pull.
- **Cache sessions** (a JWT or cookie) across the requests of a pull instead of logging
  in repeatedly, and respect global protocol options such as the HTTPS port.
- **Save logs and status as both files and events**: write the raw runtime log with
  ``write_file()`` *and* parse its lines into :class:`~peat.data.models.Event` entries,
  so users get the original and a searchable timeline.
- **Ship a reproducible test.** A container-based test with a public image makes a module
  verifiable by every contributor and by CI, which is worth more than any amount of
  description.
- **Include an example configuration and example outputs**, and a documentation page.
  They double as acceptance criteria for reviewers.

Development tips
================
When developing a module, write a small script that invokes the module directly instead
of going through the CLI. It starts faster, produces less unrelated output, lets you attach
a debugger, gives fine-grained control over which methods run, and makes it easy to drop
into the interpreter (the :term:`REPL`) or a `Jupyter notebook
<https://realpython.com/jupyter-notebook-introduction/>`__:

.. code-block:: python
   :caption: mymodule_testing.py

   from pathlib import Path
   from peat import SELRelay, initialize_peat

   initialize_peat({"VERBOSE": True, "DEBUG": 1})

   input_path = Path("examples/devices/sel/sel_351/set_all.txt")
   dev = SELRelay.parse(input_path)
   print(dev.export())

.. code-block:: console

   $ pdm run python mymodule_testing.py          # Run and exit

   $ pdm run python -i mymodule_testing.py       # Then stay in the interpreter
   >>> dev.firmware
   >>> other = SELRelay.parse(Path("some_other_file.txt"))
   >>> from peat import datastore
   >>> pull_dev = datastore.get("192.0.2.22")
   >>> SELRelay.pull(pull_dev)
   >>> pull_dev.firmware.version

Debugging from the CLI
----------------------
Two command line arguments help when the problem only appears through the CLI:

- ``--pdb`` (``--launch-debugger``): initialize, then break into the Python debugger
  (``pdb``) before executing the command. ``interact`` inside pdb opens a REPL.
- ``--repl`` (``--launch-interpreter``): initialize, then open the interactive
  interpreter with PEAT configured. Useful for exploring the API from the executable
  distribution, inspecting state, or testing a hypothesis under specific conditions.

Also useful: ``-VVV`` for protocol-level logging, the ``telnet.log`` and ``enip/``
transcripts in the run directory, and ``--dry-run`` to check that your module is imported
and selected without touching a device.
