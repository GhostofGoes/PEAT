.. _peat-device-modules:

********************************
Using third-party device modules
********************************
PEAT implements support for each device as a semi-standalone *device module*: a Python
class that encapsulates everything PEAT knows about a kind of device (for example
:class:`~peat.modules.sel.sel_relay.SELRelay` for SEL relays). While PEAT includes a large
selection of modules, additional modules can be **imported at runtime** with no changes to
PEAT's code, including with the pre-built executables and the container. These are
variously called "PEAT device modules", "PEAT modules", "third-party modules", or
"runtime modules".

Use cases for runtime-loaded modules:

- Modules that can't be open-sourced because of sensitivities (device-specific knowledge,
  customer environments)
- Modules you write yourself for a device, or for the output of a tool you use
- Trying a modified or newer version of a built-in module without rebuilding PEAT

Writing a module requires only a text editor and some Python. The
:doc:`/developer/module_developer_guide` walks through creating one, using the example
module in the repository.

Importing modules
=================
Use ``-I`` (``--import-modules``) with one or more paths. A path can be a single ``.py``
file containing one or more :class:`~peat.device.DeviceModule` subclasses, or a directory
(a Python package with an ``__init__.py``) containing them. Modules can also be listed in
the configuration file's ``additional_modules`` option.

.. code-block:: bash

   # Parse the output of the fictional "awesome-tool" with the AwesomeTool example module
   #   -d AwesomeTool : the module to use (the name of its Python class)
   #   -I awesome_module.py : the file to import the module from
   #   -- awesome_output.json : the file to parse
   peat parse -d AwesomeTool -I ./examples/example_peat_module/awesome_module.py -- ./examples/example_peat_module/awesome_output.json

   # Import a directory of modules, then scan with one of them
   peat scan -I ./my_peat_modules/ -d MyDevice -i 192.0.2.0/24

   # Several paths
   peat pull -I ./modules/vendor_a.py ./modules/vendor_b/ -i 192.0.2.0/24

   # Confirm the module was imported
   peat parse -I ./awesome_module.py --list-modules

Imported modules behave exactly like built-in ones: they can be selected with ``-d`` by
class name or alias, they participate in scans if they define identification methods, and
their options go in ``device_options`` under the key the module defines.

.. code-block:: yaml
   :caption: Importing from a configuration file

   additional_modules:
     - "./my_peat_modules/"
     - "/opt/peat/extra/sensitive_device.py"

Modules and the executable
==========================
The bundled executable contains only the Python standard library modules and third-party
packages that PEAT itself uses. A runtime module that imports a package PEAT doesn't
include (or an unusual standard library module) fails with an error such as
``Failed to import mypackage.mymodule: No module named 'csv'``. Options:

- Stick to the libraries PEAT ships with: the standard library, ``requests``,
  ``beautifulsoup4``, ``lxml``, ``pydantic``, ``scapy``, ``pyserial``, ``paramiko``,
  ``pysnmp``, and the others listed in :doc:`/developer/dependencies`.
- Use the Python package instead of the executable, where any installed package is
  available.
- Add the needed modules to ``hidden_imports`` in ``distribution/peat.spec`` and build your
  own executable (see :doc:`/contributing/building`).

With the container, mount the module into the container and import it from there:

.. code-block:: bash

   docker run --rm -i -v "$(pwd)/my_module.py:/my_module.py:ro" -v "$(pwd)/peat_results:/peat_results" \
       ghcr.io/sandialabs/peat parse -I /my_module.py -d MyDevice -- /peat_results/some_file.txt

Trust
=====
A module is Python code that runs with PEAT's permissions, often as root or Administrator,
on a host with access to control system networks. Only import modules from sources you
trust, and review them like any other code.
