***************
Python examples
***************
Short, self-contained examples of using PEAT as a Python library. They assume PEAT is
installed in the current Python environment (see :doc:`/getting_started/install`) or that
you're running inside the development environment (``pdm run python``). Most examples
call :func:`~peat.init.initialize_peat` first; it isn't required, but it sets up logging
and the output directories the same way the command line does.

.. tip::
   Replace the example addresses (``192.0.2.x``, which are reserved for documentation) with
   your devices, and remember that pulls and scans touch live equipment. ``--dry-run``
   has no equivalent in the API, so test against a lab device first.

Setup and configuration
=======================

Initializing PEAT
-----------------
.. code-block:: python

   from peat import initialize_peat, config

   # Keys match the configuration options (case-insensitive). These override
   # environment variables and configuration files, like command line arguments do.
   initialize_peat({"DEBUG": 1, "VERBOSE": True, "RUN_NAME": "api-example"})

   # Options can also be changed at any time
   config.MAX_THREADS = 50
   print(config.RUN_DIR)  # peat_results/api-example

Loading a configuration file
----------------------------
.. code-block:: python

   from peat import initialize_peat

   # "config_file" is the same option as "-c" on the command line
   initialize_peat({"config_file": "examples/peat-config-simple.yaml", "DEBUG": 1})

Using PEAT without writing files
--------------------------------
.. code-block:: python

   from peat import initialize_peat

   # Disable all file output (results are only returned in memory)
   initialize_peat({"OUT_DIR": None, "RUN_DIR": None})

The high-level API: scan, pull, parse
=====================================
These functions mirror the command line and return the same :doc:`summaries
</reference/summaries>` as dictionaries.

Scanning a network
------------------
.. code-block:: python

   from pprint import pprint
   from peat import initialize_peat, scan

   initialize_peat({"VERBOSE": True})

   # Targets accept everything "-i" does: hosts, CIDR networks, ranges, files.
   # "unicast_ip" is the normal scan type; "broadcast_ip" and "serial" also exist.
   summary = scan(["192.0.2.0/24"], "unicast_ip", device_types=["sel", "controllogix"])

   print(f"{summary['num_hosts_verified']} devices identified in {summary['scan_duration']:.1f}s")
   for host in summary["hosts_verified"]:
       print(host["ip"], host["description"]["product"], host["peat_module"])

   # Hosts that answered but PEAT couldn't identify
   pprint(summary["hosts_online"])

Pulling from devices
--------------------
.. code-block:: python

   from peat import initialize_peat, pull

   initialize_peat({"RUN_NAME": "nightly-pull", "config_file": "site.yaml"})

   # A pull scans first, then pulls from the identified devices
   summary = pull(["192.0.2.0/24"], "unicast_ip", device_types=["selrelay"])
   if summary is None:
       raise SystemExit("pull failed, see the log")

   for device in summary["pull_results"]:
       print(device["id"], device["firmware"].get("version"))

   # Skip the scan phase and pull directly from the hosts in the configuration file
   summary = pull([], "unicast_ip", device_types=[], skip_scan=True)

Parsing files
-------------
.. code-block:: python

   from pathlib import Path
   from peat import initialize_peat, parse

   initialize_peat({"RUN_NAME": "parse-backups"})

   # Parse a directory (searched recursively) with the modules that match each file.
   # device_types=None uses every module that can parse.
   summary = parse(Path("relay_backups/"), device_types=["sel"])

   print(summary["num_parse_successes"], "parsed,", summary["num_parse_failures"], "failed")
   for result in summary["parse_results"]:
       print(result["name"], "->", result["module"], result["results"].get("id"))

Device interaction with the module API
======================================
Device modules (subclasses of :class:`~peat.device.DeviceModule`) operate on
:class:`~peat.data.models.DeviceData` objects obtained from the
:data:`~peat.data.store.datastore`. This gives finer control than the high-level API.

Pull from a Modicon M340 PLC
----------------------------
.. code-block:: python

   from pprint import pprint
   from peat import M340, datastore, initialize_peat

   initialize_peat({"DEBUG": 1, "VERBOSE": True})

   dev = datastore.get("192.0.2.230")   # Creates the DeviceData if it doesn't exist
   pull_succeeded = M340.pull(dev)      # bool, True if the pull was successful
   print(pull_succeeded)
   pprint(dev.export())                 # The data as a dictionary
   dev.export_to_files()                # Write device-data-*.json to the run directory

Pull from an SEL relay with credentials
---------------------------------------
.. code-block:: python

   from peat import SELRelay, datastore, initialize_peat

   initialize_peat({})

   dev = datastore.get("192.0.2.22")

   # Per-device options, equivalent to the "options" of a host in the configuration file
   dev._runtime_options["ftp"] = {"user": "FTPUSER", "pass": "TAIL"}
   dev._runtime_options["sel"] = {"pull_methods": ["ftp", "telnet"]}

   if SELRelay.pull(dev):
       print(dev.firmware.id)                       # e.g. SEL-351S-6-R516-V2-Z004004-D20190111
       for service in dev.service:
           print(service.protocol, service.port, service.status)

Push firmware to a ControlLogix PLC
-----------------------------------
.. code-block:: python

   from pathlib import Path
   from peat import ControlLogix, datastore, initialize_peat

   initialize_peat({})

   fw_path = Path("clx-firmware.dmk")
   dev = datastore.get("192.0.2.200")
   push_succeeded = ControlLogix.push(dev, fw_path, "firmware")  # or "config"
   print(push_succeeded)

Identify a single device
------------------------
.. code-block:: python

   from peat import SELRelay, datastore, initialize_peat

   initialize_peat({})
   dev = datastore.get("192.0.2.22")

   # Run the module's identification methods, most reliable first
   for method in sorted(SELRelay.ip_methods, key=lambda m: m.reliability, reverse=True):
       if method.identify_function and method.identify_function(dev):
           print(f"Identified via {method.protocol}: {dev.description.full}")
           break

Parsing
=======

Parse an SEL project file
-------------------------
An ``.rdb`` file exported from AcSELerator QuickSet, or a ``SET_ALL.TXT`` from a relay:

.. code-block:: python

   from pathlib import Path
   from peat import SELRelay

   dev = SELRelay.parse(Path("breaker-1.rdb"))
   print(dev.export())

   dev = SELRelay.parse(Path("relay_files/SET_ALL.TXT"))
   print(dev.firmware.id, dev.description.model)

Parse an M340 project file
--------------------------
Extracts the Structured Text logic and configuration from an ``.apx`` project file:

.. code-block:: python

   from pathlib import Path
   from peat import M340

   dev = M340.parse(Path("project-file.apx"))
   print(dev.logic.parsed)

Parse an L5X file
-----------------
A ``.L5X`` file exported from Rockwell Studio 5000:

.. code-block:: python

   from pprint import pprint
   from pathlib import Path
   from peat import L5X

   dev = L5X.parse(Path("basetest.L5X"))
   pprint(dev.export())

Parse data from memory
----------------------
:meth:`~peat.device.DeviceModule.parse` also accepts raw bytes, which is useful when the
data came from somewhere other than a file (a network capture, a database, an API):

.. code-block:: python

   from peat import SELRelay

   raw = open("SET_ALL.TXT", "rb").read()
   dev = SELRelay.parse(raw)

Working with device data
========================

Reading and storing values
--------------------------
.. code-block:: python

   from peat import DeviceData, Interface, Service

   dev = DeviceData(ip="192.0.2.10")

   # Simple attributes are assigned directly
   dev.os.version = "7"
   dev.description.vendor.name = "ACME, Inc."

   # Lists of models are stored with store(), which merges duplicates
   dev.store("interface", Interface(ip="192.0.2.10", mac="00:11:22:33:44:55"))
   dev.store("service", Service(protocol="modbus", port=502, transport="tcp"))

   # ...and searched with retrieve()
   modbus = dev.retrieve("service", {"protocol": "modbus"})
   print(modbus.port)

Exporting
---------
.. code-block:: python

   data = dev.export()            # dict in the data model structure
   summary = dev.export_summary() # dict without large fields
   text = dev.json(sorted=True)   # JSON string
   doc = dev.elastic()            # dict shaped for the Elasticsearch schema
   dev.export_to_files()          # device-data-*.json in the run directory
   dev.export_to_elastic()        # push to the configured Elasticsearch server

Comparing two pulls
-------------------
.. code-block:: python

   import json
   from deepdiff import DeepDiff  # pip install deepdiff

   before = json.load(open("peat_results/september/devices/192.0.2.22/device-data-summary.json"))
   after = json.load(open("peat_results/october/devices/192.0.2.22/device-data-summary.json"))

   # Ignore fields that change every run
   diff = DeepDiff(before, after, exclude_paths=["root['created']"])
   print(diff.pretty())

The module API
==============

Listing modules, aliases, and vendors
-------------------------------------
.. code-block:: python

   import json
   from peat import module_api

   print(module_api.names)           # ["ControlLogix", "Easygen3500XT", ...]
   print(module_api.aliases)         # ["2301e", "clx", "plc", "sel", ...]
   print(module_api.alias_mappings)  # {"sel": ["SEL3620", "SELRTAC", "SELRelay"], ...}

   # Only modules that can scan networks
   print(module_api.filter_names("ip_methods"))

   # Vendor ID and name for every module, as JSON
   identifiers = {
       name: {"id": device.vendor_id, "name": device.vendor_name}
       for name, device in module_api.modules.items()
   }
   print(json.dumps(identifiers, indent=4))

Looking up modules
------------------
.. code-block:: python

   from peat import module_api

   mod = module_api.get_module("selrelay")           # by name or alias, case-insensitive
   mods = module_api.lookup_types(["sel", "m340"])   # several names/aliases -> classes
   parsers = module_api.lookup_types(["rockwell"], filter_attr="filename_patterns")

Importing a third-party module
------------------------------
.. code-block:: python

   from peat import module_api, parse

   module_api.import_module("examples/example_peat_module/awesome_module.py")
   summary = parse("examples/example_peat_module/awesome_output.json", device_types=["AwesomeTool"])

Writing a module is covered in the :doc:`module_developer_guide`.

Elasticsearch
=============
.. code-block:: python

   from peat import Elastic, initialize_peat, state

   # Connect at initialization (equivalent to "-e")
   initialize_peat({"ELASTIC_SERVER": "http://localhost:9200/"})
   print(state.elastic.type)   # "Elasticsearch" or "OpenSearch"

   # Or create a client directly
   es = Elastic("http://user:pass@elastic.example.net:9200/")
   es.ping()
   es.push("peat-notes", {"message": "custom document", "tags": ["example"]})

Generating a configuration file
===============================
.. code-block:: python

   from peat import generate_simple_config

   hosts = [
       ("192.0.2.22", "feeder-7", "SELRelay"),
       ("192.0.2.40", "plc-1", "M340"),
   ]
   yaml_text = generate_simple_config(hosts)
   open("site.yaml", "w").write(yaml_text)

Helper scripts
==============
The repository's ``scripts/`` directory contains small, runnable examples of the API:
``module_vendor_ids.py`` (the vendor listing above) and ``gen_rtac_events.py`` (logs into
an SEL RTAC repeatedly with :class:`~peat.modules.sel.sel_http.SELHTTP` to generate
system log events for testing).
