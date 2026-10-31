*********
Configure
*********

.. warning::
   The configuration values shown here are intended to demonstrate how to configure PEAT. **We STRONGLY recommend customizing the settings for your use case and environment.** The best example of this is limiting the PEAT device modules used to only those present in the environment, e.g. ``-d sel`` if using PEAT with SEL-manufactured devices.

Configuring PEAT
================
PEAT has a number of global settings that are configurable via several methods, including command line arguments, environment variables, and a :term:`YAML` file.

**If a value is configured via multiple methods, the order of precedence determines what value is actually used.**

.. _config-precedence:

Order of precedence for configuration
-------------------------------------
1. Command line arguments (example: ``-VV``)
2. Environment variables (example: ``export PEAT_DEBUG=2``)
3. The section of the configuration file for the command being run (example: ``pull:``, see :ref:`config-command-sections`)
4. Configuration file (example: ``-c peat-config.yaml``)
5. Default values

If using the Python API, e.g. ``config.DEBUG=1`` or values passed to ``initialize_peat(...)``, those are applied at the same level as command line arguments and override environment variables and the config file.

.. important::
   :attr:`EXCLUDED_MODULES <peat.settings.Configuration.EXCLUDED_MODULES>` is an exception to the order of precedence. Exclusions from all sources are **combined**: a source with a higher precedence can add exclusions, but can't remove exclusions from a source with a lower precedence. For example, ``-x M340`` on the command line doesn't remove a "never touch 192.0.2.200" rule in the config file. Refer to :ref:`config-excluded-modules`.


YAML configuration file
=======================
PEAT can be configured using a :term:`YAML` file. This file can be provided on the :term:`CLI` using the ``-c`` argument, for example ``peat scan -c peat-config.yaml``.

Values loaded from the file override the default values, but can be overridden by environment variables and command line arguments. In other words, options set in a config file have lower precedence than those set via command line args or environment variables.

Refer to :ref:`peat-config` for the available configuration options.

Config file usage examples
--------------------------
.. code-block:: bash

   peat scan -c ./examples/peat-config.yaml -d clx -i 192.0.2.0/24
   peat pull -c ./examples/peat-config.yaml -d ion sel -i 192.0.2.0/24
   peat push -c ./examples/peat-config.yaml -d selrelay -i 192.0.2.1 -- ./SET_1.TXT
   peat parse -c ./examples/peat-config.yaml -d selrelay ./SET_ALL.TXT


Walkthrough of the YAML config
==============================
The file starts with a ``metadata`` section. This is metadata about the config file itself, including the ``name`` of the config, a human-readable ``description``, the name of the original ``author``, timestamp of when it was ``created``, and timestamp of when it was ``updated``. ``name`` should be set, the others are optional but recommended.

.. code-block:: yaml
   :caption: Metadata example

   metadata:
     name: "simple-peat-config"
     description: "Simplified PEAT configuration with all comments removed"
     author: "cegoes"
     created: "May 22nd, 2024"
     updated: ""


Most of the top-level keys are standard config options, and most can be specified via command line args or environment variables, with a few exceptions (notable example are a lot of the elastic options aren't CLI-configurable to reduce complexity and size of ``--help``). Examples include ``resolve_ip``, ``print_results``, ``elastic_server``, ``debug``, and others.

.. code-block:: yaml
   :caption: Examples of standard config options

   verbose: false
   quiet: false
   print_results: false
   no_color: false
   no_logo: false
   assume_online: false
   max_threads: 260
   default_timeout: 5.0


The ``pillage`` section is the configuration for PEAT Pillage, refer to :ref:`pillage-config`.

The ``device_options`` section are settings for modules or protocols that are applied to everything in this PEAT run. In other words, it's global/universal, it's not on a per-host basis. Generally speaking, module/vendor specified methods have a dedicated key, e.g. ``sel`` for SEL devices (:class:`~peat.modules.sel.sel_relay.SELRelay` and :class:`~peat.modules.sel.sel_rtac.SELRTAC` modules), ``sage`` for the :class:`~peat.modules.schneider.sage.sage.Sage` module, etc. Then, there are protocol-specific options, e.g. ``telnet``, ``ssh``, etc. The protocol-specific options are usually port, timeout, login credentials, and any other protocol-specific options (such as SSH key paths).

.. code-block:: yaml
   :caption: Simple example forcing ``telnet`` to be used for pulls from any SEL devices.

   device_options:
     sel:
       pull_methods:
         - telnet


The ``hosts`` section is a list of hosts that will be scanned/pulled/interrogated by PEAT. Think of it as a inventory of devices. PEAT will use the information about these those to tune it's scanning parameters. Additionally, this is where per-host configurations are set, notably login credentials, as well as any other settings that need to be set for a particular host.

.. code-block:: yaml
   :caption: Example of the hosts section

   hosts:
   - label: "SEL-351S"
     comment: "SEL-351S Protection System in building XXX"
     identifiers:
       ip: 192.0.0.220
       mac: 00:30:A7:11:12:13
       serial_port: /dev/ttyUSB0
     peat_module: "SELRelay"
     options:
       ftp:
         user: "FTPUSER"
         pass: "TAIL"
   - label: "SEL-351"
     comment: "SEL-351 Protection System in building XXX"
     identifiers:
       ip: 192.0.0.221
       mac: 00:30:A7:11:12:14
     peat_module: "SELRelay"
     options:
       ftp:
         user: "FTP"
         pass: "TAIL"
       sel:
         never_download_dirs:
           - EVENTS


It's important to keep in mind that config options are not consistent. PEAT modules have evolved over time and they don't always follow the same way of doing things as other modules, especially those modules that existed before the YAML config was a thing (YAML config was introduced in late 2021). If you're uncertain of a option's behavior, refer to the reference config, and the module's class definition if needed.


.. _config-device-types:

Choosing PEAT modules (``device_types``)
========================================
The PEAT modules used by a command can be chosen with the ``-d`` command line argument, the :attr:`device_types <peat.settings.Configuration.DEVICE_TYPES>` option in the config file (at the top level or in a :ref:`command section <config-command-sections>`), or the ``PEAT_DEVICE_TYPES`` environment variable. The values are the same for all of them: names of PEAT modules (e.g. ``SELRelay``) or aliases (e.g. ``sel``, ``plc``, ``all``). Run ``peat scan --list-all`` to list the modules and aliases.

The ``-d`` argument has precedence over the other sources. If device types aren't set anywhere:

- ``scan``, ``pull``, and ``parse`` use all modules (``all``). For ``parse``, if modules are imported with ``-I`` and no device types are set, only the imported modules are used.
- ``push`` fails with an error, since a push should always use a specific module. If the device types for a push come from the config file or an environment variable instead of ``-d``, PEAT logs a warning.

Device types that don't match any module or alias are ignored, with a warning. Device types are ignored when a host file (``-f``) is used, since the modules to use are read from the host file.

When PEAT is used as a Python package, the scan, pull, and parse functions (e.g. :func:`peat.api.scan_api.scan`) use the ``device_types`` option (and ``PEAT_DEVICE_TYPES``) if they're called without device types (``device_types=None``).

.. code-block:: bash

   # These are equivalent
   peat scan -d sel controllogix -i 192.0.2.0/24
   PEAT_DEVICE_TYPES="sel,controllogix" peat scan -i 192.0.2.0/24
   peat scan -c config.yaml -i 192.0.2.0/24  # with "device_types: [sel, controllogix]"

.. _config-excluded-modules:

Excluding PEAT modules (``excluded_modules``)
=============================================
PEAT modules can be excluded from a run, either for all targets or only for specific targets. This is useful for devices that are known to react badly to a module (e.g. a fragile device that shouldn't be scanned at all), or for modules that shouldn't be used in an environment. Exclusions are configured with the :attr:`excluded_modules <peat.settings.Configuration.EXCLUDED_MODULES>` option, the ``PEAT_EXCLUDED_MODULES`` environment variable, or the ``-x``/``--exclude-modules`` command line argument (scan, pull, push, and parse).

.. code-block:: yaml
   :caption: Example of excluded_modules

   excluded_modules:
     ControlLogix: true          # Never use the ControlLogix module
     SEL: [192.0.2.5, 192.0.2.6] # Don't use the SEL modules for these IPs
     M340:                       # Don't use the M340 module for these targets
       - 192.0.2.64/26           # A subnet
       - 192.0.2.10-20           # A range of IPs
       - line-3-plc              # The label of a host in "hosts"
     all: [192.0.2.200]          # Don't use ANY module for this IP

The values that are accepted:

.. list-table::
   :header-rows: 1
   :widths: 20 40 40

   * - Source
     - Example
     - Meaning
   * - YAML or JSON file
     - ``{ControlLogix: true, SEL: [192.0.2.5, 192.0.2.6]}``
     - ``true`` excludes the module for all targets, a list excludes it for those targets
   * - YAML or JSON file
     - ``[ControlLogix, M340]``
     - Exclude these modules for all targets (same as ``{ControlLogix: true, M340: true}``)
   * - YAML file
     - ``ControlLogix:`` (no value)
     - Same as ``true``
   * - YAML file
     - ``SEL: "192.0.2.5, 192.0.2.6"``
     - Same as ``SEL: [192.0.2.5, 192.0.2.6]``
   * - YAML file
     - ``SEL: false``
     - Nothing is excluded. This never removes an exclusion from another source.
   * - Environment variable
     - ``PEAT_EXCLUDED_MODULES="ControlLogix SEL=192.0.2.5,192.0.2.6"``
     - Whitespace-separated, same format as ``-x``. Whitespace next to ``,`` and ``=`` is ignored, so ``SEL=192.0.2.5, 192.0.2.6`` also works. Use the JSON form for names that contain spaces.
   * - Environment variable
     - ``PEAT_EXCLUDED_MODULES='{"ControlLogix": true, "SEL": ["192.0.2.5"]}'``
     - A JSON (or YAML) mapping or list
   * - Command line
     - ``-x ControlLogix -x SEL=192.0.2.5,192.0.2.6 -x m340,sel3620``
     - ``NAME`` (or ``NAME1,NAME2``) excludes for all targets, ``NAME=TARGET[,TARGET...]`` excludes for those targets. Use ``-x`` multiple times for multiple rules.

How exclusions work:

#. **Names** are PEAT module names or aliases, without regard to case, and are resolved when the command runs, so modules imported with ``-I`` or ``additional_modules`` can be excluded. Aliases exclude every module they match, e.g. ``sel`` excludes the ``SELRelay``, ``SELRTAC``, and ``SEL3620`` modules, and ``all`` matches every module. **PEAT refuses to run if a name doesn't match any module or alias**, for example a misspelled name (``-x ControlLgix``) or a target in the place of a name (``192.0.2.6`` in ``SEL=192.0.2.5 192.0.2.6``). The error says which name is wrong. A ``false`` rule for an unknown name is a no-op, and isn't an error.
#. **Rules for the same module are combined**: ``true`` wins over a list of targets, lists of targets are joined, and ``false`` never removes anything. For example, ``{sel: true, SELRelay: false}`` still excludes ``SELRelay``. To exclude only some of the modules matched by an alias, list the modules by name.
#. **Exclusions from all sources are combined** (the config file, the :ref:`command section <config-command-sections>`, the environment variable, and ``-x``). Unlike other options, exclusions are never removed by a source with a higher precedence. This is deliberate, so that rules for devices that must not be touched aren't lost by accident.
#. **Targets** use the same format as ``-i``, with a few additions. They're interpreted in this order:

   #. The label of a host in ``hosts`` (case-insensitive), which matches the host's identifiers (``ip``, ``mac``, ``serial_port``, ``hostname``, and ``name``)
   #. A MAC address, e.g. ``00:30:A7:11:12:13``
   #. A serial port, e.g. ``/dev/ttyUSB0`` or ``COM4``
   #. A host file (``.txt`` or ``.json``), with the same format as for ``-i``
   #. An IP address, subnet (e.g. ``192.0.2.0/24``), IP range (e.g. ``192.0.2.10-20``), or hostname. Hostnames are resolved to IP addresses using DNS when PEAT starts, and also match the hostname of a device.

#. **PEAT refuses to run if a target can't be used**, for example ``192.0.2.300``, a hostname that can't be resolved, or a host file that doesn't exist. PEAT also refuses to run if ``excluded_modules`` itself is invalid, or if a name in it doesn't match any module. A broken exclusion never quietly turns into no exclusion.
#. **Exclusions always win**, including over modules set with ``-d`` or ``device_types``, ``peat_module`` for a host in ``hosts``, and modules from a host file (``-f``).
#. **Where exclusions apply**: modules that are excluded for all targets are never used by ``scan``, ``pull``, ``push``, or ``parse``. Exclusions for specific targets apply to ``scan``, ``pull``, and ``push``. ``parse`` has no targets, so they're ignored, and their targets aren't resolved (``parse`` doesn't do DNS lookups for hostname targets, and works offline). A target that has every module excluded is skipped before any traffic is sent to it, including the online check (ARP, ICMP, or TCP SYN). Exclusions apply when PEAT *selects* a module for a target or file. They don't affect HEAT, pillage, or modules that use another module internally.

.. warning::
   Some exclusions can't prevent all traffic to a target:

   - **Broadcast scans** (``-b``) send probes to every host on a network. Only modules that are excluded for all targets are left out of a broadcast scan. Responses from targets that a module is excluded for are ignored.
   - **Sweeps** (``--sweep``) don't use any modules, so exclusions don't apply to them.

   PEAT logs a warning naming the targets of exclusions for specific targets when a sweep or a broadcast scan is run, since it can't stop that traffic. To send no traffic at all to a device, leave it out of the targets of sweeps, and don't use broadcast scans on its network.
   - **MAC address and hostname rules** are checked when PEAT learns the MAC address or hostname of a device, which may be after the online check. Use IP addresses (or labels of hosts in ``hosts`` that have an IP address) to make sure no traffic is sent.

Use ``--dry-run`` to check which modules and exclusions would be used, without sending any traffic:

.. code-block:: bash

   peat scan --dry-run -c site.yaml -x clx=192.0.2.10 -i 192.0.2.0/24

.. _config-command-sections:

Command sections (``scan``, ``pull``, ``push``, ``parse``)
==========================================================
The config file can have sections with settings that only apply to a single command: ``scan``, ``pull``, ``push``, and ``parse``. Any option that can be set at the top level of the config file can be set in a section, except for ``metadata`` and the other sections. The short names ``sweep`` (in ``scan``, for ``scan_sweep``) and ``skip_scan`` (in ``pull`` and ``push``, for ``pull_skip_scan`` and ``push_skip_scan``) can also be used. Unknown options in a section are ignored, with a warning.

.. code-block:: yaml
   :caption: Example of command sections

   device_types: [sel, controllogix]

   scan:
     targets: [192.0.2.0/24]
     sweep: false

   pull:
     device_types: [sel]
     skip_scan: false
     device_options:
       sel:
         pull_methods: [ftp, telnet]

   push:
     device_types: [selrelay]

How command sections work:

- **Only the section for the command being run is used.** For example, ``peat pull`` uses the ``pull`` section, but not the ``scan`` section, even though a pull also scans. Options in the ``pull`` section that affect scanning (e.g. ``intensive_scan``) apply to the scan done by the pull.
- **Precedence**: values in a section override values at the top level of the config file, and are overridden by environment variables and command line arguments (see :ref:`config-precedence`).
- **Merging**: mappings (e.g. ``device_options``) are merged with the value at the top level of the config file, and the value in the section wins if both have the same key. In the example above, any ``ftp`` credentials in the top-level ``device_options`` are still used by ``peat pull``. All other values, including lists, replace the top-level value. ``excluded_modules`` in a section is combined with all other exclusions.
- **Output directories**: ``out_dir`` and ``run_dir`` in a section override the top-level values, the same as other options.
- PEAT logs which options were applied from the section when it starts, e.g. ``Applied the 'pull' section of the config: device_types, pull_skip_scan``, and which options in the section are overridden by environment variables or command line arguments.
- When PEAT is used as a Python package, sections are applied by ``initialize_peat()`` if the ``func`` key is set to the command (e.g. ``initialize_peat({"func": "pull", "config_file": "site.yaml"})``), or with :meth:`config.apply_command_section("pull") <peat.settings.Configuration.apply_command_section>`.

.. note::
   ``pillage`` is **not** a command section. It's the configuration for PEAT Pillage, refer to :ref:`pillage-config`.

To share settings between sections, use YAML anchors and merge keys. Top-level keys that aren't PEAT options (like ``common_settings`` below) are ignored by PEAT.

.. code-block:: yaml
   :caption: Sharing settings between sections

   common_settings: &common
     intensive_scan: false
     assume_online: false

   scan:
     <<: *common
     sweep: false

   pull:
     <<: *common
     skip_scan: false

A complete example is in ``examples/peat-config-module-selection.yaml``.

.. _config-targets:

Targets in the config file (``targets``)
========================================
The :attr:`targets <peat.settings.Configuration.TARGETS>` option sets the network (IP) targets for ``scan`` and ``pull`` when no targets are given on the command line (``-i``, ``-s``, ``-f``, or ``-b``). It uses the same format as ``-i``: IP addresses, subnets, IP ranges, hostnames, labels of hosts in ``hosts``, ``all`` (every host in ``hosts``), and host files. ``targets`` can be set in a command section, so a ``scan`` section can include everything needed for a scan, e.g. ``peat scan -c site.yaml``. ``push`` always requires targets on the command line. ``targets`` is only used by the command line interface. The Python API functions (e.g. :func:`peat.api.scan_api.scan`) always take the targets as an argument.

If neither targets on the command line nor ``targets`` are set, ``scan`` and ``pull`` use the IP addresses of the hosts in ``hosts``.

.. code-block:: bash

   PEAT_TARGETS="192.0.2.0/24,192.0.2.50" peat scan -d sel

Environment variables
=====================
Configuration options can be set via system environment variables that are prefixed with ``PEAT_``. For example, to change the debugging level to ``1``, set the environment variable ``PEAT_DEBUG`` to ``1``, such as with ``export PEAT_DEBUG=1`` on Linux. Environment variables will override default settings and settings loaded from a configuration file, and are overridden by command line arguments. For example, if the environment variable ``PEAT_DEBUG`` is set to ``1``, and peat is run with ``peat scan -VV``, then the value of :attr:`DEBUG <peat.settings.Configuration.DEBUG>` for that run of PEAT will be ``2``.

.. code-block:: bash
   :caption: Linux environment variable configuration example

   # Set variables via export
   export PEAT_DEBUG=1
   export PEAT_VERBOSE=true
   peat parse examples/
   peat scan -i localhost

   # Modify only for this command execution
   PEAT_DEBUG=2 peat parse examples/

.. code-block:: batch
   :caption: Windows environment variable configuration example

   setx PEAT_DEBUG 1
   setx PEAT_VERBOSE true
   peat parse examples/
   peat scan -i localhost

Lists and mappings in environment variables
-------------------------------------------
Options that are lists (e.g. :attr:`HASH_ALGORITHMS <peat.settings.Configuration.HASH_ALGORITHMS>` or :attr:`DEVICE_TYPES <peat.settings.Configuration.DEVICE_TYPES>`) can be set as a comma-separated string or as a JSON list. Whitespace around items is removed. If an item contains a comma, use the JSON format.

Options that are mappings (e.g. :attr:`DEVICE_OPTIONS <peat.settings.Configuration.DEVICE_OPTIONS>`) can be set as a JSON object (or YAML "flow" syntax, e.g. ``{key: value}``).

We recommend the JSON format, since it's the most likely to keep working in future versions of PEAT. The same formats work for a single value in a config file, e.g. ``hash_algorithms: md5`` is the same as ``hash_algorithms: [md5]``.

.. code-block:: bash

   export PEAT_HASH_ALGORITHMS="md5,sha256"
   export PEAT_HASH_ALGORITHMS='["md5", "sha256"]'
   export PEAT_DEVICE_OPTIONS='{"sel": {"pull_methods": ["telnet"]}}'

If an option can't be loaded (for example ``PEAT_MAX_THREADS=abc``), PEAT logs an error and uses the value from the next source in the order of precedence. If ``excluded_modules`` can't be loaded, or the config file given with ``-c`` can't be loaded, PEAT refuses to run.


Additional topics
=================

Disabling file output
---------------------
Setting directory-related configuration options (e.g. :attr:`SUMMARIES_DIR <peat.settings.Configuration.SUMMARIES_DIR>`) to an empty string will **disable** any output to that directory. For example, setting :attr:`LOG_DIR <peat.settings.Configuration.LOG_DIR>` to an empty string (e.g. ``LOG_DIR=""``) will disable writing of logging data to files, including PEAT's logging and any protocols that log to a file (such as Telnet).

This feature is works well for most of the general options, such as :attr:`SUMMARIES_DIR <peat.settings.Configuration.SUMMARIES_DIR>` or :attr:`ELASTIC_DIR <peat.settings.Configuration.ELASTIC_DIR>`. Be warned, however, that mileage may vary for heavily used output dirs, such as :attr:`DEVICE_DIR <peat.settings.Configuration.DEVICE_DIR>` and :attr:`OUT_DIR <peat.settings.Configuration.OUT_DIR>`. They should work fine, but there have been regressions in the past where files have been written when :attr:`OUT_DIR <peat.settings.Configuration.OUT_DIR>` was disabled (in one case). If disabling file output is critical to your use case, we recommend testing locally before executing in the field.

Auto-generated configs
----------------------
Every run of PEAT generates a YAML file with the configuration values from the run in the path set by :attr:`META_DIR <peat.settings.Configuration.META_DIR>`, which by default is ``./peat_results/*/peat_metadata/``. This contains values for all configurations, regardless of their source, and is the single source of truth for how PEAT was configured at the end of a run. Note that if you used a config file for the run the auto-generated config may not match the config file you specified exactly.

These auto-generated configuration files can also be safely reused in a future run without modification. For example, ``peat scan -c ./peat_results/*/peat_metadata/peat_configuration.yaml -i 192.0.2.0/24``. This can help ensure consistency between runs, simplifies the process of reproducibility (redoing the same run in the same manner at a later date), and saves typing.

The auto-generated config contains the values that were used, including values from the :ref:`command section <config-command-sections>` for the command that was run, and the combined ``excluded_modules`` from all sources. The command sections are included as well. If you reuse the file with the same command, the run is the same. If you reuse it with a different command, the values that came from the first command's section are still used, since they're now at the top level of the file.

Encrypted config files
----------------------
Config files encrypted with ``peat encrypt-config`` can be used with ``-c``. PEAT detects that the file is encrypted and asks for the password.

JSON file
---------
PEAT will also accept configuration files in :term:`JSON` format. This is provided for flexibility and to provide backward compatibility. However, it's more limited than the YAML, and harder to write. The YAML format is preferred.


.. _peat-config:

YAML config reference
=====================
.. literalinclude:: ../examples/peat-config.yaml
   :name: PEAT YAML configuration reference
   :language: yaml


.. _pillage-config:

Pillage config reference
========================
- ``auto_copy`` [True or False] If ``True`` automatically copy a file to the results directory.  If ``False`` ask for permission to copy first.  This can be helpful in the case when there may be lot of false positives and the user wants to verify prior to copying. For example if you are searching for ``xml`` files.
- ``recursive`` [True of False] If ``True`` search in the source parent directory and all sub directories.  If ``False`` only search in the source parent directory and ignore all sub directories.
- Default/Brand specific search criteria:

  - ``locations`` [List of strings, each one should be a directory path] If empty search through all directories.  If directories exist only files in those directories will be considered. **Not yet implemented, Pillage currently searches through all directories regardless of what is listed here.**
  - ``filenames`` [List of strings] A list of filenames to search for.  When searching filenames take precedence over extensions and will be used first to determine the validity of a file.  No wildcards are accepted.  Must be the full filename with extension. Example ``['set_all.txt', '700g_001.rdb']``
  - ``extensions`` [List of strings] A list of extensions to search for.  No wildcards are accepted.  Example ``['txt', 'rdb', 'xml']``
