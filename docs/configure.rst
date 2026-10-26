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
3. Configuration file (example: ``-c peat-config.yaml``)
4. Default values

If using the Python API, e.g. ``config.DEBUG=1`` or values passed to ``initialize_peat(...)``, those are applied at the same level as command line arguments and override environment variables and the config file.


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


Additional topics
=================

.. _tls-verification:

TLS certificate verification
----------------------------
PEAT verifies TLS (SSL) certificates for HTTPS connections, including connections to devices and to Elasticsearch/OpenSearch. Many older OT devices use self-signed certificates, which fail verification, and PEAT will log a warning explaining how to proceed when this happens. There are three ways to connect to these devices:

- **Trust the certificate (recommended)**: add the device's certificate, or the CA that issued it, to a PEM file and set :attr:`TLS_CA_BUNDLE <peat.settings.Configuration.TLS_CA_BUNDLE>` (``tls_ca_bundle: /path/to/ca-bundle.pem``).
- **Disable verification for specific hosts**: set the ``https.verify`` option to ``false`` for the host. Setting it in ``device_options`` disables verification for all devices, while still verifying the Elasticsearch server.
- **Disable verification everywhere**: set :attr:`TLS_VERIFY <peat.settings.Configuration.TLS_VERIFY>` to false (``tls_verify: false`` in the config file, or ``PEAT_TLS_VERIFY=false``).

.. code-block:: yaml
   :caption: Disable TLS certificate verification for a single host

   hosts:
   - label: "SEL-3530"
     identifiers:
       ip: 192.0.2.30
     options:
       https:
         verify: false

.. warning::
   When verification is disabled, anyone who can intercept the connection can capture credentials PEAT sends over it (e.g. web logins). PEAT logs a warning for each host that verification is disabled for.


.. _ssh-host-keys:

SSH host keys
-------------
PEAT checks the host key of every device it connects to with SSH, before sending any credentials. Keys are checked against the system ``~/.ssh/known_hosts`` file and PEAT's own known_hosts file, set by :attr:`SSH_KNOWN_HOSTS <peat.settings.Configuration.SSH_KNOWN_HOSTS>` (default: ``~/.peat/known_hosts``, in the home directory of the user running PEAT, e.g. ``/root`` if run with ``sudo``).

- **New host**: the key is trusted on first use and saved to PEAT's known_hosts file, and a warning with its fingerprint (``SHA256:...``, the format output by ``ssh-keygen -lf``) is logged. If possible, check the fingerprint against the device.
- **Changed key**: the connection is refused and an error is logged with the expected and actual fingerprints. This can mean the connection is being intercepted, or that the device's key changed (e.g. after a firmware update or device replacement). If the change is expected, remove the old key from the known_hosts file, or set the ``ssh.trust_new_host_key`` option to ``true`` for the host to accept and save the new key.
- **Pinned key**: set the ``ssh.host_key_fingerprint`` option for a host to only accept a key with that fingerprint (``SHA256:...`` or MD5 hex). Pinned keys are not saved to the known_hosts file.
- **Unusable known_hosts file**: if PEAT's known_hosts file can't be read or saved (e.g. a read-only home directory, or a file that isn't a known_hosts file), a warning is logged once and connections continue. Keys trusted during the run are kept in memory, so a key that changes during the run is still refused. Set ``ssh_known_hosts: ""`` to not use a PEAT known_hosts file.

.. code-block:: yaml
   :caption: Pin the SSH host key of a single host

   hosts:
   - label: "Sage-RTU"
     identifiers:
       ip: 192.0.2.40
     options:
       ssh:
         host_key_fingerprint: "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"

Disabling file output
---------------------
Setting directory-related configuration options (e.g. :attr:`SUMMARIES_DIR <peat.settings.Configuration.SUMMARIES_DIR>`) to an empty string will **disable** any output to that directory. For example, setting :attr:`LOG_DIR <peat.settings.Configuration.LOG_DIR>` to an empty string (e.g. ``LOG_DIR=""``) will disable writing of logging data to files, including PEAT's logging and any protocols that log to a file (such as Telnet).

This feature is works well for most of the general options, such as :attr:`SUMMARIES_DIR <peat.settings.Configuration.SUMMARIES_DIR>` or :attr:`ELASTIC_DIR <peat.settings.Configuration.ELASTIC_DIR>`. Be warned, however, that mileage may vary for heavily used output dirs, such as :attr:`DEVICE_DIR <peat.settings.Configuration.DEVICE_DIR>` and :attr:`OUT_DIR <peat.settings.Configuration.OUT_DIR>`. They should work fine, but there have been regressions in the past where files have been written when :attr:`OUT_DIR <peat.settings.Configuration.OUT_DIR>` was disabled (in one case). If disabling file output is critical to your use case, we recommend testing locally before executing in the field.

Auto-generated configs
----------------------
Every run of PEAT generates a YAML file with the configuration values from the run in the path set by :attr:`META_DIR <peat.settings.Configuration.META_DIR>`, which by default is ``./peat_results/*/peat_metadata/``. This contains values for all configurations, regardless of their source, and is the single source of truth for how PEAT was configured at the end of a run. Note that if you used a config file for the run the auto-generated config may not match the config file you specified exactly.

These auto-generated configuration files can also be reused in a future run. For example, ``peat scan -c ./peat_results/*/peat_metadata/peat_configuration.yaml -i 192.0.2.0/24``. This can help ensure consistency between runs, simplifies the process of reproducibility (redoing the same run in the same manner at a later date), and saves typing.

Secrets are omitted from the auto-generated configs, from the copy of the config file saved to :attr:`META_DIR <peat.settings.Configuration.META_DIR>`, and from the configuration saved to Elasticsearch, and they are redacted (replaced with ``<redacted>``) in the command line recorded in the logs. This includes device passwords and SNMP communities (e.g. ``pass``, ``password``, ``community``, and ``creds`` in ``device_options``) and passwords in Elasticsearch server URLs (``http://elastic:changeme@localhost:9200/`` is saved as ``http://elastic@localhost:9200/``). The first line of a saved YAML file is a comment listing the secrets that were omitted. When you reuse an auto-generated config, the default values are used for the omitted options (e.g. the default SNMP communities), so set the secrets again if you need them (e.g. in the config file or with environment variables).

When a configuration is loaded (from a file, environment variables, or the command line), values that are ``<redacted>`` are ignored with a warning, as are ``[username, <redacted>]`` pairs and URLs with a ``<redacted>`` password. This prevents a placeholder copied from the logs from being used as a password or SNMP community.

Results file permissions
------------------------
Files and directories created in the results are only accessible by the user running PEAT (umask ``077``), since they may contain sensitive data. If PEAT is run with ``sudo``, the owner of the run directory is changed to the user that ran ``sudo`` when PEAT exits. This isn't done when PEAT runs in a container.

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
- ``max_file_size`` [Integer, bytes] Files larger than this are skipped (with a warning) instead of copied. Defaults to ``268435456`` (256 MiB). Set to ``0`` to disable the limit.
- ``image_format`` [String] Format of the disk image to pillage (passed to ``qemu-nbd -f``): ``auto``, ``raw``, ``qcow2``, ``vmdk``, ``vhdx``, ``vdi``, or ``vpc`` (VHD). Defaults to ``auto``, which picks the format from the file extension (``.qcow2``, ``.qcow``, ``.vmdk``, ``.vhdx``, ``.vdi``, ``.vhd``), and uses ``raw`` for any other extension (e.g. ``.img`` or ``.dd``). It can also be set with ``peat pillage --image-format``, which overrides this option. The format is never detected from the contents of the image ("probing"), since a crafted raw image can pretend to be another format that references a "backing file" on the system running PEAT, which would then be read. For formats other than ``raw``, the image is checked with ``qemu-img info`` first, and isn't mounted if it references other files: a backing file, a qcow2 external data file (``data-file``), or VMDK extents other than the image itself and files next to it named after it (e.g. ``disk-s001.vmdk`` for a "split" ``disk.vmdk``). The image is connected to the first free ``/dev/nbdN`` device.
- Default/Brand specific search criteria:

  - ``locations`` [List of strings, each one should be a directory path] If empty search through all directories.  If directories exist only files in those directories will be considered. **Not yet implemented, Pillage currently searches through all directories regardless of what is listed here.**
  - ``filenames`` [List of strings] A list of filenames to search for.  When searching filenames take precedence over extensions and will be used first to determine the validity of a file.  No wildcards are accepted.  Must be the full filename with extension. Example ``['set_all.txt', '700g_001.rdb']``
  - ``extensions`` [List of strings] A list of extensions to search for.  No wildcards are accepted.  Example ``['txt', 'rdb', 'xml']``

.. note::
   Pillage only copies regular files. Symbolic links, device files, FIFOs, and other special files found in the source are skipped, as are the top-level ``Windows``, ``System Volume Information``, ``PerfLogs``, ``MSOCache``, ``cygwin64``, ``Recovery``, ``Boot``, and ``$Recycle.Bin`` directories. Disk images are mounted read-only with the ``nodev``, ``nosuid``, and ``noexec`` options.
