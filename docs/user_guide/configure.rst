*********
Configure
*********
PEAT has a large set of options: output locations, scanning behavior, Elasticsearch
export, per-module and per-protocol settings (ports, credentials, which protocols to use),
and an inventory of known hosts. Options can be set in several ways, and this page
explains each and how they combine. The option-by-option reference is the annotated
:ref:`reference configuration file <peat-config>`.

.. warning::
   The example configuration files are intended to demonstrate how to configure PEAT.
   **We strongly recommend customizing the settings for your use case and environment.**
   The simplest and most valuable customization is limiting the device modules used to
   those present in the environment, for example ``-d sel`` when working with SEL devices.

Ways to configure PEAT
======================
#. **Command line arguments**, for example ``-VV`` or ``--out-dir /data/peat``. The most
   common options have arguments; see the :ref:`cli-reference`.
#. **Environment variables** prefixed with ``PEAT_``, for example ``PEAT_DEBUG=2``.
#. **A configuration file** in :term:`YAML` (or :term:`JSON`), passed with
   ``-c peat-config.yaml``. This is the only way to set many options, including
   credentials, per-module settings, and the ``hosts`` inventory.
#. **Defaults** built into PEAT.

.. _config-precedence:

Order of precedence
-------------------
When the same option is set in several places, the first of these wins:

1. Command line arguments (and values set from Python, see below)
2. Environment variables
3. Configuration file
4. Default values

For example, with ``PEAT_DEBUG=1`` in the environment and ``peat scan -VV`` on the
command line, :attr:`DEBUG <peat.settings.Configuration.DEBUG>` is ``2`` for that run.

When using the :doc:`Python API </developer/peat_api>`, values assigned at runtime
(``config.DEBUG = 1``) or passed to :func:`~peat.init.initialize_peat` are applied at the
same level as command line arguments, overriding environment variables and configuration
files.

Every run writes the configuration it actually used, from all sources, to
``peat_results/<run-dir>/peat_metadata/peat_configuration.yaml``. When in doubt about
what value applied, look there.

.. raw:: html
   :file: ../images/config_precedence.svg

.. only:: not html

   Module and protocol options are merged separately for each device: a host's ``options``
   in the ``hosts`` list override ``device_options``, which override the module's
   ``default_options``; ``device_options`` and ``hosts`` are keys in the configuration file.

YAML configuration file
=======================
A configuration file is passed with ``-c`` (``--config-file``). Values in the file override
the defaults and are overridden by environment variables and command line arguments.

.. code-block:: bash

   peat scan -c ./peat-config.yaml -d clx -i 192.0.2.0/24
   peat pull -c ./peat-config.yaml -d ion sel -i 192.0.2.0/24
   peat push -c ./peat-config.yaml -d selrelay -i 192.0.2.1 -- ./SET_1.TXT
   peat parse -c ./peat-config.yaml -d selrelay ./SET_ALL.TXT

Start from one of the example files (included in the release bundles and in the
repository's ``examples/`` directory), or generate one interactively with
:doc:`peat config-builder <config_builder>`:

- :download:`peat-config-simple.yaml <../../examples/peat-config-simple.yaml>`: a short
  file with the options most users touch
- :download:`peat-config.yaml <../../examples/peat-config.yaml>`: the complete, annotated
  reference with every option and its default (also rendered in
  :ref:`the reference <peat-config>`)

Walkthrough of the file
-----------------------
**metadata** describes the configuration itself: a ``name`` (used in auto-generated run
directory names, so keep it short and file-system friendly), a human-readable
``description``, the ``author``, and ``created``/``updated`` timestamps. ``name`` should
be set; the rest are optional but recommended.

.. code-block:: yaml

   metadata:
     name: "substation-a"
     description: "SEL relays and RTACs at Substation A, FTP credentials for the relays"
     author: "cegoes"
     created: "May 22nd, 2024"
     updated: ""

**General options** are the top-level keys. Most correspond to a command line argument or
an environment variable, with some exceptions (many Elasticsearch options are only
available here, to keep ``--help`` manageable). The key is the lower-case name of the
option: ``out_dir`` for :attr:`OUT_DIR <peat.settings.Configuration.OUT_DIR>`,
``print_results`` for :attr:`PRINT_RESULTS <peat.settings.Configuration.PRINT_RESULTS>`,
and so on.

.. code-block:: yaml

   verbose: false
   quiet: false
   print_results: false
   no_color: false
   no_logo: false
   assume_online: false
   max_threads: 260
   default_timeout: 5.0
   out_dir: "./peat_results/"
   elastic_server: null

**device_options** holds settings for modules and protocols that apply to every device in
the run (it's global, not per host). Module- or vendor-specific settings live under a key
named for the module or vendor: ``sel`` for the SEL modules
(:class:`~peat.modules.sel.sel_relay.SELRelay` and
:class:`~peat.modules.sel.sel_rtac.SELRTAC`), ``sage`` for
:class:`~peat.modules.schneider.sage.sage.Sage`, ``openplcv4`` for OpenPLC, and so on.
Protocol settings live under the protocol name (``telnet``, ``ftp``, ``ssh``, ``http``,
``https``, ``snmp``, ``mysql``, ...) and are usually the port, timeout, login
credentials, and protocol specifics such as SSH key paths.

.. code-block:: yaml
   :caption: Force Telnet to be used for pulls from any SEL device, and set FTP credentials

   device_options:
     sel:
       pull_methods:
         - telnet
     ftp:
       user: "FTPUSER"
       pass: "TAIL"

**hosts** is an inventory of the devices PEAT will interact with. PEAT uses it to tune
scanning, and it's where per-host settings go, notably credentials that differ per device
and the module to use for a host. Host *labels* can be used as targets on the command
line (``peat pull -i SEL-351S``). Options under a host override the ``device_options``
and the module defaults for that host only.

.. code-block:: yaml

   hosts:
     - label: "SEL-351S"
       comment: "SEL-351S Protection System in building XXX"
       identifiers:
         ip: 192.0.2.220
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
         ip: 192.0.2.221
         mac: 00:30:A7:11:12:14
       peat_module: "SELRelay"
       options:
         ftp:
           user: "FTP"
           pass: "TAIL"
         sel:
           never_download_dirs:
             - EVENTS

**pillage** configures :doc:`peat pillage <pillage>`; see :ref:`pillage-config`.

The YAML file supports anchors and aliases, and PEAT adds a ``!JOIN`` tag to concatenate
strings, which the reference file uses to derive the output sub-directories from
``out_dir``.

.. note::
   Options are not perfectly consistent between modules. PEAT modules have evolved over
   time, and modules that predate the YAML configuration (introduced in late 2021) don't
   always follow the same conventions as newer ones. If you're uncertain about an option,
   check the reference configuration and, if needed, the module's ``default_options`` in
   :doc:`/developer/device_modules`.

Protecting credentials
----------------------
Configuration files often contain device credentials. Restrict their permissions, keep
them out of version control, and consider encrypting them with
``peat encrypt-config``; an encrypted file can be used directly with ``-c`` and PEAT will
prompt for the password. See :doc:`encryption`.

Environment variables
=====================
Any option can be set with an environment variable named ``PEAT_<OPTION>`` (upper case).
Environment variables override defaults and the configuration file, and are overridden by
command line arguments.

.. tab-set::

   .. tab-item:: Linux / macOS
      :sync: linux

      .. code-block:: bash

         # For the rest of the shell session
         export PEAT_DEBUG=1
         export PEAT_VERBOSE=true
         peat parse examples/
         peat scan -i localhost

         # For a single command
         PEAT_DEBUG=2 peat parse examples/

   .. tab-item:: Windows (PowerShell)
      :sync: windows

      .. code-block:: powershell

         # For the rest of the session
         $env:PEAT_DEBUG = "1"
         $env:PEAT_VERBOSE = "true"
         .\peat.exe parse examples\

         # Persistently for the user (takes effect in new terminals)
         setx PEAT_DEBUG 1

Values are converted to the option's type: booleans accept ``true``/``false``,
``yes``/``no``, and ``1``/``0``; paths and numbers are parsed accordingly.

Additional topics
=================

Disabling file output
---------------------
Setting a directory option to an empty string disables output to that directory. For
example ``LOG_DIR: ""`` disables writing of log files, including protocol transcripts.
This works well for :attr:`SUMMARIES_DIR <peat.settings.Configuration.SUMMARIES_DIR>`,
:attr:`ELASTIC_DIR <peat.settings.Configuration.ELASTIC_DIR>`, and
:attr:`LOG_DIR <peat.settings.Configuration.LOG_DIR>`. Disabling the heavily used
:attr:`DEVICE_DIR <peat.settings.Configuration.DEVICE_DIR>` and
:attr:`OUT_DIR <peat.settings.Configuration.OUT_DIR>` should also work, but there have been
regressions in the past where files were written anyway. If disabling file output is
critical to your use case, test locally before executing in the field.

.. _auto-generated-configs:

Auto-generated configurations
-----------------------------
Every run of PEAT writes a YAML file with the configuration values from the run to the
directory set by :attr:`META_DIR <peat.settings.Configuration.META_DIR>`, by default
``./peat_results/<run-dir>/peat_metadata/peat_configuration.yaml``. It contains every
option, regardless of its source, and is the single source of truth for how PEAT was
configured at the end of a run. If you used a configuration file, the generated file may
not match it exactly, since it includes command line and environment overrides.

These files can be reused in a future run without modification:
``peat scan -c ./peat_results/<run-dir>/peat_metadata/peat_configuration.yaml -i 192.0.2.0/24``.
This ensures consistency between runs, simplifies reproducing a run at a later date, and
saves typing.

JSON configuration files
------------------------
PEAT also accepts configuration files in :term:`JSON` format, for flexibility and backward
compatibility. JSON is more limited (no comments, no anchors or ``!JOIN``) and harder to
write; the YAML format is preferred.

Configuring from Python
-----------------------
When using PEAT as a library, pass options to :func:`peat.initialize_peat` or assign them
on the :data:`peat.config` object. See :doc:`/developer/peat_api` and the
:doc:`/design/configuration_and_state` design document for how the settings system works
internally.

.. code-block:: python

   from peat import config, initialize_peat

   initialize_peat({"DEBUG": 1, "VERBOSE": True, "OUT_DIR": "/data/peat"})
   config.MAX_THREADS = 50
