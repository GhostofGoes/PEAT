*******************
Lifecycle of a run
*******************
What happens between ``peat pull -c site.yaml -d selrelay -i 192.0.2.0/24`` and the exit
code, step by step, with the functions involved. Knowing this order explains where options
take effect, when files appear, and why some things (such as a configuration error) stop a
run before any packet is sent.

.. raw:: html
   :file: ../images/run_lifecycle.svg

.. only:: not html

   A run passes through five stages: argument parsing (``--help`` and ``--version`` exit
   here), initialization (settings loaded from the configuration file, environment, and
   command line; run directory created; logging started; Elasticsearch connected with
   ``-e``; a configuration error ends the run with exit code 1 before any packet is sent),
   informational commands (``--list-modules``, ``--examples``, and similar print and exit),
   running the command (the command's API function in ``peat.api``, with the modules
   writing into the datastore), and finishing (configuration and state exported, summaries
   and device data written, exit code 1 if any error was recorded). On disk, the run
   directory and ``peat_metadata/`` appear during initialization, ``logs/`` is written from
   then until the end, and ``devices/`` and ``summaries/`` are filled while the command
   runs and finishes.

1. Argument parsing
===================
``peat`` runs :mod:`peat.__main__`, which builds the argument parser with
:func:`peat.cli_args.build_argument_parser` and parses the command line. The parser has one
sub-parser per command, each with the shared general arguments (``-c``, ``-R``, ``-v``,
``-V``, ``-e``, ...) and the command's own. Informational arguments (``--version``,
``--help``) exit here. The parsed arguments are passed as a dictionary to
:func:`peat.cli_main.run_peat`.

2. Initialization
=================
:func:`peat.init.initialize_peat` is called with the arguments and
``entrypoint="CLI"``. In order:

#. Keys are lower-cased, so the same function works for scripts
   (``initialize_peat({"DEBUG": 1})``).
#. If ``-c`` was given, the **configuration file** is read (decrypting it, with a password
   prompt, when it has the encrypted-file header) and loaded into
   :data:`peat.config` as the "file" layer.
#. The **runtime layer** is loaded from the arguments: any argument whose name matches an
   option sets that option (``--print-results`` sets ``PRINT_RESULTS``). See
   :doc:`configuration_and_state`.
#. **Third-party modules** listed in ``-I`` / ``additional_modules`` are imported through
   :data:`peat.module_api`. A failed import is an error.
#. The **output directories** are resolved: ``OUT_DIR`` (``./peat_results``), then
   ``RUN_DIR`` from ``--run-dir``, ``--run-name``, or the auto-generated
   ``<command>_<config-name>_<timestamp>_<run-id>``, then every ``*_DIR`` that derives
   from it.
#. The **logo** is printed (to standard error, unless ``--no-logo``), and **logging** is
   configured with :func:`peat.log_utils.setup_logging`: terminal level from ``-v``/``-q``,
   debugging level from ``-V``, file sinks for ``peat.log`` and ``json-log.jsonl``,
   ``debug-info.txt``, and protocol logs. The original configuration file is copied into
   ``peat_metadata/``.
#. Start-up information is logged: log file location, configuration name, run directory.
#. **Device options** are prepared: serial baud rates and the global timeout are applied,
   ``device_options`` becomes the datastore's global options, and ``hosts`` entries become
   per-host option overrides and known identifiers.
#. The **exit handlers** that write ``peat_configuration.yaml`` and ``peat_state.yaml``
   are registered (CLI entry point only).
#. **Elasticsearch** is connected if ``-e``/``ELASTIC_SERVER`` is set: an
   :class:`~peat.elastic.Elastic` client is created and pinged (detecting OpenSearch),
   dated-index behavior is configured, and the client is stored in ``state.elastic``. A
   connection failure is logged and export is disabled rather than aborting the run.
#. Whether PEAT has **superuser privileges** is recorded in ``state.superuser_privs``
   (this decides whether raw sockets are used), and a warning about it is logged.

Anything that fails here (bad configuration, unreadable file, module import error) ends
the run with exit code 1 before any device is touched.

3. Informational commands
=========================
Back in :func:`~peat.cli_main.run_peat`, the ``--list-modules``, ``--list-aliases``,
``--list-alias-mappings``, ``--list-all``, ``--examples``, and ``--all-examples``
arguments print their output as JSON or text and exit with code 0. ``config-builder``
launches the interactive builder and exits. ``--pdb`` and ``--repl`` drop into the
debugger or interpreter here, after initialization, with the configured PEAT available.

4. Running the command
======================
:func:`~peat.cli_main.oneshot_main` dispatches on the command:

- ``heat`` goes straight to :func:`peat.api.heat_api.heat_main`.
- The encryption commands call :mod:`peat.api.crypto_api` and exit immediately with 0 or 1.
- For ``scan``, ``pull``, and ``push``, :func:`~peat.cli_main.get_targets` works out the
  **targets and communication type**: from ``-f`` (a previous summary, including from
  standard input), ``-i`` (``unicast_ip``), ``-b`` (``broadcast_ip``), ``-s``
  (``serial``), or, if none were given, the IPs of the ``hosts`` in the configuration
  file. Host labels are resolved to their identifiers, and a target of ``all`` means every
  configured host. The module names come from ``-d`` plus any runtime-imported modules
  and the ``peat_module`` of configured hosts.
- For ``parse``, the module names come from ``-d`` (default ``all``).
- Module names are sorted for determinism. With ``--dry-run``, the run ends here
  successfully, having validated everything without executing the command.
- The high-level API function is called: :func:`~peat.api.parse_api.parse`,
  :func:`~peat.api.pull_api.pull`, :func:`~peat.api.scan_api.scan`,
  :func:`~peat.api.push_api.push`, or :func:`~peat.api.pillage_api.pillage`. Each returns
  a summary (or a boolean for push and pillage) and has written its own summary file and
  Elasticsearch document. What each one does is described in :doc:`scanning` and
  :doc:`pull_parse_push`.
- For scan, pull, and push, :func:`~peat.cli_main.export_device_data` de-duplicates the
  datastore and writes every verified device's ``device-data-*`` files (and, for scan and
  push, pushes them to Elasticsearch; pull and parse export per device as they go).
- With ``-E``/``--print-results``, the summary (or, for pull, the device data) is printed
  to standard output as JSON.

A :class:`~peat.consts.PeatError` from the API (bad arguments, invalid device types) is
logged as an error; any other exception is logged with its traceback. Either marks the
run as failed.

5. Finishing
============
Back in :func:`~peat.cli_main.run_peat`:

#. The configuration and state are pushed to Elasticsearch (``peat-configs``,
   ``peat-state``) if enabled. ``DEVICE_OPTIONS`` and ``HOSTS`` are removed from the
   configuration document first, since their dynamic mappings cause push failures.
#. The run duration is logged (``Finished run in ...``).
#. Empty directories under the run directory are removed.
#. If PEAT ran as root on a POSIX system, a handler to **fix file ownership** of the run
   directory back to the invoking user (``SUDO_UID``) is registered to run last.
#. ``README.md`` describing the output layout is written to the output directory.
#. The process exits with **code 1** if any error was recorded in ``state.error``, else
   **0**. At exit, the registered handlers run in order: connection cleanup (closing
   device sessions cleanly, which some devices require), then file handlers (the
   configuration and state dumps, then the ownership fix).

As a library
============
When PEAT is imported as a package, the same :func:`~peat.init.initialize_peat` runs
(with ``entrypoint="Package"``), but the configuration and state dumps aren't registered,
and the caller decides what to do with the returned summaries. Passing ``OUT_DIR: None``
disables file output entirely. See :doc:`/developer/python_examples`.
