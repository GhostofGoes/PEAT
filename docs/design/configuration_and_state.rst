.. _config-state-deepdive:

***********************
Configuration and state
***********************
PEAT uses two global singletons, or `registries <https://martinfowler.com/eaaCatalog/registry.html>`__,
to manage its configuration and runtime state:

- :data:`peat.config`, an instance of :class:`~peat.settings.Configuration`: every
  user-settable option (see :doc:`/reference/configuration`)
- :data:`peat.state`, an instance of :class:`~peat.settings.State`: values that preserve
  or share runtime state across PEAT, such as the Elasticsearch connection, whether PEAT
  has superuser privileges, the entry point, and whether an error occurred

Both are subclasses of :class:`~peat.settings_manager.SettingsManager`. The user-facing
ways to configure PEAT (arguments, environment variables, files) are described in
:doc:`/user_guide/configure`; this page explains how the system works internally. The
API documentation is in :ref:`settings-api`.

Using the singletons
====================
The singletons can be imported and used anywhere in PEAT or in third-party code:

.. code-block:: python

   from peat import config, state

Changes are applied and visible immediately, regardless of import order, so values can be
read and written from anywhere in the code and at any phase of execution:

.. code-block:: pycon

   >>> from peat import config
   >>> config.DEBUG
   0
   >>> config.DEBUG = 2
   >>> config.DEBUG
   2

Sources and precedence
======================
Values can come from runtime changes (assignments and CLI arguments), environment
variables, and a configuration file. Each source is kept separately in a
:class:`~collections.ChainMap` stored in the special ``"CONFIG"`` key of the object, and
the value returned on access is the first one found in precedence order:

1. Runtime changes (assignments, values passed to :func:`~peat.init.initialize_peat`,
   CLI arguments)
2. Environment variables (``PEAT_<OPTION>``)
3. Configuration file
4. The class defaults

Because the sources are kept apart, PEAT can tell whether a value is still the default
(:meth:`~peat.settings_manager.SettingsManager.is_default_value`), which some code uses to
decide whether to apply its own defaults, for example the parse API disabling network
lookups only when the user didn't explicitly enable them. The merged result is what gets
written to ``peat_metadata/peat_configuration.yaml`` at the end of a run.

Type checking and conversion
============================
The type of each option is declared with a Python type annotation on the class attribute.
Values loaded from environment variables or files (which are text) are checked and
converted by :meth:`~peat.settings_manager.SettingsManager.typecast`:

- :class:`~pathlib.Path` options accept path strings and are converted to ``Path``
  objects.
- :class:`bool` options accept various spellings of truth: ``1``/``0``, ``yes``/``no``,
  ``true``/``false``.
- Numbers and lists are parsed accordingly.

.. warning::
   Runtime changes made directly to attributes (``config.DEBUG = 2``) are **not** type
   checked or converted. Use the correct type.

Directory options
=================
The output directory options depend on each other: ``RUN_DIR`` defaults to a
sub-directory of ``OUT_DIR``, and ``DEVICE_DIR``, ``LOG_DIR``, ``SUMMARIES_DIR``,
``META_DIR``, ``ELASTIC_DIR``, ``TEMP_DIR``, ``HEAT_ARTIFACTS_DIR``, and ``ZEEK_LOGDIR``
default to sub-directories of ``RUN_DIR``. :func:`~peat.init.initialize_peat` resolves them
with :meth:`Configuration.fixup_dirs() <peat.settings.Configuration.fixup_dirs>` after the
run name is known, and setting any of them to an empty string (``None``) disables output
to that location. The reference YAML uses anchors and a custom ``!JOIN`` tag to express
the same relationships.

Configuration from command line arguments
=========================================
**Command line arguments with a name matching an option's name are automatically loaded
into the configuration** as runtime changes. For example ``--print-results`` sets
:attr:`PRINT_RESULTS <peat.settings.Configuration.PRINT_RESULTS>`. This happens in
:func:`~peat.init.initialize_peat`, whose ``conf`` argument is the dictionary of CLI
arguments from :func:`peat.cli_main.run_peat` (keys are lower-cased first, so
``initialize_peat({"DEBUG": 1})`` works from scripts too). Only the configuration is
loaded this way; the state can't be changed from the CLI.

Environment variables beginning with ``PEAT_STATE_`` are loaded into the state. This
exists for debugging and temporary workarounds and should otherwise be avoided, since it
can cause undefined behavior.

Adding an option
================
To add a new value to the configuration or state, add an attribute to the appropriate
class (:class:`~peat.settings.Configuration` or :class:`~peat.settings.State`). The
attribute **must** have a type annotation and a default value, and a docstring describing
it (the docstring is what appears in the API documentation):

.. code-block:: python

   class Configuration(SettingsManager):
       ...
       COOLNESS_FACTOR: int = 0
       """
       Modifies the coolness of a run.
       """
       ...

The option can immediately be set from environment variables and configuration files:

.. code-block:: bash

   export PEAT_COOLNESS_FACTOR=9001
   peat parse examples/

   # For a single command
   PEAT_COOLNESS_FACTOR=9001 peat parse examples/

Then:

- Add the option, with a comment describing it and its default value, to
  ``examples/peat-config.yaml``. That file is the configuration reference in the
  documentation, so this is how users learn about the option.
- **The command line argument is not added automatically.** Add it to
  :func:`~peat.cli_args.build_argument_parser` in :mod:`peat.cli_args` if it should be
  available on the CLI: to the ``general arguments`` group in the ``subparsers`` loop if it
  applies to all commands, otherwise to the specific command's parser (or a loop over
  several). Use ``default=None`` so the argument only overrides when given:

  .. code-block:: python

     group.add_argument(
         "-o",
         "--out-dir",
         type=validate_filepath_arg,
         metavar="PATH",
         default=None,
         help="Output directory for all runs of PEAT. "
         'Defaults to "peat_results" in the current directory.',
     )

- If the option affects output locations, see how the ``*_DIR`` options are handled in
  :func:`~peat.init.initialize_peat` and :ref:`output-structure`.
- Add a test (``tests/test_settings.py`` and ``tests/test_cli_args.py`` have examples).

Why singletons?
===============
PEAT supports several independent ways of being used (the CLI, as a Python package, and
historically an HTTP server), and device modules deep in the call stack need access to
options such as timeouts, output directories, and debugging levels. Passing configuration
objects through every call would be impractical, and module-level globals would make
testing and re-initialization hard. The registry pattern with layered sources gives the
flexibility to read and write anywhere while keeping the precedence rules in one place.
The cost is that :mod:`peat.settings` must not import anything else from PEAT (everything
imports it), which is why it contains a certain amount of Python hackery; see the
:doc:`/contributing/codebase_tour` landmines.
