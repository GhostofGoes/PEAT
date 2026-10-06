***********************
Configuration reference
***********************
PEAT's configuration options, with their defaults and documentation. Options can be set
in a :term:`YAML` configuration file, as environment variables, as command line arguments,
or from Python; :doc:`/user_guide/configure` explains how the sources combine. The
canonical, documented list of options is the reference configuration file below, which is
kept in the repository as
:download:`examples/peat-config.yaml <../../examples/peat-config.yaml>`.

.. tip::
   Every run writes the complete configuration it used to
   ``peat_results/<run-dir>/peat_metadata/peat_configuration.yaml``. That file is a valid
   configuration file and a good starting point for your own.

Related example configurations:

- :download:`peat-config-simple.yaml <../../examples/peat-config-simple.yaml>`: a
  minimal file with the options most users need
- :download:`peat-config-sel-force-telnet.yaml <../../examples/peat-config-sel-force-telnet.yaml>`:
  restrict SEL pulls to Telnet
- :download:`peat-config-sel-serial-testing.yaml <../../examples/peat-config-sel-serial-testing.yaml>`:
  SEL relays over serial
- :download:`peat-config-sceptre-testing.yaml <../../examples/peat-config-sceptre-testing.yaml>`:
  SCEPTRE virtual field devices
- :download:`openplc-config.yaml <../../examples/openplc-config.yaml>`: OpenPLC Runtime v4
  credentials and options

Configuration options in Python
===============================
Each top-level option corresponds to an attribute of
:class:`peat.settings.Configuration` (the key in upper case: ``out_dir`` is
:attr:`~peat.settings.Configuration.OUT_DIR`), which is also the name of the environment
variable with a ``PEAT_`` prefix (``PEAT_OUT_DIR``). The attribute documentation is in
:ref:`the PEAT API reference <configuration-api>`.

.. _peat-config:

YAML configuration reference
============================
.. literalinclude:: ../../examples/peat-config.yaml
   :name: PEAT YAML configuration reference
   :language: yaml
   :linenos:

.. _pillage-config:

Pillage configuration
=====================
The ``pillage`` section defines what :doc:`peat pillage </user_guide/pillage>` looks for.

- ``auto_copy`` (``true`` or ``false``): if ``true``, matching files are copied to the
  results directory automatically; if ``false``, PEAT asks for permission before copying
  each file. Interactive mode helps when a pattern produces many false positives, for
  example when searching for ``xml`` files.
- ``recursive`` (``true`` or ``false``): if ``true``, search the source directory and all
  sub-directories; if ``false``, only the source directory itself.
- ``default`` and ``brands.<Brand>``: search criteria. ``default`` applies to every file;
  each entry under ``brands`` is a vendor whose matches are copied into a sub-directory of
  that name. Each criteria set has:

  - ``locations`` (list of directory paths): limit the search to these directories.
    **Not yet implemented**; pillage currently searches every directory regardless.
  - ``filenames`` (list of strings): exact file names to search for, including the
    extension, case-insensitive, no wildcards. Checked before ``extensions``.
    Example: ``["set_all.txt", "700g_001.rdb"]``
  - ``extensions`` (list of strings): file extensions to search for, without the dot and
    without wildcards. Example: ``["txt", "rdb", "xml"]``

.. literalinclude:: ../../examples/peat-config.yaml
   :language: yaml
   :start-at: pillage:
   :end-before: # -----------------------------------------------------------------------------

Device and protocol options
===========================
The ``device_options`` section holds options for modules (keyed by a module or vendor
name such as ``sel``, ``sage``, ``openplcv4``) and for protocols (``telnet``, ``ftp``,
``ssh``, ``http``, ``mysql``, ...): ports, timeouts, credentials, and module-specific
behavior such as which protocols to use for pulls (``pull_methods``) or which files to
skip. These apply to every device in a run. The ``hosts`` section applies options to
individual devices and can pin the module used for a host. Both are documented inline in
the reference configuration above, and per device family on the
:doc:`device reference pages <devices/index>`.

Options are **not** perfectly consistent between modules: modules have evolved over time,
and those that predate the YAML configuration (introduced in late 2021) don't always follow
the same conventions. When in doubt, the reference configuration and the module's
``default_options`` class attribute (shown on the module's page in
:doc:`/developer/device_modules`) are authoritative.

Environment variables
=====================
Any option can be set with an environment variable named ``PEAT_<OPTION>`` in upper case,
for example ``PEAT_DEBUG=2`` or ``PEAT_OUT_DIR=/data/peat``. Values are converted to the
option's type (booleans accept ``true``/``false``, ``yes``/``no``, ``1``/``0``). Variables
beginning with ``PEAT_STATE_`` set the corresponding runtime state value instead; this
exists for debugging and should be avoided otherwise.

The ``LOGURU_*`` environment variables customize log formatting and colors (see
:doc:`/contributing/logging`), and ``PEAT_IN_CONTAINER`` tells PEAT it is running in the
container image.
