*******************
Command line basics
*******************
Conventions shared by every PEAT command: getting help, naming runs, selecting device
modules, choosing targets, and the general arguments. The complete argument list for
each command is in the :ref:`cli-reference`.

Getting help
============
.. code-block:: bash

   # Usage for PEAT and for each command (--help, -h, and no arguments all work)
   peat --help
   peat scan --help
   peat pull -h

   # Cheat sheet of real-world examples for a command, or for all commands
   peat scan --examples
   peat scan --all-examples

   # Version
   peat --version

   # On Linux, the installed man page contains the whole user guide
   man peat

Anatomy of a command
====================
.. code-block:: text

   peat <command> [general arguments] [command arguments] [-- <positional arguments>]

   peat pull -R site-a -c peat-config.yaml -d selrelay -i 192.0.2.0/24
        │     │         │                  │           └─ targets (hosts, networks, files)
        │     │         │                  └─ device modules to use
        │     │         └─ configuration file
        │     └─ run name (output directory name)
        └─ command

Positional arguments (the files to parse or push) must come last. When an option that
accepts several values (such as ``-d`` or ``-i``) directly precedes them, separate the two
with ``--`` so the paths aren't treated as more option values:

.. code-block:: bash

   peat parse -d selrelay m340 -- ./SET_ALL.TXT ./project.apx
   peat push -d selrelay -i 192.0.2.22 -- ./SET_1.TXT

General arguments
=================
These are accepted by every command, after the command name. Most correspond to a
:doc:`configuration option <configure>` and can also be set in a configuration file or an
environment variable.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Argument
     - Purpose
   * - ``-c FILE``, ``--config-file FILE``
     - Load configuration from a :term:`YAML` (or :term:`JSON`) file. See :doc:`configure`.
   * - ``-R NAME``, ``--run-name NAME``
     - Name the run; results go to ``peat_results/NAME/``. See :doc:`output`.
   * - ``-o PATH``, ``--out-dir PATH``
     - Parent directory for all runs (default ``./peat_results``).
   * - ``--run-dir PATH``
     - Use this exact directory for the run instead of a sub-directory of the output directory.
   * - ``-v``, ``--verbose``
     - Print ``DEBUG``-level log messages to the terminal (they are always written to the log file).
   * - ``-V``, ``--debug``
     - Enable debugging output; repeat for more detail (``-VV``, ``-VVV``, up to ``-VVVV``).
       Detailed protocol output generally starts at level 2.
   * - ``-q``, ``--quiet``
     - Don't print log messages to the terminal. Combine with ``-E`` for machine-readable output.
   * - ``-E``, ``--print-results``, ``--json``
     - Print the :term:`JSON` results of the operation to standard output.
   * - ``--dry-run``
     - Do everything except execute the command's actions (no packets are sent). Useful to
       verify a configuration before touching devices.
   * - ``-I PATH...``, ``--import-modules PATH...``
     - Import third-party device modules from ``.py`` files or directories. See
       :doc:`third_party_modules`.
   * - ``--no-color``, ``--no-logo``
     - Plain terminal output; skip the start-up logo.
   * - ``-e [URL]``, ``--elastic-server [URL]``
     - Export results to Elasticsearch or OpenSearch (``http://localhost:9200/`` if no URL
       is given). See :doc:`elasticsearch`.
   * - ``--list-modules``, ``--list-aliases``, ``--list-alias-mappings``, ``--list-all``
     - Print the imported device modules and their aliases as JSON, then exit.
   * - ``--pdb``, ``--repl``
     - Development aids: drop into the Python debugger or interpreter after initialization.

.. _selecting-modules:

Selecting device modules
========================
By default PEAT uses every module that supports the command (for example, all modules
with network identification methods for a scan). Limit it with ``-d`` (``--device-types``)
to the modules you expect. **We strongly recommend doing so on production networks**: it
makes scans faster and sends fewer packets to devices that don't understand them.

``-d`` accepts module names and aliases, case-insensitively. Aliases include vendor names
(``sel``, ``rockwell``), device classes (``plc``, ``rtu``, ``relay``), and short names
(``clx`` for ControlLogix):

.. code-block:: bash

   peat scan -d selrelay -i 192.0.2.0/24           # one module
   peat scan -d sel -i 192.0.2.0/24                # every SEL module (relays, RTACs, 3620)
   peat scan -d plc -i 192.0.2.0/24                # every module whose device type is PLC
   peat scan -d m340 controllogix -i 192.0.2.0/24  # several modules

   # What is available
   peat scan --list-modules
   peat scan --list-aliases
   peat scan --list-alias-mappings

.. note::
   ``--list-modules`` lists *all* imported modules, including ones that don't support the
   current command (for example, parse-only modules show up for ``peat scan``).

.. _targets:

Specifying targets
==================
Active commands (``scan``, ``pull``, ``push``) take targets with one of these arguments:

- ``-i`` (``--ip``, ``--hosts``): network hosts. Any mix of IP addresses, hostnames,
  :term:`CIDR` networks, ranges, and files containing hosts (one per line, or a JSON
  array). Ranges can be used in any octet: ``192.0.2.200-205`` or
  ``172.16-30.80-90.12-14``. Labels of hosts defined in the configuration file's ``hosts``
  section also work.
- ``-b`` (``--broadcast``): broadcast targets for :ref:`broadcast scanning
  <broadcast-scanning>`: networks, broadcast addresses, interface names, or files of them.
- ``-s`` (``--serial``): serial ports, as names (``COM4``, ``/dev/ttyUSB0``) or numbers
  and ranges (``0-4`` is ``COM0`` to ``COM4`` on Windows, ``/dev/ttyS0`` to ``/dev/ttyS4``
  on Linux).
- ``-f`` (``--file``): a JSON summary from a previous scan, pull, or push. The verified
  hosts in it become the targets, which allows chaining runs: ``peat scan ... -q -E | peat pull -f -``
  (``-`` reads from standard input).

.. code-block:: bash

   peat scan -i 192.0.2.1
   peat scan -i 192.0.2.0/24 10.0.0.5-10 relay-7.example.net
   peat scan -i examples/target_hosts.txt examples/target_hosts.json 172.16.3.0/24
   peat pull -f peat_results/first_scan/summaries/scan-summary.json
   peat scan -s 0-4 --baudrates 9600 19200

Example files: :download:`target_hosts.txt <../../examples/target_hosts.txt>`,
:download:`target_hosts.json <../../examples/target_hosts.json>`,
:download:`broadcast_targets.txt <../../examples/broadcast_targets.txt>`.

Timeouts and threads
====================
- ``-T SECONDS`` (``--timeout``) sets how long to wait for responses (default 5.0). Lower
  values speed up scans of networks with many unresponsive hosts; raise it for slow links
  or sluggish devices.
- :attr:`MAX_THREADS <peat.settings.Configuration.MAX_THREADS>` (configuration file or
  ``PEAT_MAX_THREADS``) caps concurrent host checks (default 260). Lower it on
  constrained hosts or fragile networks.
- ``-Y`` (``--assume-online``) skips the online check (like ``nmap -Pn``). Use it when
  devices or firewalls block ARP and ICMP; it makes scans of many hosts much slower.

.. _windows-usage:

Windows notes
=============
Run PEAT in an **Administrator** PowerShell terminal or script. Running as a standard user
restricts certain Windows networking APIs, which affects :term:`ICMP` and :term:`ARP` host
checks, broadcast scanning, and network sniffing, so scans are slower and less reliable.
Install `Npcap <https://npcap.com/>`__ for raw-socket features (it comes with Wireshark).
PEAT also runs in a legacy ``cmd`` terminal, but colors and formatting may not render well.

Paths work the same as elsewhere on Windows: ``peat parse -d m340 'C:\Projects\Station.apx'``.
Note that PowerShell's ``Get-Content`` can't pipe binary files; use a path argument or
file redirection (``<``) for binary project files.

Exit codes and output streams
=============================
PEAT writes log messages to **standard error** and results (``-E``) to **standard
output**, so the two can be separated with normal shell redirection. The exit code is
``0`` on success and ``1`` if an error occurred during the run (for example a device
failed to pull or initialization failed), which makes PEAT usable in scripts and
schedulers:

.. code-block:: bash

   if peat pull -q -c site.yaml -d selrelay -i 192.0.2.0/24; then
       echo "pull succeeded"
   fi
