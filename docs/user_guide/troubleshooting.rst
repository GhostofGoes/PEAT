***************
Troubleshooting
***************
Where to look when PEAT doesn't do what you expect, common problems and their fixes, and
the limitations that aren't bugs. For bugs that are known and tracked, see
:ref:`known-issues`.

Getting more information
========================
PEAT logs everything to the run directory's ``logs/`` folder regardless of what is shown
on the terminal, so the first step is usually to look at the log file of the run that
misbehaved:

.. code-block:: bash

   # The log of the newest run
   less "$(ls -td peat_results/*/ | head -1)logs/peat.log"

Then re-run with more output:

- ``-v`` (``--verbose``) prints ``DEBUG``-level messages to the terminal (they're always in
  the log file).
- ``-V`` (``--debug``) enables debugging output; repeat it for more detail. Level 1
  (``-V``) adds detailed program flow, level 2 (``-VV``) adds protocol-level detail such as
  the commands sent to devices and their responses, levels 3 and 4 add raw packet and data
  dumps. The debugging level can also be set with the
  :attr:`DEBUG <peat.settings.Configuration.DEBUG>` configuration option.
- ``--dry-run`` runs initialization (configuration, module imports, target parsing) without
  executing anything, which isolates configuration problems from device problems.

.. code-block:: bash
   :caption: Troubleshooting a pull from SEL devices on a subnet

   peat pull -VVV -R example_tshoot -d selrelay -i 192.0.2.0/24

   # The files generated
   ls -lAht peat_results/example_tshoot/logs/

   # The log, and the raw Telnet conversation with the devices
   less peat_results/example_tshoot/logs/peat.log
   less peat_results/example_tshoot/logs/telnet.log

Log files
=========
.. list-table::
   :header-rows: 1
   :widths: 18 52 30

   * - Name
     - Description
     - Default path
   * - Log
     - Primary log file for PEAT. Human-readable text with most logging events generated
       during the run, as well as metadata generated at start-up.
     - ``peat_results/<run-dir>/logs/peat.log``
   * - JSON logs
     - The same events as :term:`JSON`, one record per line (JSON Lines). Useful for
       ingesting into automated tools, e.g. a :term:`SIEM` or log processor, and for
       rebuilding the ``peat-logs`` Elasticsearch index.
     - ``peat_results/<run-dir>/logs/json-log.jsonl``
   * - Debug info
     - Information about the system PEAT ran on and how it was invoked, gathered at
       start-up. Include it in bug reports.
     - ``peat_results/<run-dir>/logs/debug-info.txt``
   * - Protocol logs
     - Raw protocol conversations, in human-readable text: Telnet (``telnet.log``), and
       EtherNet/IP/CIP (``enip/``). Useful for troubleshooting modules that use these
       protocols.
     - ``peat_results/<run-dir>/logs/telnet.log``, ``peat_results/<run-dir>/logs/enip/``
   * - Elasticsearch log
     - Logging events from PEAT's Elasticsearch client, in a human-readable text format.
       These are **not** written to the main log.
     - ``peat_results/<run-dir>/logs/elasticsearch.log``
   * - Configuration
     - The configuration PEAT used for the run, in :term:`YAML` format, from all sources.
     - ``peat_results/<run-dir>/peat_metadata/peat_configuration.yaml``
   * - State
     - PEAT's internal state as of the end of the run, in JSON and YAML.
     - ``peat_results/<run-dir>/peat_metadata/peat_state.yaml``

Much of this data is also stored in Elasticsearch when export is enabled (see
:ref:`peat-index-reference`).

Common problems
===============

PEAT hangs for a few seconds before printing anything
-----------------------------------------------------
Normal. The executable unpacks itself to the temporary directory and imports its
dependencies, which takes a few seconds. ``--no-logo`` doesn't make it faster.

No hosts are responding, but the devices are up
-----------------------------------------------
- PEAT needs root (Linux) or Administrator (Windows) rights to use :term:`ARP` and
  :term:`ICMP` for online checks; otherwise it tries a TCP connection to port 80, which
  many devices don't listen on. Re-run with ``sudo`` or from an elevated PowerShell, or
  set :attr:`SYN_PORT <peat.settings.Configuration.SYN_PORT>` to a port the devices do
  have open (for example 502 for Modbus devices or 44818 for CIP devices).
- Devices behind a firewall or router that drops ICMP (the SEL RTAC drops ICMP by default)
  appear offline. Use ``-Y`` (``--assume-online``) for those addresses.
- On Linux, PEAT warns ``RAW sockets are available, however tcpdump is not installed`` when
  libpcap/tcpdump are missing; install them (``sudo apt install tcpdump``) for reliable
  ARP/ICMP checks.
- On Windows, install `Npcap <https://npcap.com/>`__.
- In a container, ``--network host`` is required.

Hosts are online but not identified ("verified")
------------------------------------------------
- Make sure the module for the device is selected (``-d``) or that no ``-d`` is limiting
  the scan to the wrong modules. ``peat scan --list-modules`` shows what's available.
- The device's identification protocol may be disabled or on a non-default port. Set the
  port under ``device_options.<protocol>.port`` or per host in ``hosts``.
- Try ``--intensive-scan`` against that single address to run every identification method
  regardless of open ports (not recommended on sensitive devices).
- Raise the timeout (``-T 10``) for slow devices or links.
- The device may not be supported; compare with :doc:`/getting_started/supported_devices`.

A pull fails or is incomplete
-----------------------------
- Check credentials in the configuration file (``device_options`` and ``hosts``). The log
  shows login failures. Run with ``-VV`` to see the protocol exchange, and check
  ``telnet.log``.
- Restrict ``pull_methods`` to protocols the device actually has enabled, for example only
  Telnet when FTP is disabled on SEL relays (see
  :download:`peat-config-sel-force-telnet.yaml <../../examples/peat-config-sel-force-telnet.yaml>`).
- Some devices are slow or limit concurrent sessions. Make sure no other tool (or
  engineer) is logged in, and increase ``-T``.
- Large artifacts (event records, HMI files) can time out; exclude them with
  ``never_download_dirs`` / ``never_download_files`` or raise the module's timeouts.
- PEAT keeps going after a failure on one device and reports the failure in the log, the
  summary, and its exit code.

MAC addresses are missing
-------------------------
MAC addresses can only be resolved for devices on the local subnet (same broadcast
domain), and only with root/Administrator rights. In :term:`WSL`, MAC lookups don't work
at all.

A parse produces nothing or odd results
---------------------------------------
- Check the module matches the file (``-d``), and that the file isn't empty (``peat parse``
  may behave oddly with 0-byte files).
- PEAT selects modules by file name patterns and content signatures; a renamed file may
  need ``-d`` to be parsed. Run with ``-v`` to see which module was chosen and why.
- Project files saved by very old or very new versions of vendor software may not be
  understood. Please report the version in an issue.

Windows: colors and formatting look wrong
-----------------------------------------
Use PowerShell or Windows Terminal rather than ``cmd``. Disable colors with ``--no-color``
or customize a problematic color with Loguru's ``LOGURU_<LEVEL>_COLOR`` environment
variables (see :doc:`/contributing/logging`).

Elasticsearch export problems
-----------------------------
Logging events from PEAT's Elasticsearch internals are not written to the normal log.
Instead, they go to ``logs/elasticsearch.log`` in the run directory. Common issues:

- **Connection failures**: check the URL scheme, host, port, and credentials, and
  reachability from the host running PEAT (``curl http://host:9200``). Raise
  ``--elastic-timeout`` for slow servers.
- **Bad type mappings**: a field in an existing index has a different type than PEAT
  expects, which produces ``mapper_parsing_exception`` errors. Export any important data
  first (for example with
  `elasticsearch-dump <https://github.com/elasticsearch-dump/elasticsearch-dump>`__), delete
  the index, and re-run: ``curl -XDELETE localhost:9200/ot-device-hosts-timeseries-*``.
- The documents PEAT tried to send are in ``elastic_data/`` in the run directory, so
  nothing is lost; they can be loaded once the server is fixed.

See :doc:`elasticsearch` for details.

Permission denied writing results
---------------------------------
PEAT writes to ``./peat_results/`` in the current directory. Run it from a directory you
can write to, or set ``-o`` / :attr:`OUT_DIR <peat.settings.Configuration.OUT_DIR>`. When
running with ``sudo``, PEAT fixes the ownership of the files it created back to the
invoking user (using ``SUDO_UID``); it warns when it can't.

Limitations
===========
General limitations of PEAT that aren't bugs. Refer to :ref:`known-issues` for a list of
known issues (bugs).

- MAC addresses of devices will not be resolved during a scan or pull if the device is
  behind a router or gateway (in another subnet than the system running PEAT).
- Checking host online status with ARP or ICMP requires root (Linux) or Administrator
  (Windows) permissions. Without them PEAT falls back to TCP connection attempts, which
  are less reliable and may be blocked by firewalls.
- Pulls run one device at a time; very large populations take a while.
- Only RS-232 serial connections are supported (as of 2024), and only a few modules
  support serial.
- Broadcast scanning supports IP (layer 3) broadcasts only, and is implemented for the
  ControlLogix module.
- Pillage runs on Linux only, requires root, and can't attach disk images from inside a
  container.
- HEAT supports a limited set of protocols and requires an Elasticsearch server to be
  configured.

Reporting a problem
===================
Open an issue on `GitHub <https://github.com/sandialabs/PEAT/issues>`__ with:

- The PEAT version (``peat --version``) and how it was installed (executable, container,
  Python package)
- The command you ran, with any sensitive values (credentials, internal addresses) removed
- The relevant portion of ``logs/peat.log`` (run with ``-VV`` if possible) and
  ``logs/debug-info.txt``
- The device vendor, model, and firmware version, if a device is involved

For sensitive environments, or to report a security issue, see the project's
`security policy <https://github.com/sandialabs/PEAT/blob/main/SECURITY.rst>`__ or email
``peat (at) sandia.gov``.
