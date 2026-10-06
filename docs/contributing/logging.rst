*******
Logging
*******
The `Loguru <https://loguru.readthedocs.io/en/stable/>`__ library is used for *all*
logging messages, that is, every message intended to be read by a human user. Log
messages are written to standard error (not standard output), to the run directory's log
files, and to Elasticsearch when configured. Writing to standard error is intentional: it
lets users separate command output (``--print-results`` on standard output) from the log.

The use of :func:`print` and :func:`~pprint.pprint` is forbidden for user messages. They
are only used to print final results (for example the scan summary with ``-E``), and
those lines carry ``# noqa: T201`` (``# noqa: T203`` for ``pprint``) so the linter accepts
them.

Logging levels
==============
- ``CRITICAL``: something went really wrong, usually indicating a bug in PEAT or an
  unusual system error. Usually results in premature termination of the run.
- ``ERROR``: bad user input (an input file doesn't exist), a high-level action failed (a
  pull from a device was unsuccessful when it was supposed to succeed), a general system
  error. Issues logged at ``ERROR`` often result in a failed run (exit code 1), but may not
  warrant terminating early. For example, when pulling from five devices and one fails,
  the other four proceed.
- ``WARNING``: anything the user should be aware of that may not impact the run or be a
  failure. For example, if PEAT retrieves ten data points and one best-effort data point
  (say, battery statistics) is unavailable, that's a warning, not an error.
- ``INFO``: general progress of a run. Enough for the user to know what is happening,
  without being verbose. If more detail would be useful, log it at ``DEBUG``, where the
  user can enable it with ``-v``.
- ``DEBUG``: verbose messages with additional information for troubleshooting or
  understanding what PEAT is doing. Always saved to the log file; printed to the terminal
  with ``-v`` (``--verbose``).
- ``TRACE``, ``TRACE2``, ``TRACE3``, ``TRACE4``: four levels of very verbose logging for
  debugging, enabled by ``-V``: ``-VVV`` sets the debug level to 3 and enables ``TRACE``,
  ``TRACE2``, and ``TRACE3``. Protocol-level detail (commands and responses) generally
  starts at level 2. If the debug level is 0, ``TRACE`` messages are not saved anywhere.

Usage
=====
.. code-block:: python
   :caption: Logging examples

   from peat import log

   log.info("This is an informational message")
   log.debug("Shown with -v")
   log.trace("Debug level 1 message (-V)")
   log.trace4("Only logged if config.DEBUG == 4, e.g. with -VVVV")

   # DeviceModule classes have a "log" attribute that adds the class name as metadata.
   # From m340.py:
   @classmethod
   def _verify_snmp(cls, dev: DeviceData) -> bool:
       ...
       cls.log.trace(f"Verifying {dev.ip}:{port} via SNMP (timeout: {timeout})")

   # To add the target of an action (IP address, serial port, hostname, ...) to every
   # message, bind a logger with "target" set. From ab_push.py:
   _log = log.bind(target=ip)
   _log.info(f"Pushing firmware to {ip}:{port} (size: {utils.fmt_size(len(firmware))})")

   # Exceptions: log.exception() includes the traceback (at ERROR level)
   try:
       ...
   except Exception:
       log.exception(f"Failed to pull from {dev.get_id()}")

Guidelines:

- Include what the message is about (the device, file, protocol, port) so it's useful when
  read later in ``peat.log`` among messages from fifty other devices.
- Don't log credentials or full URLs with credentials. ``Elastic.safe_url`` exists for
  this reason.
- Use f-strings for messages (the ``G004`` lint rule is disabled for this).
- Keep ``INFO`` quiet in loops; log a summary line instead of one line per item, and put
  per-item detail at ``DEBUG``.

How logging is wired up
=======================
``peat/__init__.py`` configures Loguru before anything else is imported: it removes the
default handler, adds the ``TRACE2``-``TRACE4`` levels, routes Python ``warnings`` and the
standard-library loggers of noisy dependencies (Scapy, requests, urllib3, elasticsearch)
through Loguru, and sets their levels. :func:`peat.log_utils.setup_logging`, called from
:func:`~peat.init.initialize_peat`, then adds the sinks for the run: the terminal
(standard error, level by ``-v``/``-q``), ``logs/peat.log``, ``logs/json-log.jsonl``
(one :term:`JSON` record per line, the source of the ``peat-logs`` Elasticsearch index),
``logs/debug-info.txt``, protocol transcripts (``telnet.log``, ``enip/``), and an
Elasticsearch sink when export is enabled. The order of imports in ``peat/__init__.py``
matters; see :doc:`codebase_tour`.

Customizing output
==================
Log formatting and colors can be customized at runtime with
`Loguru's environment variables <https://loguru.readthedocs.io/en/stable/api/logger.html#env>`__.
The usual reason is a terminal with color problems: instead of disabling colors entirely
with ``--no-color``, change the problematic color with ``LOGURU_<LEVEL>_COLOR``, e.g.
``LOGURU_DEBUG_COLOR="<cyan>"`` for ``DEBUG`` messages.
