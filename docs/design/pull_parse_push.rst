********************************
How pull, parse, and push work
********************************
The three commands that move data between PEAT and devices or files, and how the
high-level API, the module API, and the data model cooperate in each. The scan phase they
share is described in :doc:`scanning`.

Pull
====
:func:`peat.api.pull_api.pull` turns a list of targets into a pull summary.

#. **Scan.** Unless ``--skip-scan`` was given, :func:`~peat.api.scan_api.scan` runs with
   the same targets, communication type, and modules, and the datastore is
   de-duplicated. If nothing was verified, the pull fails. With ``--skip-scan``, the IP
   targets are resolved and each is assigned a module: the ``peat_module`` of a matching
   ``hosts`` entry in the configuration, or the single module given with ``-d``.
#. **Pull from each verified device, one at a time.** For each device,
   ``device._module.pull(device)`` is called. :meth:`DeviceModule.pull()
   <peat.device.DeviceModule.pull>` is the base class wrapper: it validates its inputs,
   logs the start, calls the module's ``_pull()``, and on success runs
   :meth:`~peat.device.DeviceModule.update_dev` (post-processing such as populating
   derived fields and annotations) and purges duplicate list entries.
#. **Inside ``_pull()``**, a module typically:

   - reads its options (``dev.options``, a merge of module defaults, ``device_options``,
     and the host's options), including which protocols to use (``pull_methods``)
     and credentials;
   - connects with the protocol clients (FTP, Telnet, HTTP, SSH, serial, ...), retrieving
     files, running diagnostic commands, and scraping web pages, recording per-protocol
     success in ``dev.successful_pulls``;
   - writes every artifact it retrieves, unmodified, to the device's output directory
     with :meth:`DeviceData.write_file() <peat.data.models.DeviceData.write_file>`, and
     records it in ``dev.files`` (with hashes) so it ends up in the data model and the
     ``ot-device-files`` index;
   - parses what it retrieved with the same code path as ``peat parse`` (its ``_parse()``
     or parser functions), filling in firmware, logic, configuration, events, registers,
     and so on;
   - returns ``True`` if the pull was successful enough to count. PEAT's philosophy is to
     get as much as possible and fail safely: a failure to retrieve one artifact is logged
     and the pull continues.

#. **Export.** After each successful device, its data is exported to Elasticsearch (if
   enabled); after all devices, ``export_device_data`` writes the
   ``device-data-*`` files for every verified device. Failures set ``state.error`` so the
   exit code reflects them.
#. **Summary.** The pull summary records the devices pulled, the targets, the modules,
   the duration, and each device's exported data (without large fields), and is saved to
   ``summaries/pull-summary.json`` and the ``peat-pull-summaries`` index.

Parse
=====
:func:`peat.api.parse_api.parse` turns file or directory paths (or standard input) into a
parse summary.

#. **Resolve modules.** The requested modules (or all modules, when ``-d`` is omitted) are
   filtered to those that can parse: modules with ``filename_patterns`` or
   ``file_signatures``, plus modules with ``can_parse_dir`` when a directory was given.
   Standard input requires exactly one module.
#. **Resolve files.** The simple cases, a single module with standard input, one file, or a
   directory the module can handle itself, go straight to the module. Otherwise, each
   directory is searched recursively (multi-threaded, see
   :attr:`OVERRIDE_MAX_FILE_DISCOVERY_THREADS <peat.settings.Configuration.OVERRIDE_MAX_FILE_DISCOVERY_THREADS>`),
   and every file is matched against the modules' ``filename_patterns`` (case-insensitive
   shell globs) and then, since the :ref:`file signature <file-signatures>` feature, against
   their ``file_signatures`` (magic bytes, XML tags, substrings, custom checks). Files that
   match are parsed with the matching module; files that match nothing are skipped. Name
   matching keeps its precedence to preserve existing behavior; signatures are the
   fallback that lets renamed or oddly named files be recognized.
#. **Parse each file.** :meth:`DeviceModule.parse() <peat.device.DeviceModule.parse>` is
   the wrapper: it accepts a path, raw bytes, or a stream, works out a device ID and a
   file name (using the matching signature's ``default_filename`` for nameless data),
   creates or looks up the ``DeviceData``, records the input file in ``dev.files`` with
   hashes and metadata, calls the module's ``_parse()``, and post-processes the result.
   Network lookups (resolving IPs, MACs, hostnames found in files) are disabled for
   parses unless explicitly enabled, so parsing is safe on an isolated machine.
#. **Export and summarize.** Devices are exported as in a pull; the summary lists each
   file, its module, its results, and any failures, and is saved to
   ``summaries/parse-summary.json`` and the ``peat-parse-summaries`` index.

Because pulls parse with the same code, improvements to a parser benefit both
re-parsing of old backups and live pulls.

Push
====
:func:`peat.api.push_api.push` uploads one file or directory to one or more devices.

#. **Validate inputs**: the source path exists and the push type is ``config`` or
   ``firmware``.
#. **Scan and verify** the targets with the given module (unless ``--push-skip-scan``,
   which requires a single module and marks every target as active and verified). Only
   verified devices are pushed to; this is the safeguard against pushing to the wrong
   device.
#. **Push to each device.** :meth:`DeviceModule.push() <peat.device.DeviceModule.push>`
   validates, logs, and calls the module's ``_push(dev, path, push_type)``, which performs
   the upload in the device's native way (FTP uploads and a Telnet restart for SEL
   relays, CIP firmware transfer for ControlLogix, a REST API upload for OpenPLC). The
   outcome is recorded as an event on the device (``action: file_push``,
   ``outcome: success``/``failure``).
#. **Export** the devices' data and report success or failure through the log and the
   exit code.

Where the base class helps
==========================
:class:`~peat.device.DeviceModule` deliberately keeps the public verbs (``pull``,
``parse``, ``push``) in the base class and asks modules to implement the underscore
versions (``_pull``, ``_parse``, ``_push``). The wrappers provide consistent validation,
logging, error handling, device ID and file bookkeeping, and post-processing
(:meth:`~peat.device.DeviceModule.update_dev`: ``annotate_fields``, derived description
and ``related`` fields, duplicate purging), so every module behaves the same from the
outside and module authors can focus on the device. :meth:`~peat.device.DeviceModule.method_implemented`
lets the APIs ask whether a module supports a verb.
