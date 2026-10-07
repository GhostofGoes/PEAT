***************************
Pushing to devices (REPEAT)
***************************
``peat push`` uploads configuration or firmware to a device. The typical use is
**recovery**: restoring a known-good configuration or firmware image after an incident or
a bad change, which is why the capability is also called :term:`REPEAT`. Pushing is
supported by a subset of modules; see the "Push" entries in
:doc:`/getting_started/supported_devices`.

.. danger::
   A push changes the device. Pushing the wrong file, or pushing to the wrong device, can
   take a protection relay or controller out of service. Always:

   - verify the target with a scan or ``--dry-run`` first,
   - push to one device before pushing to many,
   - have the device's current configuration backed up (a ``peat pull`` does this), and
   - coordinate with the process owners.

Basic usage
===========
Push takes the device module (``-d``, a single module), the targets (``-i``), the push
type (``-t config`` or ``-t firmware``, when the module supports both), and the file or
directory to push as the positional argument. The ``--`` before the path is required.

.. code-block:: bash

   # Push a single configuration file to an SEL relay
   peat push -d selrelay -i 192.0.2.1 -- SET_1.TXT

   # Push a directory of configuration files to an SEL-451 relay
   peat push -d selrelay -i 192.0.2.1 -- ./SETTINGS/

   # Push firmware to an Allen-Bradley ControlLogix 1756 PLC
   peat push -d controllogix -i 192.0.2.1 -t firmware -- ./1756.011.dmk

   # Deploy a compiled program to an OpenPLC Runtime v4 instance
   peat push -d openplcv4 -c openplc-config.yaml -i 192.0.2.40 -- ./program.zip

   # Dry run: verify the targets and configuration, push nothing
   peat push --dry-run -d selrelay -i 192.0.2.21 -c peat-config.yaml -- ./SETTINGS/

Only a single file or directory can be given per push. To push a specific set of files,
copy them into a new directory and push that directory:

.. code-block:: bash

   mkdir ./custom_configs/
   cp ./SET_1.TXT ./SET_6.TXT ./custom_configs/
   peat push -d selrelay -i 192.0.2.1 -- ./custom_configs/

How a push works
================
By default PEAT scans and verifies the targets first, and pushes only to the devices that
were positively identified as the type given with ``-d``. This protects against pushing to
the wrong device. Each module then performs the upload in the device's native way: SEL
relays receive settings files over FTP and are optionally restarted via Telnet
(``restart_after_push``); ControlLogix PLCs receive firmware via :term:`CIP`; OpenPLC
receives a program archive through its REST API.

``--push-skip-scan`` skips the verification scan (and implicitly assumes the hosts are
online). Use it only when a scan is impossible, for example when the device's
identification protocols are disabled:

.. code-block:: bash

   peat push --push-skip-scan -d selrelay -i 192.0.2.22 -- ./SET_1.TXT

Pushing to several devices at once is possible (``-i 192.0.2.0/24 192.0.0.0/24``), which is
convenient for a fleet-wide setting change, but combine it with ``-d`` and a configuration
file, and test on one device first.

Device notes
============
- **SEL relays**: settings are pushed as the individual ``SET_*.TXT`` files, since
  ``SET_ALL.TXT`` is read-only on the relay. Set ``sel.restart_after_push: true`` in the
  configuration to apply the settings by restarting the relay. See
  :doc:`/reference/devices/sel`.
- **ControlLogix**: firmware ``.dmk`` images are pushed over CIP. The PLC must be in a mode
  that accepts a firmware update, and the update takes several minutes.
- **SCEPTRE** virtual field devices: pull and parse only; the module does not implement
  push, although it pulls configuration and firmware over FTP.
- **OpenPLC Runtime v4**: pushes a program ``.zip`` and triggers a build; set
  ``clean_upload`` to force a clean rebuild. See :doc:`/reference/devices/openplc`.

Results
=======
A push run produces a run directory like any other command, with the scan summary of the
verification phase, logs including the protocol transcripts, and ``device-data-*.json``
files for the devices pushed to. The push result (success or failure) is in the log and
reflected in PEAT's exit code.

Examples
========
The complete list of push examples from ``peat push --examples``:

.. literalinclude:: ../../peat/cli_args.py
   :language: bash
   :start-after: push_examples = """
   :end-before: """  # End push examples
