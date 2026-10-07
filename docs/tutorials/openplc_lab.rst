**************************************
A PEAT lab with OpenPLC in a container
**************************************
*You want to see PEAT scan, pull from, and push to a real controller before pointing it at
anything that matters, and you don't have a PLC on your desk.* :peat-icon:`openplc` OpenPLC Runtime v4 is an
open-source soft PLC that runs in a container and exposes the REST API PEAT's
:class:`~peat.modules.openplc.openplcv4.OpenPLCv4` module talks to. In about fifteen
minutes you'll have a lab you can reset at will. This is also exactly how PEAT's own
continuous integration tests the module.

What you need
=============
- Docker (or Podman) on Linux, macOS, or Windows
- PEAT installed (any distribution; the examples use the ``peat`` executable)
- The PEAT repository checked out, or two files from it:
  `openplc-config.yaml <https://github.com/sandialabs/PEAT/blob/main/examples/openplc-config.yaml>`__
  and the example program
  `Relay_Blink_PLC.zip <https://github.com/sandialabs/PEAT/blob/main/tests/modules/openplc/data_files/Relay_Blink_PLC.zip>`__

Step 1: start the runtime
=========================
Start the official OpenPLC Runtime v4 image with its API on port 8443. The capabilities
let the runtime use real-time scheduling; the volume keeps its state between restarts.

.. code-block:: bash

   docker run -d --name openplc-runtime -p 8443:8443 \
       --cap-add=SYS_NICE --cap-add=SYS_RESOURCE \
       -v openplc-runtime-data:/var/run/runtime \
       ghcr.io/autonomy-logic/openplc-runtime:latest

   # Wait for the API to come up
   until curl -k -s https://127.0.0.1:8443/api/version > /dev/null; do sleep 2; done
   curl -k -s https://127.0.0.1:8443/api/version

A fresh runtime has no users, and the API requires authentication for everything except
the version endpoint. Create an account PEAT will use:

.. code-block:: bash

   curl -k -X POST https://127.0.0.1:8443/api/create-user \
       -H "Content-Type: application/json" \
       -d '{"username": "admin", "password": "admin", "role": "user"}'

   # Check that logging in works (returns an access token)
   curl -k -s -X POST https://127.0.0.1:8443/api/login \
       -H "Content-Type: application/json" \
       -d '{"username": "admin", "password": "admin"}'

Step 2: configure PEAT
======================
The example configuration sets the credentials and a plugin to query. It applies to every
OpenPLC device PEAT talks to in a run:

.. literalinclude:: ../../examples/openplc-config.yaml
   :language: yaml
   :caption: examples/openplc-config.yaml

Step 3: scan
============
Scan the loopback address with only the OpenPLC module. (``127.0.0.1`` is always treated
as online, so no elevated permissions are needed for this lab.)

.. code-block:: console

   $ peat scan -R lab-scan -d openplcv4 -i 127.0.0.1
   ...
   | Running scan of 1 target using 1 module (comm_type: unicast_ip)
   | Checking online status of 1 hosts using ARP and/or ICMP requests
   | 1 hosts are responding (checked 1 hosts in 0 seconds)
   | Scanning 1 IP using 1 module: OpenPLCv4
   | 127.0.0.1    | Checking 1 port for 127.0.0.1 using 1 method
   | 127.0.0.1    | 127.0.0.1 has 1 open port with 1 known protocol: https
   | 127.0.0.1    | Fingerprinting 127.0.0.1 using 1 matching method
   | 127.0.0.1    | Identification method 'https' from module 'OpenPLCv4' succeeded for 127.0.0.1
   | Completed scan of 1 device in 0.31 seconds (1 result)
   | Saved scan summary to peat_results/lab-scan/summaries/scan-summary.json

The module identified the runtime from ``GET /api/version`` on port 8443, without
credentials. The scan summary now contains the device with its OS name and version
(``OpenPLC Runtime v4``) and the verified ``openplc_api`` service. An example of what a
complete scan summary of an OpenPLC instance looks like is
``examples/example-openplc-scan-summary.json``:

.. literalinclude:: ../../examples/example-openplc-scan-summary.json
   :language: json
   :lines: 1-40
   :caption: First 40 lines of ``examples/example-openplc-scan-summary.json``

Step 4: pull
============
Now authenticate and collect everything the runtime exposes:

.. code-block:: console

   $ peat pull -R lab-pull -d openplcv4 -c openplc-config.yaml -i 127.0.0.1
   ...
   | Beginning pull for 1 devices
   | 127.0.0.1    | Pulling from 127.0.0.1
   | 127.0.0.1    | Finished pulling from 127.0.0.1
   | Finished pulling from 1 devices in 1.2 seconds
   | Saved pull summary to peat_results/lab-pull/summaries/pull-summary.json

Look at what came back:

.. code-block:: console

   $ tree peat_results/lab-pull/devices/127.0.0.1/
   peat_results/lab-pull/devices/127.0.0.1/
   ├── compilation_status.log
   ├── device-data-event.jsonl
   ├── device-data-files.jsonl
   ├── device-data-full.json
   ├── device-data-interface.jsonl
   ├── device-data-service.jsonl
   ├── device-data-summary.json
   ├── device-data-users.jsonl
   ├── ethercat_status.json
   └── openplc_runtime.log

   $ jq '{run_mode, status, os: .os.full, users: [.users[].name], files: [.files[].name]}' \
         peat_results/lab-pull/devices/127.0.0.1/device-data-summary.json
   {
     "run_mode": "STOPPED",
     "status": "Offline",
     "os": "Autonomy Logic, Inc. OpenPLC Runtime v4 v4.1.7",
     "users": ["admin"],
     "files": ["compilation_status.log", "ethercat_status.json", "openplc_runtime.log"]
   }

The pull queried the status (including timing statistics under ``extra.timing_stats``),
the user list, the runtime log (saved as a file *and* parsed into ``event`` entries), the
last compilation status, the serial ports, and the EtherCAT plugin status configured in
``plugins_to_query``. :doc:`/reference/devices/openplc` describes each endpoint and field.

Step 5: push a program
======================
Deploy the example program, a compiled OpenPLC project archive, to the runtime. PEAT
verifies the device first, uploads the archive to ``/api/upload-file``, and asks for a
clean build (``clean_upload: true``):

.. code-block:: console

   $ peat push -R lab-push -d openplcv4 -c openplc-config.yaml -i 127.0.0.1 -- Relay_Blink_PLC.zip
   ...
   | 127.0.0.1    | Identification method 'https' from module 'OpenPLCv4' succeeded for 127.0.0.1
   | 127.0.0.1    | Pushing config to 127.0.0.1
   | 127.0.0.1    | Config push to 127.0.0.1 was successful

Pull again and you'll see the compilation in ``compilation_status.log``, the new program
in ``logic.name``, and a ``file_push`` event in ``device-data-event.jsonl``:

.. code-block:: console

   $ peat pull -R lab-pull-2 -d openplcv4 -c openplc-config.yaml -i 127.0.0.1
   $ head -3 peat_results/lab-pull-2/devices/127.0.0.1/compilation_status.log
   Status: Compiled
   Exit Code: 0
   ---

Step 6: break things on purpose
===============================
A lab is for experiments. Some ideas:

- Change the password in the runtime and watch the pull fail, then fix it in the
  configuration. Run with ``-VV`` to see the HTTP exchange.
- Run the scan without ``-d`` and see how long PEAT spends on the other modules'
  methods, then compare with ``-d openplcv4``.
- Start a second runtime on another port and give it a per-host port override in the
  ``hosts`` section of the configuration.
- Export the pulls to Elasticsearch with ``-e`` (see :doc:`elasticsearch_dashboard`) and
  compare runs before and after the push.
- Read the module (``peat/modules/openplc/openplcv4.py``) alongside the pull output; it is
  a compact, modern example of a PEAT module, and the
  :doc:`/developer/module_developer_guide` uses it as a reference.

Clean up
========
.. code-block:: bash

   docker rm -f openplc-runtime
   docker volume rm openplc-runtime-data

How the CI uses this
====================
The ``Container Tests`` GitHub Actions workflow (``.github/workflows/tests-container.yml``)
runs these same steps automatically: it starts the runtime container, creates the
``admin`` user, and runs ``pytest --run-container tests/modules/openplc/`` which scans,
pushes ``Relay_Blink_PLC.zip``, and pulls, asserting on the results. If you write a module
for another device that has a container or simulator, this is the pattern to copy (see
:doc:`/contributing/testing`).
