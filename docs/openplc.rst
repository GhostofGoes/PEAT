.. _openplc_peat_module:

==============================
OpenPLC Runtime v4 PEAT Module
==============================

:Author: Th3BanHamm3r
:Version: 1.0
:Date: 2026-07-10

.. contents::
   :local:

Overview
========

This document provides in-depth documentation for the PEAT (Process Extraction and Analysis Tool) module designed for **OpenPLC Runtime v4**. The module enables discovery, fingerprinting, data collection, and program deployment on OpenPLC v4 instances via its native REST API.

For initial setup of the runtime environment, please refer to the official Autonomy Logic documentation:

.. seealso::

   * `OpenPLC Runtime v4 GitHub <https://github.com/Autonomy-Logic/openplc-runtime>`__
   * `OpenPLC Editor GitHub <https://github.com/Autonomy-Logic/openplc-editor>`__
   * `Autonomy Edge OpenPLC Documentation <https://edge.autonomylogic.com/docs/>`__
   * `OpenPLC Runtime v4 Documentation <https://github.com/Autonomy-Logic/openplc-runtime/tree/main/docs>`__
   * `OpenPLC Editor Documentation <https://github.com/Autonomy-Logic/openplc-editor/tree/main/docs>`__

PEAT Module Configuration
=========================

The :class:`~peat.modules.openplc.openplcv4.OpenPLCv4` module (``openplcv4.py``) defines the following default options in its ``default_options`` class attribute.

Default Options
---------------

.. code-block:: python

   default_options = {
       "openplcv4": {
           "username": "",
           "password": "",
           "pull_methods": ["https"],
           "clean_upload": True,
           "plugins_to_query": {},
       },
       "https": {
           "port": 8443,
           "ssl": True,
       },
   }

* **username/password**: Credentials for the OpenPLC v4 API. A user must be created on the runtime first.
* **pull_methods**: The module currently only supports ``https`` for data pulling.
* **clean_upload**: If ``true``, the module will instruct the runtime to wipe compilation caches before building an uploaded program.
* **plugins_to_query**: A mapping of plugin name to the command to send to that plugin during a data pull, for example ``{"ethercat": "status"}``. The output of each command is saved to a JSON file. The EtherCAT master status is added to the data model as a service (see :ref:`openplc-ethercat`); the output of other plugins is saved under ``extra.plugin_status``.
* **https**: Port and TLS settings for the runtime's REST API (the OpenPLC Runtime v4 default is HTTPS on port ``8443``).

These defaults can be overridden in the ``device_options`` section of the PEAT :doc:`YAML configuration file <configure>`, or per-host in the ``hosts`` section. For example:

.. code-block:: yaml

   device_options:
     openplcv4:
       username: "openplc"
       password: "openplc"
       pull_methods:
         - https
       clean_upload: true
       plugins_to_query:
         ethercat: status

Module Capabilities
===================

The module defines several core functions to interact with the OpenPLC v4 API.

Device Identification
---------------------

The module identifies OpenPLC v4 instances by sending a GET request to the ``/api/version`` endpoint. A successful response confirms the device's identity.

.. code-block:: http

   GET /api/version HTTP/1.1
   Host: {device_ip}:8443

Refer to this tool to control the OpenPLC Runtime v4 via Python scripts in order to automate deployment and C2; no Editor needed.

.. seealso::

   * `plc4.py - OpenPLC Runtime v4 CLI Utility <https://github.com/Th3BanHamm3r/OpenPLC-Runtime-v4-CLI-Utility>`__

Data Pulling (``peat pull``)
----------------------------

When ``peat pull`` is executed, the module authenticates and systematically pulls data from various API endpoints.

**Authentication:**

1. A ``POST`` request is made to ``/api/login`` with the provided username and password.
2. A successful login returns a JWT ``access_token``.
3. This token is used as a Bearer token in the ``Authorization`` header for all subsequent requests.

**Data Endpoints:**

The module collects data from the following endpoints:

* ``GET /api/status?include_stats=true``: Retrieves the main PLC status, including run mode (``RUNNING``, ``STOPPED``), the position of the RUN/STOP switch, loaded program name, and detailed timing statistics for each task.
* ``GET /api/get-users-info``: Retrieves a list of all registered users and their roles.
* ``GET /api/runtime-logs``: Extracts the latest runtime logs, which are then saved as events and a log file (``openplc_runtime.log``).
* ``GET /api/compilation-status``: Extracts the status and output of the last program compilation, saved to ``compilation_status.log``.
* ``GET /api/serial-ports``: Retrieves the serial ports available on the device.
* ``POST /api/plugin-command``: If ``plugins_to_query`` is configured, this endpoint is used to send commands to specific plugins (e.g., ``ethercat status``) and retrieves their output.

Program Pushing (``peat push``)
-------------------------------

The ``peat push`` command allows for deploying a compiled program to the runtime.

1. The module authenticates to the API.
2. It sends a ``POST`` request to ``/api/upload-file`` with the valid program ``.zip`` file.
3. The ``clean`` parameter can be set to force a clean build.

Output Data Structure
=====================

The data collected by the PEAT module is structured in a JSON format, as seen in the ``device-data-full.json`` file.

Key Fields:
-----------

* **description**: General device info, including vendor ("Autonomy Logic, Inc.") and product model.
* **run_mode**: Current PLC state, e.g., "RUNNING".
* **key_switch**: Position of the runtime's RUN/STOP switch (``switchPosition``), lowercase, e.g. ``run``. The switch is also in ``indicators`` (see below).
* **indicators**: The RUN/STOP switch as an indicator (``name: mode_switch``, ``type: switch``, ``category: mode``), with the raw position in ``value`` and the time it was read in ``timestamp``.
* **os**: Operating system details, specifically "OpenPLC Runtime v4" and its version.
* **logic.tasks**: Scan statistics of each PLC task (``timing_stats.tasks``): ``scan_count``, ``overruns``, ``scan_time_min``/``max``/``avg``. The cycle time and cycle latency statistics are in the task's ``extra`` in microseconds (e.g. ``cycle_time_avg_us``).
* **service**: The EtherCAT master (``protocol: ethercat``, ``role: master``) with its counters in ``statistics``, if the ``ethercat`` plugin was queried.
* **files**: The currently loaded PLC program (``category: logic``), and the files PEAT generated from the API responses: the runtime log and compilation status (``category: log``) and the plugin outputs (``category: diagnostic``). The description of the generated files says "generated by PEAT from the OpenPLC API": they are not files on the device.
* **interfaces**: A list of interfaces and that the device has made available.
* **event**: A detailed log of runtime events. The log level of each entry (e.g. ``INFO``) is in ``log_level`` (exported to Elasticsearch as ``log.level``).
* **users**: List of user accounts.
* **extra.plugin_status**: Contains the output from queried plugins other than ``ethercat``.
* **extra.timing_stats**: Only for runtimes that return the older flat timing statistics format (without ``tasks``).

Example Output:
===============

1. PLC Status & Run Mode
------------------------

Basic status information dictates the core operational state of the PLC.

.. code-block:: json

    "type": "PLC",
    "run_mode": "RUNNING",
    "status": "Online",
    "os": {
        "full": "Autonomy Logic, Inc. OpenPLC Runtime v4 v4.1.7",
        "name": "OpenPLC Runtime v4",
        "vendor": {
            "name": "Autonomy Logic, Inc."
        },
        "version": "v4.1.7"
    }

2. User Information
-------------------

The ``users`` array contains all registered accounts pulled from the runtime.

.. code-block:: json

    "users": [
        {
            "id": "1",
            "name": "admin"
        }
    ]

3. Task Timing Statistics and RUN/STOP Switch
---------------------------------------------

When statistics are included in the status pull, PEAT adds the scan statistics of each task to ``logic.tasks``. Times reported by the runtime in microseconds are converted to durations; minimums that were never measured (reported by the runtime as ``9223372036854775807``) are left out.

.. code-block:: json

    "logic": {
        "tasks": [
            {
                "extra": {
                    "cycle_latency_avg_us": 3,
                    "cycle_latency_max_us": 15,
                    "cycle_latency_min_us": 1,
                    "cycle_time_avg_us": 1000,
                    "cycle_time_max_us": 1010
                },
                "name": "TASK0",
                "overruns": 0,
                "scan_count": 120,
                "scan_time_avg": "0:00:00.000042",
                "scan_time_max": "0:00:00.000250",
                "scan_time_min": "0:00:00.000010"
            }
        ]
    },
    "key_switch": "run",
    "indicators": [
        {
            "category": "mode",
            "name": "mode_switch",
            "timestamp": "2026-07-16 17:40:02.123456+00:00",
            "type": "switch",
            "value": "run"
        }
    ]

4. File Extraction (Runtime, Compilation, & Plugin Logs)
--------------------------------------------------------

The raw ``openplc_runtime.log``, ``compilation_status.log``, and ``<plugin>_<command>.json`` are also dumped independently. These files are generated by PEAT from the API responses (they are not files on the device), which their description says.

.. code-block:: json

   "files": [
        {
            "category": [
                "log"
            ],
            "description": "Last compilation status, generated by PEAT from the OpenPLC API",
            "device": "192.168.10.20",
            "extension": "log",
            "name": "compilation_status.log"
        },
        {
            "category": [
                "diagnostic"
            ],
            "description": "Output for ethercat plugin (status), generated by PEAT from the OpenPLC API",
            "device": "192.168.10.20",
            "extension": "json",
            "mime_type": "application/json",
            "name": "ethercat_status.json"
        },
        {
            "category": [
                "log"
            ],
            "description": "Runtime logs, generated by PEAT from the OpenPLC API",
            "device": "192.168.10.20",
            "extension": "log",
            "name": "openplc_runtime.log"
        }
   ]

5. Runtime Events
-----------------

PEAT parses the raw text logs from the runtime endpoint, standardizing them into the ``event`` timeline.

.. code-block:: json

   "event": [
        {
            "created": "2026-07-02 19:11:08+00:00",
            "dataset": "runtime",
            "id": "29",
            "kind": [
                "event"
            ],
            "log_level": "INFO",
            "message": "Native plugin './build/plugins/libs7comm_plugin.so' symbols loaded successfully",
            "module": "OpenPLCv4",
            "provider": "192.168.10.20",
            "timezone": "UTC"
        }

.. _openplc-ethercat:

6. EtherCAT Master Status and Other Plugins
-------------------------------------------

If the ``ethercat`` plugin is queried (``plugins_to_query: {ethercat: status}``), the EtherCAT master becomes a service. Its counters are in the service ``statistics`` (with the time they were read in ``timestamp``): ``cycle_count`` is ``egress.packets`` (one EtherCAT frame per cycle) and ``wkc_error_count`` (working counter errors) is ``ingress.errors``. The other metrics are in ``statistics.extra``. The masters' name, state and slave count are in the service's ``extra.masters``. If there are several masters, the counters are summed and the other metrics are in ``statistics.extra`` per master name.

.. code-block:: json

   "service": [
       {
           "enabled": true,
           "extra": {
               "masters": [
                   {
                       "expected_wkc": 0,
                       "name": "default",
                       "plugin_state": "IDLE",
                       "slave_count": 0
                   }
               ]
           },
           "protocol": "ethercat",
           "role": "master",
           "statistics": {
               "egress": {
                   "packets": 0
               },
               "extra": {
                   "avg_cycle_us": 0,
                   "avg_latency_us": 0,
                   "avg_period_us": 0,
                   "consecutive_wkc_errors": 0,
                   "exchange_skips": 0,
                   "max_cycle_us": 0,
                   "max_exchange_us": 0,
                   "max_latency_us": 0,
                   "max_period_us": 0,
                   "min_cycle_us": 0,
                   "min_exchange_us": 0,
                   "min_latency_us": 0,
                   "min_period_us": 0,
                   "noframe_count": 0,
                   "recovery_attempts": 0
               },
               "ingress": {
                   "errors": 0
               },
               "timestamp": "2026-07-16 17:40:02.123456+00:00"
           }
       }
   ]

Outputs from other queried plugins are captured in their native format and nested under ``extra.plugin_status``, keyed by the plugin name.
