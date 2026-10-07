*******************************************
PEAT data in Elasticsearch and Kibana
*******************************************
*You've been running monthly pulls for a year and have a pile of run directories. Someone
asks "which devices are still on the firmware with the known vulnerability, and when did
each one last change?" You could script it. Or you could put everything in Elasticsearch
once and answer questions like that in Kibana for as long as you keep collecting.*

PEAT writes to :peat-icon:`elasticsearch` Elasticsearch (or :peat-icon:`opensearch` OpenSearch) natively with ``-e``, following a documented
schema, so the setup is: run a server, add ``-e`` to your commands, and point :peat-icon:`kibana` Kibana at
the indices. This tutorial does all three locally with Docker, then loads a year of
existing results.

What you need
=============
- Docker with Compose, 4 GB of free memory for Elasticsearch and Kibana
- PEAT, and the PEAT repository (for the Compose file in ``scripts/``) or your own
  Elasticsearch

Step 1: start Elasticsearch and Kibana
======================================
The repository includes a Compose file and a helper script for development and testing.
It starts a single-node Elasticsearch 8 with security disabled (fine for a lab, not for a
shared server) and Kibana, both on ``localhost``:

.. code-block:: console

   $ bash scripts/elastic-testing.sh run
   Elasticsearch is at: http://localhost:9200/
   Kibana web interface is at: https://localhost:5601/
   NOTE: it may take several minutes before Kibana is accessible

   $ curl -s http://localhost:9200 | jq '.version.number'
   "8.19.3"

(``elastic_only`` starts only Elasticsearch; ``stop`` and ``remove`` do what they say;
``flush`` deletes PEAT's indices; ``export`` dumps them to ``elastic_index_export/``.)

Step 2: send a run to Elasticsearch
===================================
Add ``-e`` to any command. With no URL it means ``http://localhost:9200/``:

.. code-block:: console

   $ peat pull -R substation-a-2026-10 -c substation-a.yaml -d sel -i 192.0.2.0/24 -e
   | Connected to Elasticsearch cluster 'peat-development-cluster'
   ...
   | Pushing pull result summary to Elasticsearch (index basename: peat-pull-summaries)
   | Saving configuration to Elasticsearch (index basename: peat-configs)
   | Saving state to Elasticsearch (index basename: peat-state)

   $ curl -s 'http://localhost:9200/_cat/indices/ot-*,peat-*?v&s=index'
   health status index                                   docs.count
   yellow open   ot-device-events-2026.10.05                   812
   yellow open   ot-device-files-2026.10.05                    196
   yellow open   ot-device-hosts-timeseries-2026.10.05          14
   yellow open   ot-device-registers-2026.10.05               1,204
   yellow open   peat-configs-2026.10.05                         1
   yellow open   peat-logs-2026.10.05                        2,310
   yellow open   peat-pull-summaries-2026.10.05                  1
   yellow open   peat-scan-summaries-2026.10.05                  1
   yellow open   peat-state-2026.10.05                           1

One document per device went to ``ot-device-hosts-timeseries``, one per file, register,
and event to their own indices, plus the summaries and PEAT's own logs and configuration.
Everything also landed in ``peat_results/substation-a-2026-10/elastic_data/`` as JSON.
Indices are dated by day in UTC; see :doc:`/user_guide/elasticsearch` for the options.

Step 3: load the backlog
========================
Re-parsing the raw files from earlier runs sends them to Elasticsearch with the same
schema. The pulled files are kept unmodified in each run directory, so:

.. code-block:: bash

   for run in peat_results/substation-a-2026-0{1..9}; do
       peat parse -q -R "reload-$(basename "$run")" -d selrelay -e -- "$run"/devices/*/relay_files/SET_ALL.TXT
   done

Parsed documents get *today's* ``@timestamp``, since that's when PEAT created them. For a
true history, the originals' ``file.mtime`` (when the relay wrote the file) and
``agent.id``/``peat_run_id`` (which run) are in each document. Runs that *were* exported
with ``-e`` at the time also have a copy of every document in their ``elastic_data/``
directory, which can be loaded as-is (preserving the original timestamps) with the
`elasticsearch-dump <https://github.com/elasticsearch-dump/elasticsearch-dump>`__ tool:

.. code-block:: bash

   docker run --rm --network host -v "$(pwd)/peat_results/substation-a-2026-03/elastic_data":/data \
       elasticdump/elasticsearch-dump:latest \
       --input=/data/ot-device-hosts-timeseries-2026.03.02.json \
       --output=http://localhost:9200/ot-device-hosts-timeseries-2026.03.02 --type=data

Step 4: explore in Kibana
=========================
Open http://localhost:5601 and create data views (Stack Management > Data Views):

- ``ot-device-hosts-timeseries-*`` with ``@timestamp`` as the time field: one document
  per device per run
- ``ot-device-events-*``: device logs and events
- ``peat-logs-*``: PEAT's own logs, for troubleshooting runs

In **Discover**, with the hosts data view, some queries in KQL:

.. code-block:: text

   host.description.vendor.id : "SEL" and host.firmware.version : "R516"
   host.service.protocol : "ftp" and host.service.status : "verified"
   host.description.model : "SEL-451" and not host.firmware.id : "SEL-451-5-R322-V0-Z011011-D20180630"
   agent.id : "179126071779"

The last one shows every device from one run; ``agent.id`` is the run ID PEAT printed at
start-up and recorded in the summary.

Step 5: build the dashboard
===========================
In **Dashboards**, create a dashboard and add a few visualizations with Lens:

- **Devices by vendor and model**: a bar chart of unique count of ``host.id``, broken
  down by ``host.description.product``.
- **Firmware versions**: a table of ``host.description.product``,
  ``host.firmware.version``, unique count of ``host.id``. Filter to the latest run with
  ``agent.id`` to avoid counting the same device in every run.
- **Services exposed**: unique count of ``host.id`` by ``host.service.protocol`` (set the
  field as a keyword aggregation), filtered to ``host.service.status: verified``.
- **Changes over time**: a line chart of unique count of ``host.firmware.id`` per device
  over ``@timestamp`` using the hosts index; a step up means a device changed firmware
  between runs.
- **Device events**: a data table on ``ot-device-events-*`` of ``host.ip``,
  ``event.created``, ``event.message``, sorted by ``event.created``, to read relay and
  RTAC logs across the fleet in one place.

Good practice from the PEAT team's own dashboards: know who will use it and what question
they're asking, keep each dashboard simple and link several rather than build one giant
one, put the important numbers top-left, and prefer charts a bit wider than tall.

Answering the opening question is now a filter: ``host.firmware.id : "SEL-451-5-R322-V0-Z011011-D20180630"``
over the latest run's ``agent.id`` lists the devices still on that version, and the
firmware chart over time shows when each one last changed.

Malcolm
=======
If your organization runs `Malcolm <https://malcolm.fyi/>`__ (which is built on
OpenSearch), PEAT writes to it directly through its API proxy, and a ready-made dashboard
is in the repository:

.. code-block:: bash

   peat pull -d sel -i 192.0.2.0/24 -e https://user:pass@malcolm.example.net/mapi/opensearch

Import ``distribution/opensearch-files/peat-malcolm-dashboard.ndjson`` through OpenSearch
Dashboards' *Stack Management > Saved Objects > Import*. The ``quickstart.md`` next to it
is a one-page orientation for analysts receiving PEAT data in Malcolm.

Clean up
========
.. code-block:: bash

   bash scripts/elastic-testing.sh export   # keep the data, if you want it
   bash scripts/elastic-testing.sh remove   # stop and delete the containers

Notes
=====
- Large fields (firmware images, raw file contents, memory reads) are not exported by
  default; ``--elastic-save-blobs`` includes them. The files are always in the run
  directory anyway.
- The schema is documented field by field in :doc:`/reference/database_schema`; the
  ``host.extra.<module>`` fields are vendor-specific.
- Elasticsearch client errors are logged to ``logs/elasticsearch.log`` in the run
  directory, not to ``peat.log``. Mapping conflicts and their fix are covered in
  :doc:`/user_guide/elasticsearch`.
- The Compose setup has security disabled. For anything beyond a lab, enable security and
  use ``https://user:pass@host:9200`` URLs (PEAT redacts credentials from its logs).
