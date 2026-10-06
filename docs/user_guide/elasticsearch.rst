.. _peat-elastic-operate:

******************************************
Exporting to Elasticsearch and OpenSearch
******************************************
PEAT can export everything it collects to :term:`Elasticsearch` or OpenSearch: device data,
scan/pull/parse summaries, its own logs, and the configuration and state of each run. This
is how PEAT data gets into dashboards (Kibana, OpenSearch Dashboards, Malcolm), is queried
across many runs, and is consumed by downstream analytics. The documents follow a defined
schema based on the Elastic Common Schema (:term:`ECS`), described in
:doc:`/reference/database_schema`.

Export is off by default. Enable it with ``-e`` (``--elastic-server``) or the
:attr:`ELASTIC_SERVER <peat.settings.Configuration.ELASTIC_SERVER>` configuration option.

Quick start
===========
.. code-block:: bash

   # A server on localhost (http://localhost:9200/) is assumed when no URL is given
   peat pull -d selrelay -i 192.0.2.0/24 -e

   # A remote server
   peat scan -d clx -i 192.0.2.0/24 -e http://192.0.2.20:9200

   # Credentials and HTTPS
   peat parse -d selrelay -e https://peat:secret@elastic.example.net:9200 ./SET_ALL.TXT

   # Malcolm (OpenSearch behind the Malcolm API proxy)
   peat pull -d m340 -i 192.0.2.0/24 -e https://user:pass@localhost/mapi/opensearch

   # Load a batch of earlier backups
   peat parse -e http://localhost:9200 -d sel ./relay_backups/

PEAT connects at start-up (failing fast if the server is unreachable, after
:attr:`ELASTIC_TIMEOUT <peat.settings.Configuration.ELASTIC_TIMEOUT>` seconds or
``--elastic-timeout``), creates any missing indices with PEAT's type mappings, and pushes
documents as the run progresses.

Need a server to try it with? The repository contains a Docker Compose file that starts
Elasticsearch and Kibana locally: ``bash scripts/elastic-testing.sh run`` (see the script
for the stop, flush, and export commands). The :doc:`tutorials </tutorials/index>` include
a walkthrough that builds a dashboard from PEAT data.

What is exported
================
Each kind of data goes to its own index (the names are
:ref:`configurable <peat-index-reference>`):

.. list-table::
   :header-rows: 1
   :widths: 32 68

   * - Index
     - Documents
   * - ``ot-device-hosts-timeseries``
     - One document per device per run, with the device's data. Over time this gives a
       history of each device's configuration, firmware, and status, hence "timeseries".
   * - ``ot-device-files``, ``ot-device-registers``, ``ot-device-tags``, ``ot-device-io``, ``ot-device-events``, ``ot-device-memory``
     - List-type device data broken out into one document per item (file, register, tag,
       I/O point, event, memory read) for easier searching and visualization.
   * - ``peat-scan-summaries``, ``peat-pull-summaries``, ``peat-parse-summaries``
     - The summary of each run.
   * - ``peat-logs``
     - PEAT's own log messages (every event, including ``DEBUG``).
   * - ``peat-configs``, ``peat-state``
     - The configuration and internal state of each run, for reproducibility.

Every document shares the :ref:`base and agent fields <base-fields>`: ``@timestamp``,
``agent.id`` (the run ID), ``agent.type`` (``PEAT``), ``agent.version``, ``message``, and
``tags``. Add your own tags to every document with
:attr:`ELASTIC_ADDITIONAL_TAGS <peat.settings.Configuration.ELASTIC_ADDITIONAL_TAGS>`
(for example a site name) to make runs easy to filter.

Configuration and behavior
==========================
- **Large fields are not exported by default.** Binary blobs and large text fields
  (firmware images, raw configuration files, memory) are excluded to keep the indices
  small. Enable them with ``--elastic-save-blobs`` or
  :attr:`ELASTIC_SAVE_BLOBS <peat.settings.Configuration.ELASTIC_SAVE_BLOBS>`. The files
  themselves are always in the run directory.
- **Indices are split by date**: a new index is created each day, named
  ``<index-name>-<year>.<month>.<day>`` in :term:`UTC`, for example
  ``ot-device-hosts-timeseries-2026.04.21``. Index patterns such as
  ``ot-device-hosts-timeseries-*`` cover them all. Disable the date suffix with
  :attr:`ELASTIC_DISABLE_DATED_INDICES <peat.settings.Configuration.ELASTIC_DISABLE_DATED_INDICES>`
  (or ``PEAT_ELASTIC_DISABLE_DATED_INDICES=true``) to write to the base index names.
- **Logs, configuration, and state** are exported by default. Disable them with
  :attr:`ELASTIC_SAVE_LOGS <peat.settings.Configuration.ELASTIC_SAVE_LOGS>`,
  :attr:`ELASTIC_SAVE_CONFIG <peat.settings.Configuration.ELASTIC_SAVE_CONFIG>`, and
  :attr:`ELASTIC_SAVE_STATE <peat.settings.Configuration.ELASTIC_SAVE_STATE>`.
- **Index names** are configurable per index
  (:attr:`ELASTIC_HOSTS_INDEX <peat.settings.Configuration.ELASTIC_HOSTS_INDEX>` and
  friends), for example to keep several sites or exercises apart. Most Elasticsearch
  options are only available in the configuration file, not on the command line, to keep
  ``--help`` manageable.
- **Timestamps** are in UTC.
- **OpenSearch** is detected automatically from the server's response and PEAT switches to
  the OpenSearch client, including Malcolm's API proxy (``/mapi/opensearch``). See
  :doc:`opensearch`.

Local copies of exported documents
==================================
Everything PEAT sends to Elasticsearch is also saved as :term:`JSON` files in the run
directory, by default in ``peat_results/<run-dir>/elastic_data/`` (configurable with
:attr:`ELASTIC_DIR <peat.settings.Configuration.ELASTIC_DIR>` or ``PEAT_ELASTIC_DIR``),
together with the index type mappings in ``elastic_data/mappings/``. These files can be
used to rebuild the indices after a server failure, or to load the data into a server that
wasn't reachable when PEAT ran (for example when PEAT was used on an isolated network).
The ``elastic-testing.sh`` script shows one way to load them with
`elasticsearch-dump <https://github.com/elasticsearch-dump/elasticsearch-dump>`__.

Dashboards and visualizations
=============================
PEAT ships with a dashboard for Malcolm / OpenSearch Dashboards (which also imports into
Kibana); see :doc:`opensearch`. When building your own dashboards:

- Be deliberate: know who the user is and the questions they are asking.
- Keep it simple; don't force users to scroll and remember. Make more, linked dashboards
  rather than one giant one.
- Put important information in important places, use a grid, and favor charts that are a
  bit wider than tall.
- ``host.description.product``, ``host.firmware.version``, ``host.service.protocol``,
  ``host.event.action``, and ``agent.id`` are good starting points for aggregations.

Recommended reading:
`Structure and Layout in System Dashboard Design <https://onemogin.com/observability/dashboards/practitioners-guide-to-system-dashboard-design.html>`__
and
`Presentation and Accessibility in System Dashboard Design <https://onemogin.com/observability/dashboards/practitioners-guide-to-system-dashboard-design-p2.html>`__.
The :doc:`/tutorials/elasticsearch_dashboard` tutorial builds a dashboard step by step.

Troubleshooting
===============
Elasticsearch client logs are **not** written to PEAT's normal log; they go to
``peat_results/<run-dir>/logs/elasticsearch.log``. Start there.

- **Connection refused / timeout**: check the URL (scheme, host, port), credentials, and
  that the server is reachable from the host running PEAT. In a container, use
  ``--network host`` to reach a server on ``localhost``.
- **Mapping conflicts** (``mapper_parsing_exception``, ``illegal_argument_exception``):
  a field in an existing index has a different type than PEAT's mapping, typically after
  an upgrade or when another tool wrote to the same index. Export anything important with
  elasticsearch-dump, delete the index, and re-run:
  ``curl -XDELETE localhost:9200/ot-device-hosts-timeseries-2026.04.21``. Dynamically
  named fields under ``host.extra.<module>`` exist to avoid this problem across modules.
- **Too many fields**: raise the index's ``index.mapping.total_fields.limit`` if a device
  produces very wide documents, or disable ``ELASTIC_SAVE_BLOBS``.

.. seealso::

   :doc:`/reference/elasticsearch_indices`
      Table of the indices and their configuration options

   :doc:`/reference/database_schema`
      Field-level schema of every index

   :doc:`/developer/elastic_implementation`
      How the export is implemented
