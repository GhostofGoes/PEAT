**********************
OpenSearch and Malcolm
**********************
PEAT exports to `OpenSearch <https://opensearch.org/>`__ exactly as it does to
Elasticsearch: the same ``-e`` argument, the same indices and schema, the same local
copies of every document. OpenSearch is detected automatically, so nothing needs to be
configured beyond the server URL. This matters in practice because
`Malcolm <https://malcolm.fyi/>`__, the open-source network traffic analysis suite from
CISA and Idaho National Laboratory that is widely used on :term:`OT` networks, stores its
data in OpenSearch, and PEAT ships a dashboard for it.

This page covers what differs from Elasticsearch, how to send PEAT data to a Malcolm
instance, and how to use the Malcolm dashboard. Everything else (which indices are
written, index naming, blobs, troubleshooting) is in :doc:`elasticsearch`.

How OpenSearch is detected
==========================
When PEAT first connects, it requests the server's root document and reads the
``tagline`` field: Elasticsearch answers ``You Know, for Search``, OpenSearch answers
``The OpenSearch Project: https://opensearch.org/``. For OpenSearch, PEAT switches to the
`opensearch-py <https://github.com/opensearch-project/opensearch-py>`__ client and
serializer, and adjusts the index mappings: fields that are ``flattened`` in Elasticsearch
become ``flat_object`` in OpenSearch (``host.extra``, ``event.extra``, ``service.extra``,
and the other free-form fields). The detected type is logged at connection time and
recorded in the run's state:

.. code-block:: text

   | Connected to OpenSearch cluster 'docker-cluster'
   ...
   | Saving configuration to OpenSearch (index basename: peat-configs)

Requirements:

- OpenSearch **2.7 or newer** (the ``flat_object`` field type was added in 2.7). Malcolm
  releases from 2023 onward satisfy this.
- Network access to the OpenSearch API (port 9200 by default) or to Malcolm's API proxy.
- Credentials with permission to create indices and write documents.

Connecting
==========
.. code-block:: bash

   # OpenSearch with the security plugin (the default): HTTPS and credentials in the URL
   peat pull -d sel -i 192.0.2.0/24 -e https://admin:MyStr0ngPassw0rd@opensearch.example.net:9200

   # OpenSearch with security disabled (labs only)
   peat parse -d selrelay -e http://localhost:9200 ./SET_ALL.TXT

   # Malcolm, through its API proxy (see below)
   peat scan -d clx -i 192.0.2.0/24 -e https://analyst:secret@malcolm.example.net/mapi/opensearch

Credentials in the URL are redacted from PEAT's logs and from the state and configuration
dumps (``safe_url``). If the shell history is a concern, put ``elastic_server`` in an
:doc:`encrypted configuration file <encryption>` instead:

.. code-block:: yaml

   elastic_server: "https://analyst:secret@malcolm.example.net/mapi/opensearch"
   elastic_additional_tags:
     - "substation-a"

.. note::
   PEAT does **not** verify TLS certificates when connecting to Elasticsearch or
   OpenSearch (``verify_certs=False``), because OpenSearch and Malcolm use self-signed
   certificates by default. This means the connection is encrypted but the server's
   identity isn't checked. Use a trusted network path or a VPN to the server when the
   results are sensitive.

Malcolm
=======
Malcolm exposes OpenSearch to external tools through its web interface at
``/mapi/opensearch`` (the "Malcolm API"), authenticated with Malcolm's own user accounts.
PEAT writes through this proxy, so no direct access to the OpenSearch port is needed:

.. code-block:: bash

   peat pull -d sel -i 192.0.2.0/24 -e https://user:pass@malcolm.example.net/mapi/opensearch

Malcolm's own indices (``arkime_sessions3-*``, ``malcolm_beats_*``) are untouched; PEAT
creates its ``ot-device-*`` and ``peat-*`` indices alongside them. If Malcolm rejects
index creation, the account needs the appropriate OpenSearch role; Malcolm's
documentation covers its account management.

Where PEAT fits in Malcolm
--------------------------
Malcolm sees the network from the wire: sessions, protocols, and what Zeek and Arkime
can decode. PEAT sees the devices from the inside: configuration, logic, firmware,
services, users, and logs. Together they answer questions neither can alone:

- **Enrichment**: OT traffic refers to registers by numeric address; PEAT's
  ``ot-device-registers`` documents say what those registers are (tag names,
  descriptions, data types) for each device.
- **Baselines and change detection**: regular PEAT pulls into the same OpenSearch give a
  history of each device's firmware and logic hashes; the Malcolm dashboard flags devices
  whose hashes changed.
- **Device logs**: PEAT's ``ot-device-events`` puts relay and RTAC event logs next to
  Malcolm's network events on one timeline.
- **Forensics**: artifacts such as firmware images and configuration files (and their
  hashes) are preserved in the run directory, with the hashes searchable in OpenSearch.

The PEAT dashboard for Malcolm
==============================
``distribution/opensearch-files/peat-malcolm-dashboard.ndjson`` is a saved-objects export
for OpenSearch Dashboards containing index patterns for ``ot-device-hosts-*`` and
``ot-device-events-*`` and the **PEAT overview** dashboard with these panels:

- *PEAT description panel*: what the dashboard shows and how to read it
- *PEAT devices*: the list of devices PEAT found, with vendor, model, and firmware
- *PEAT device firmware hashes* and *PEAT device logic hashes*: one row per device;
  **multiple hashes for a device mean its firmware or logic changed** between pulls
- *PEAT events* and *PEAT unique events*: device event logs across the fleet, and the
  distinct event types

To import it, open Malcolm's dashboards (OpenSearch Dashboards), go to
**Dashboards Management > Saved objects > Import**, select the ``.ndjson`` file, and
choose to overwrite existing objects if you're updating. The dashboard appears under
*Dashboards* as "PEAT overview". Data appears after the first PEAT run that exported to
Malcolm; use the time picker to cover the run's time.

The same file imports into Kibana for Elasticsearch deployments, with minor adjustments
if an object type isn't recognized.

For analysts receiving PEAT data
================================
The companion ``distribution/opensearch-files/quickstart.md`` is a one-page orientation
intended to be handed to analysts who will see PEAT data in Malcolm without running PEAT
themselves. In short:

- **What the data is**: scans, pulls, and parses of OT devices (PLCs, relays, RTUs,
  meters), one document per device per run in ``ot-device-hosts-timeseries-*``, with
  files, registers, tags, I/O, events, and memory broken out into their own indices
  (:doc:`/reference/elasticsearch_indices`).
- **How to tell runs apart**: ``agent.id`` is the PEAT run ID, ``agent.version`` the PEAT
  version, and ``tags`` carry any site or exercise tags the operator set.
- **What to do with it**: system understanding (what's really on the network), device
  monitoring (two runs that differ), log analysis (``ot-device-events``), network traffic
  enrichment (register and tag definitions), and forensic analysis (hashes of firmware,
  logic, and configuration).
- **Next steps**: build filters, visualizations, and dashboards for the questions you
  have; feed the data to analytics such as Sandia's Archimedes; and reach your PEAT point
  of contact or ``peat (at) sandia.gov`` for help.

Differences from Elasticsearch
==============================
.. list-table::
   :header-rows: 1
   :widths: 30 35 35

   * - Aspect
     - Elasticsearch
     - OpenSearch
   * - Client library
     - ``elasticsearch`` (8.x client; servers 7 and 8)
     - ``opensearch-py`` (2.x)
   * - Free-form fields (``*.extra``)
     - ``flattened``
     - ``flat_object`` (OpenSearch 2.7+)
   * - Dashboards
     - Kibana; import the ``.ndjson`` through *Stack Management > Saved Objects*
     - OpenSearch Dashboards / Malcolm; import through *Dashboards Management > Saved objects*
   * - Default security
     - Security enabled in 8.x; HTTPS with the generated CA
     - Security plugin enabled; self-signed HTTPS; Malcolm fronts it with its own
       authentication
   * - Everything else
     - Same: indices, schema, dated index names, local document copies, options
     - Same

Troubleshooting
===============
Client errors go to ``logs/elasticsearch.log`` in the run directory (the file name is the
same for both back ends).

- ``No 'tagline' field in response``: the URL doesn't point at an OpenSearch/Elasticsearch
  API. For Malcolm, make sure the path ends in ``/mapi/opensearch`` and the scheme is
  ``https``.
- ``401``/``403`` errors: wrong credentials, or the account can't create indices.
- ``mapper_parsing_exception`` on ``flat_object``: the OpenSearch version is older than
  2.7. Upgrade, or disable ``extra`` fields' export by pulling with
  ``ELASTIC_SAVE_BLOBS`` off (the default) and accepting that free-form data isn't indexed.
- Connections through a corporate HTTP proxy: PEAT disables proxy environment variables
  for the initial connection test; if Malcolm sits behind an additional reverse proxy
  that rewrites paths, point PEAT directly at the Malcolm host.

.. seealso::

   :doc:`elasticsearch`
      Exporting to Elasticsearch, index naming, and options shared with OpenSearch

   :doc:`/tutorials/elasticsearch_dashboard`
      Building dashboards from PEAT data

   :doc:`/reference/database_schema`
      The document schema
