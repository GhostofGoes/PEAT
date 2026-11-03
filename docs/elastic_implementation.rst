***********************
Elasticsearch internals
***********************

.. seealso::

   :ref:`database-schema`
      Elasticsearch index schema definitions and details

   :ref:`peat-index-reference`
      Table of the Elasticsearch indices used by PEAT

   :ref:`peat-elastic-operate`
      Elasticsearch usage and other information.

Notes
=====
- PEAT follows the `Elastic Common Schema (ECS) <https://www.elastic.co/docs/reference/ecs>`__, and **any changes must adhere to the ECS (when possible)**
- **All indices share the ECS Base and Agent field sets** (refer to :ref:`database-schema`)
- ALL timestamps are in the :term:`UTC` timezone
- Field types (the "Type" column in the tables) are Elasticsearch datatypes (`reference <https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-types.html>`__). When storing as a plain :term:`JSON` file, ensure the format it is stored in either matches or can be cohered to the corresponding ES format.
- The document's ``_id`` field is unique for each document. The format is: ``peat~<run-id>~<microsecond>``, where ``<microsecond>`` is an integer.
- Sub-fields are nested :term:`JSON` objects. From the `ECS Guidelines <https://www.elastic.co/docs/reference/ecs/ecs-guidelines>`__: "The document structure should be nested JSON objects. If you use Beats or Logstash, the nesting of JSON objects is done for you automatically. If you're ingesting to Elasticsearch using the API, your fields must be nested objects, not strings containing dots."
- PEAT follows ECS version ``9.5.0`` (:attr:`peat.elastic.Elastic.ECS_VERSION`).
- PEAT creates its indices with ``index.mapping.total_fields.limit`` set to ``20000`` (Elasticsearch's default limit is 1000). The ``ot-device-hosts-timeseries`` mapping has about 2100 fields and ``peat-parse-summaries`` about 4100 fields. **Indices or index templates created outside of PEAT** (e.g. by Malcolm or OpenSearch index templates) MUST set ``index.mapping.total_fields.limit`` to at least ``5000``, otherwise Elasticsearch/OpenSearch will reject PEAT documents.
- Fields that were mapped dynamically by older versions of PEAT (e.g. ``host.files.*``, ``host.label``, ``host.comment``, ``host.serial_number``, ``host.mac_vendor``, ``host.successful_pulls``) now have explicit types. Kibana data views that span old and new daily indices may show type conflicts for these fields; re-create the data view or reindex the old indices.
- Lists of objects are mapped as ``object`` (not ``nested``, which Kibana Lens can't aggregate). Fields of different list items are not kept together in queries; see :doc:`data_model` for the per-item indices and the ``host.indicator_states`` summary.
- Each model with its own index defines the name of its index setting in the private attribute ``_es_index_varname`` (e.g. ``Relationship`` uses ``ELASTIC_RELATIONSHIPS_INDEX``). :meth:`~peat.data.models.DeviceData.export_to_elastic` pushes every item of every list field of such a model to that index.

.. seealso::

   `Elastic Common Schema (ECS) documentation <https://www.elastic.co/docs/reference/ecs/ecs-field-reference>`__

   `ECS Overview <https://www.elastic.co/docs/reference/ecs>`__

   `ECS Field Reference <https://www.elastic.co/docs/reference/ecs/ecs-field-reference>`__

   `ECS Guidelines <https://www.elastic.co/docs/reference/ecs/ecs-guidelines>`__

   `Elasticsearch data types <https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-types.html>`__

Code documentation
==================

Elastic
-------
.. automodule:: peat.elastic
   :members:

Index type mappings
-------------------
.. automodule:: peat.es_mappings
   :members:
