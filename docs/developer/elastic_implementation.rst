***********************
Elasticsearch internals
***********************

.. seealso::

   :ref:`database-schema`
      Elasticsearch index schema definitions and details

   :ref:`peat-index-reference`
      Table of the Elasticsearch indices used by PEAT

   :doc:`/user_guide/elasticsearch`
      Elasticsearch usage and other information.

Conventions
===========
The schema conventions (ECS adherence, the shared base and agent field sets, UTC
timestamps, Elasticsearch data types, the ``_id`` format, and nested JSON objects) are
documented once, in :ref:`database-schema`; changes to the mappings must follow them.

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
