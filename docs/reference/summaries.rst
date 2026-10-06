*********
Summaries
*********
The result of a scan, pull, or parse is a *summary*: a :term:`JSON` document with metadata
about the operation and the data of the devices involved. Summaries are written to
``peat_results/<run-dir>/summaries/``, optionally printed to the terminal (``-E``), stored
in Elasticsearch (``-e``), and returned as a :class:`dict` by the Python API
(:func:`peat.scan`, :func:`peat.pull`, :func:`peat.parse`). A summary from one run can be
used as the targets of another with ``-f`` (see :ref:`targets`).

.. _scan-summary:

Scan summary
============
The result of device discovery and verification, produced by ``peat scan`` and by the scan
phase of ``peat pull`` and ``peat push``. Written to ``summaries/scan-summary.json``, and
to the ``peat-scan-summaries`` index. The Python API returns it from
:func:`peat.api.scan_api.scan`.

.. csv-table:: Scan summary fields
   :escape: \
   :file: field_references/scan_summaries_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left

Example (a scan of one Schneider ION power meter):

.. literalinclude:: ../../examples/example-scan-summary.json
   :language: json

.. _pull-summary:

Pull summary
============
The result of ``peat pull``. Written to ``summaries/pull-summary.json`` and the
``peat-pull-summaries`` index, and returned by :func:`peat.api.pull_api.pull`. Only the
device data (``pull_results``) is printed to the terminal with ``-E``.

.. csv-table:: Pull summary fields
   :escape: \
   :file: field_references/pull_summaries_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left

Example (an OpenPLC Runtime v4 pull):

.. literalinclude:: ../../examples/example-openplc-pull-summary.json
   :language: json
   :lines: 1-80
   :caption: First 80 lines of ``examples/example-openplc-pull-summary.json``

.. _parse-summary:

Parse summary
=============
The result of ``peat parse``. Written to ``summaries/parse-summary.json`` and the
``peat-parse-summaries`` index, and returned by :func:`peat.api.parse_api.parse`.

.. csv-table:: Parse summary fields
   :escape: \
   :file: field_references/parse_summaries_fields.csv
   :header-rows: 1
   :widths: auto
   :align: left

Example (the fictional AwesomeTool module from the
:doc:`module developer guide </developer/module_developer_guide>`):

.. literalinclude:: ../../examples/example-parse-summary.json
   :language: json

Device data in summaries
========================
The device entries in ``hosts_verified``, ``pull_results``, and ``parse_results[].results``
are the device's :doc:`data model </developer/data_model>` export, minus large fields
(memory reads, events, file contents). The complete data for each device is in
``devices/<device-id>/device-data-full.json`` in the run directory (see
:doc:`/user_guide/output`).
