*******************
Developer reference
*******************
Documentation of PEAT's Python codebase and APIs, for people who use PEAT as a library
(``import peat``), extend it with device modules, or work on PEAT itself. For the
reasoning behind the architecture, see the :doc:`/design/index`; for how to set up a
development environment and contribute changes, see :doc:`/contributing/index`.

.. note::
   The source code for documented classes and functions is available by clicking the
   ``[source]`` link to the right of each one.

Start here
==========
- :doc:`module_developer_guide`: how to write a PEAT device module, from the data model to
  tests and documentation
- :doc:`python_examples`: short, runnable examples of the Python API
- :doc:`data_model`: the :class:`~peat.data.models.DeviceData` model that all results use

Reference
=========
.. toctree::
   :maxdepth: 1

   module_developer_guide
   python_examples
   data_model
   peat_api
   device_api
   device_modules
   general_apis
   heat_api
   elastic_implementation
   dependencies

Two APIs
========
PEAT has two layers of API:

- The **PEAT API** (:doc:`peat_api`): the high-level "verbs" (:func:`peat.scan`,
  :func:`peat.pull`, :func:`peat.parse`, :func:`peat.push`, :func:`peat.pillage`,
  :func:`peat.heat_main`), the configuration (:data:`peat.config`) and state
  (:data:`peat.state`) singletons, and the constants and exceptions. This is what the
  command line interface uses, and the stable interface for scripts and other tools.
- The **module API** (:doc:`device_api`): the class-based interface that device modules
  implement (:class:`~peat.device.DeviceModule`), the identification method models
  (:class:`~peat.api.identify_methods.IPMethod`,
  :class:`~peat.api.identify_methods.SerialMethod`), file signatures, and the module
  manager (:data:`peat.module_api`) that looks modules up and imports them at runtime.

Both operate on the :doc:`data model <data_model>`, and the
:doc:`general APIs <general_apis>` (protocol clients, networking helpers, utilities,
logging) support both.
