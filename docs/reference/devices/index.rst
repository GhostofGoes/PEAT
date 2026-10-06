.. _device-module-documents:

*****************
Device references
*****************
In-depth reference pages for specific device families: how PEAT communicates with them,
what it collects, file formats, configuration options, and developer notes. The code
documentation for every module included with PEAT is in :doc:`/developer/device_modules`,
and the summary table of supported devices is on
:doc:`/getting_started/supported_devices`.

.. toctree::
   :maxdepth: 1

   sel
   siemens
   openplc
   mysql

Modules without a dedicated page are documented by their class docstrings in
:doc:`/developer/device_modules` and their options in the
:ref:`configuration reference <peat-config>`. Adding a page for a device is encouraged;
see :doc:`/developer/module_developer_guide`.
