**********
Data model
**********
Documentation on PEAT's internal model for structuring and managing data from devices (a.k.a "device data").

.. raw:: html
   :file: ../images/data_model.svg

.. only:: not html

   ``DeviceData`` holds one device: identifiers (``id``, ``name``, ``label``, ``type``,
   ``serial_number``, ``part_number``, and ``description`` with vendor, model, product),
   network fields (``ip``, ``mac``, ``mac_vendor``, ``hostname``, ``serial_port``), nested
   objects (``firmware``, ``boot_firmware``, ``os``, ``hardware``, ``logic``, ``related``,
   ``geo``, ``x509``, ``extra``), status (``run_mode``, ``status``, ``uptime``, ``start_time``,
   ``successful_pulls``), and ``module``, a list of sub-component ``DeviceData``. Its list
   attributes hold the sub-models: ``interface`` (``Interface``), ``service`` (``Service``),
   ``files`` (``File``), ``registers`` (``Register``), ``tag`` (``Tag``), ``io`` (``IO``),
   ``event`` (``Event``), ``memory`` (``Memory``), ``users`` (``User``), and ``ssh_keys``
   (``SSHKey``). The whole device is written to ``device-data-full.json`` and
   ``device-data-summary.json`` and to the ``ot-device-hosts-timeseries`` index; each list is
   also written to ``device-data-<attribute>.jsonl``, and files, registers, tags, I/O, events,
   and memory have their own ``ot-device-*`` indices.

Working with data
=================
There are two ways to store and retrieve data:

- Directly via class attributes: ``dev.os.version = "7"``
- Using :meth:`.DeviceData.store` with a model class instance: ``dev.store("interface", Interface(ip="10.10.10.10"))``

Simple attribute values such as :attr:`~peat.data.models.DeviceData.architecture` or :attr:`~peat.data.models.DeviceData.type` should be assigned directly, e.g. ``dev.architecture = "x86_64"``.

Complex attributes that contain objects, such as ``interfaces`` (which is a :class:`list` of :class:`~peat.data.models.Interface`), should be set using :meth:`.DeviceData.store`.

General data can be retrieved directly via attribute access, e.g. ``os_ver = dev.os.version``. Complex objects (such as "services") are easily accessed using the :meth:`.DeviceData.retrieve` helper method, which will search and filter objects based on the desired attributes, e.g. the IP address or port of a interface. However, they can also be accessed directly as regular lists, if desired.

DeviceData
==========
.. autopydantic_model:: peat.data.models.DeviceData

.. _data-models:

Data Models
===========
.. note::
   Most fields with a type of ``peat.data.models.ConstrainedStrValue`` are just :class:`str` type, but will automatically have any whitespace stripped when assigned to.

.. currentmodule:: peat.data.models

.. autosummary::

   Description
   Event
   File
   Firmware
   Geo
   Hardware
   Hash
   IO
   Interface
   LatLon
   Logic
   Memory
   OS
   Register
   Related
   Service
   SSHKey
   Tag
   Vendor
   X509
   CertEntity

.. automodule:: peat.data.models
   :members:
   :exclude-members: DeviceData, validator, Field
