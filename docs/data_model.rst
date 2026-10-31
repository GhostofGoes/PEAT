**********
Data model
**********
Documentation on PEAT's internal model for structuring and managing data from devices (a.k.a "device data").

Working with data
=================
There are two ways to store and retrieve data:

- Directly via class attributes: ``dev.os.version = "7"``
- Using :meth:`.DeviceData.store` with a model class instance: ``dev.store("interface", Interface(ip="10.10.10.10"))``

Simple attribute values such as :attr:`~peat.data.models.DeviceData.architecture` or :attr:`~peat.data.models.DeviceData.type` should be assigned directly, e.g. ``dev.architecture = "x86_64"``.

Complex attributes that contain objects, such as ``interfaces`` (which is a :class:`list` of :class:`~peat.data.models.Interface`), should be set using :meth:`.DeviceData.store`.

General data can be retrieved directly via attribute access, e.g. ``os_ver = dev.os.version``. Complex objects (such as "services") are easily accessed using the :meth:`.DeviceData.retrieve` helper method, which will search and filter objects based on the desired attributes, e.g. the IP address or port of a interface. However, they can also be accessed directly as regular lists, if desired.

.. _comparing-device-data:

Comparing device data
=====================
:meth:`.DeviceData.compare` returns the differences between a device and another device, or between a device and previously exported data (e.g. a ``device-data-full.json`` file used as a baseline). Common uses are:

- Detecting configuration drift between two pulls of the same device
- Comparing data pulled from a device to data parsed from a project file
- Comparing a device to a known-good baseline

.. code-block:: python

   import json
   from pathlib import Path

   # "dev" is a DeviceData object, e.g. from a pull or parse
   baseline = json.loads(Path("baseline/device-data-full.json").read_text(encoding="utf-8"))
   diff = dev.compare(baseline)

   if not diff.is_same:
       print(diff.format())   # Human-readable list of changes
       print(diff.summary())  # Counts of changes and a similarity ratio
       Path("diff.json").write_text(json.dumps(diff.export(), indent=4))

The result is a :class:`~peat.data.compare.DeviceDiff` with a list of :class:`~peat.data.compare.Change` objects, each with a ``kind`` (``added``, ``removed`` or ``changed``), a ``path`` and the ``old`` and ``new`` values. ``a.compare(b)`` describes how to get from ``a`` to ``b``: values only in ``b`` were "added", values only in ``a`` were "removed". Example output of :meth:`~peat.data.compare.DeviceDiff.format`:

.. code-block:: text

   ~ firmware.version: "1.0" -> "1.1"
   ~ interface[name=eth1].ip: "192.0.2.11" -> "192.0.2.12"
   - service[port=502,protocol=modbus_tcp,transport=tcp]: {"port": 502, "protocol": "modbus_tcp", "transport": "tcp"}
   + service[port=23,protocol=telnet,transport=tcp]: {"port": 23, "protocol": "telnet", "transport": "tcp"}
   ~ registers[protocol=modbus_tcp,address=40001].name: "speed" -> "velocity"

How data is compared:

- Data is compared in its exported form, the same data that is written to ``device-data-full.json``. Both inputs are normalized the same way (JSON types, empty values removed), so a device is the same as its own exported file. Two exported JSON files can be compared directly with :func:`~peat.data.compare.compare_device_data`.
- Comparing a :class:`.DeviceData` object exports it, which populates and deduplicates its fields like :meth:`.DeviceData.export` does. Hostname, IP and MAC address resolution (``RESOLVE_*`` settings) is disabled while comparing, so a comparison makes no network requests and the result doesn't depend on the network it's run on.
- Items in lists of sub-models (interfaces, services, files, registers, users, etc.) are matched by identity keys, such as the port, protocol and transport of a service, the path of a file, or the protocol, point type and address of a register, instead of by their position. Reordered lists are not differences. Items are not matched if a higher-priority key is set in both and differs, e.g. a user renamed from ``admin`` to ``operator`` is reported as removed and added, even if the user ID is the same. The keys are listed in :data:`~peat.data.compare.LIST_IDENTITY_KEYS`. Use ``ignore_order=False`` to compare lists by position.
- Values that change between pulls of an unchanged device, such as ``uptime``, ``event``, ``memory`` and the timestamps of the local copies of files, are excluded by default. These are listed in :data:`~peat.data.compare.DEFAULT_COMPARE_EXCLUDES`. Values of files that are from the local copy of a file on the system running PEAT (the location of the copy, and its owner and group) are also ignored. Use ``use_default_excludes=False`` to compare them.
- Raw data (``original`` fields) is excluded unless ``include_original=True``. Changes to raw data are still detected by changes to the hashes.
- ``include`` only compares the listed fields: top-level fields (``include=["firmware", "logic"]``) or dotted paths without list selectors (``include=["firmware.version", "interface.ip"]``). Unknown field names raise a :class:`ValueError`. ``exclude`` adds patterns of fields to exclude. A pattern without a ``.`` excludes a field with that name anywhere (e.g. ``"mtu"``), otherwise the pattern is matched against the full field path (e.g. ``"logic.*"`` or ``"*.extra"``).
- ``device-data-summary.json`` files leave out some fields (``registers``, ``tag``, ``io``, ``files``, ``memory``, ``event`` and raw data). Compare a summary to another summary, or exclude those fields: ``dev.compare(summary, exclude=["registers", "tag", "io", "files", "raw-values"])``.
- Values from devices that are used in paths are JSON-quoted if they contain special characters, raw data used to match items (e.g. SSH keys) is shown as a SHA-256 digest, and :meth:`~peat.data.compare.DeviceDiff.format` escapes control and non-ASCII characters, so the output is safe to print to a terminal.

.. automodule:: peat.data.compare
   :members: compare_device_data, DEFAULT_COMPARE_EXCLUDES, LIST_IDENTITY_KEYS, MAX_DEPTH

.. autopydantic_model:: peat.data.compare.DeviceDiff

.. autopydantic_model:: peat.data.compare.Change

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
   :exclude-members: DeviceData
