.. _supported-devices:

*****************
Supported devices
*****************

Each device PEAT supports is implemented as a :term:`PEAT module <Device module>`. The
tables on this page list the devices included with PEAT "out of the box", grouped by
vendor, along with the functions PEAT can perform against them, the protocols used, and an
estimated maturity level. Expand a device's dropdown for notes and the firmware versions
PEAT has been used with.

.. note::
   The *firmware versions* listed are versions PEAT is known to have worked with. The list
   is **not** exhaustive, and is not an indication of whether PEAT will or will not work
   with a particular firmware version.

.. warning::
   The estimated Technology Readiness Levels (:term:`TRL`) for each module are
   **estimates only**, intended to give a feel for the maturity of a module's development
   and how reliable it has proven to be. Roughly: TRL 3 and 4 are prototypes tested in a
   lab, TRL 5 and 6 have been used in realistic or high-fidelity environments, and higher
   levels have seen extended operational use.

How to read the tables
======================
The *Supported functions* column uses the PEAT commands:

- **Scan**: PEAT can discover and identify the device on a network (see
  :doc:`/user_guide/scan`).
- **Pull**: PEAT can actively retrieve information and artifacts, such as configuration,
  logic, firmware, or logs (see :doc:`/user_guide/pull`). Where a table says
  "Pull config" or "Pull logic", only those artifact types are retrieved.
- **Parse**: PEAT can extract information from the device's files offline, either files
  pulled from the device or a *project file* exported from the vendor's engineering
  software (see :doc:`/user_guide/parse`).
- **Push**: PEAT can upload configuration and/or firmware to the device (see
  :doc:`/user_guide/push`).

To list the modules in your copy of PEAT (including any third-party modules you import),
run ``peat scan --list-modules``. The names in the output are what the ``-d`` argument
accepts, along with the aliases listed by ``peat scan --list-aliases``.

Included devices
================
Download this table as :download:`supported_devices.csv <supported_devices.csv>`.

.. peat-device-table:: supported_devices.csv
   :vendor-sections:

Unintegrated devices
====================
Devices that have code and some amount of analysis work done, but are not included with
PEAT and aren't yet integrated as PEAT modules. The analysis work is done, they need a
modest amount of development effort to integrate them as PEAT modules.

Download this table as :download:`unintegrated_devices.csv <unintegrated_devices.csv>`.

.. peat-device-table:: unintegrated_devices.csv

Adding a device
===============
PEAT's module architecture makes adding a device straightforward: a module is a Python
class that implements the parts of the :doc:`module API </developer/device_api>` it
supports (identification, pulling, parsing, pushing). Modules can be bundled with PEAT or
imported at runtime with ``-I`` (see :doc:`/user_guide/third_party_modules`). The
:doc:`/developer/module_developer_guide` walks through writing one. If you have a device
you'd like supported, `open an issue <https://github.com/sandialabs/PEAT/issues>`__ or a
`discussion <https://github.com/sandialabs/PEAT/discussions>`__ on GitHub.

.. seealso::

   :doc:`/reference/protocols`
      The TCP/IP protocols and ports PEAT uses to communicate with devices

   :doc:`/reference/devices/index`
      In-depth reference pages for specific device families (SEL, Siemens, OpenPLC, and
      MySQL servers)

   :doc:`/reference/example_artifacts`
      Where to find example files for testing PEAT's parsers
