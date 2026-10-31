********
Woodward
********

PEAT supports several Woodward controls: the easYgen genset controllers (:class:`~peat.modules.woodward.easygen_3500xt.Easygen3500XT`), the 2301E speed controller (:class:`~peat.modules.woodward.wdw_2301e.WDW2301E`), and the MicroNet Plus (:class:`~peat.modules.woodward.micronet.MicroNet`). This page documents the configuration file formats PEAT can parse for these devices with ``peat parse``: the files of Woodward's *ToolKit* service tool (used for the easYgen and other controls) and the tunable files of Woodward's *Control Assistant* service tool.

.. seealso::

   `Woodward ToolKit manual B37917 <https://www.woodward.com/products/wp-content/uploads/sites/3/2024/08/B37917_B.pdf>`__
      File types (chapter 2), loading settings files, and converting easYgen-3000 settings files for easYgen-3000XT controls (chapter 8)

   `Woodward application note 37572 <https://wss.woodward.com/manuals/PGC/easYgen-3000XT_series/Application_Notes/37572_how-to-create-partial-settings-files.pdf>`__
      Creating complete and partial settings files offline from a SID

   `easYgen-3400XT/3500XT-P2 technical manual B37581 <https://wss.woodward.com/manuals/PGC/easYgen-3000XT_series/easYgen-3400XT-3500XT-P2/01_Technical_Manuals/B37581_TM_easYgen-3400-3500-XT-P2_N.pdf>`__, `3400XT/3500XT-P1 manual B37580 <https://wss.woodward.com/manuals/PGC/easYgen-3000XT_series/easYgen-3400XT-3500XT-P1/01_Technical_Manuals/B37580_TM_easYgen-3400-3500-XT-P1_P.pdf>`__, and `3100XT/3200XT-P1 manual B37574 <https://wss.woodward.com/manuals/PGC/easYgen-3000XT_series/easYgen-3100XT-3200XT-P1/01_Technical_Manuals/B37574_TM_easYgen-3100-3200-XT-P1_U.pdf>`__
      Parameter lists (parameter numbers, defaults, ranges, and security levels) of the easYgen-3000XT series

   `easYgen-3400/3500 manual 37528 <https://wss.woodward.com/manuals/Legacy/easYgen-3x00/manual_easygen3400-3500_EN37528J.pdf>`__ and `easYgen-2000 configuration manual 37427 <https://www.dsf-technologies.com/wp-content/uploads/2017/04/WOODWARD_EASYGEN-2000_CONFIGURATION-MANUAL_EN_2017.pdf>`__
      Parameter lists and ToolKit file naming for the first generation easYgen-3000 and the easYgen-2000 series

   `Control Assistant manual 26775 <https://www.woodward.com/products/publication-asset/26775>`__
      Control Assistant and the tunable (``.tc``) files it saves

   `MS-NRBF: .NET Remoting Binary Format <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/>`__
      The serialization format inside ToolKit settings and tool files

   :class:`~peat.modules.woodward.easygen_3500xt.Easygen3500XT`
      PEAT :class:`~peat.device.DeviceModule` for the easYgen genset controllers (scan, pull, and parse)

   :class:`~peat.modules.woodward.wdw_2301e.WDW2301E`
      PEAT :class:`~peat.device.DeviceModule` for the 2301E speed controller (scan, pull, and parse)

Terminology
-----------
- **ToolKit**: Woodward's Windows service tool for configuring and monitoring the easYgen genset controllers, the LS-5 and LS-6 breaker controls, the DTSC-200 transfer switch controller, the DSLC-2 and MSLC-2 synchronizers, Woodward E3 gas engine controls, and others. ToolKit saves the settings of a control to a ``.wset`` file.
- **Service Interface Definition (SID)**: the description of every parameter, status value, and event of a control, shipped by Woodward as a ``.sid`` file for each product, firmware release, and language. ToolKit uses it to talk to the control. ToolKit *applications* are identified by the SID's identifier, e.g. ``5418-6722-NEW`` (easYgen-3000 and older, a Woodward software part number and revision) or ``EG3500XTP2 2.17-0_54728`` (easYgen-3000XT, a product short name, release, hotfix, and build number).
- **LogicsManager**: the easYgen's programmable logic. Each LogicsManager parameter is an equation of three command variables (inputs), per-input operators (pass-through, ``Not``, ``True``, ``False``), two binary operators (``And``, ``Or``, ...), and on and off delays.
- **Control Assistant**: Woodward's service tool for GAP-based controls (2301E, 505, Atlas, MicroNet, and others). Its "Tunable Maintenance" feature saves the tunable values of a control to a ``.tc`` file.
- **ServLink**: Woodward's proprietary service protocol, used over RS-232 and TCP (port 666) by both ToolKit and Control Assistant. PEAT scans and pulls easYgen and 2301E controls with it.

File types
----------
.. csv-table::
   :header: "Extension", "Name", "Contents", "PEAT support"
   :widths: 10, 20, 45, 25
   :align: left

   "``.wset``", "ToolKit settings file", "The complete configuration of a control (every parameter and its value), saved from a device or created offline. Binary: a 10-byte ToolKit header followed by two .NET binary serialization (:term:`NRBF`) streams.", "Parsed by :func:`~peat.modules.woodward.parse_wset.parse_wset`. All parameters are extracted with their values, defaults, ranges, units, enumerations, security levels, and ServLink handles."
   "``.sid``", "Service Interface Definition", "All parameters, status values, LogicsManager equations, enumerations, and events of a firmware release, with their defaults, ranges, and security levels. XML, either compressed (ToolKit header plus gzip) or plain (the ``.CAN.sid`` variant).", "Parsed by :func:`~peat.modules.woodward.parse_sid.parse_sid`. Note that a SID holds parameter *definitions* and defaults, not the values configured on a device."
   "``.wtool``", "ToolKit tool file", "The ToolKit screens for a control, associated with one or more SIDs. Binary, same container as ``.wset``.", "Parsed by :func:`~peat.modules.woodward.parse_wtool.parse_wtool`. Only the tool properties, device names, and SID references are extracted. Decoding a large tool file takes several seconds."
   "``.tc``", "Control Assistant tunable file", "The tunable values of a control: tab-separated text with ``Mode``, ``Category``, ``Block Name``, ``Field Name``, ``Type``, ``Current``, ``Initial``, ``Low``, and ``High`` columns.", "Parsed by :func:`~peat.modules.woodward.wdw_tc.parse_tc`."
   "``.htm``", "ToolKit settings export", "Hierarchical or tabular HTML export of a settings file (ToolKit *File > Export*).", "Not parsed. Export the ``.wset`` instead."
   "``.msi``, ``.CONVERT.txt``, ``.eds``, ``.map``, ``.scp``", "ToolKit application package, settings conversion map, CANopen EDS, Modbus mapper file, firmware", "Published by Woodward per product and firmware release. easYgen-3000XT controls also store the application package on their internal USB mass storage.", "Not parsed. The ``.sid`` and ``.wtool`` files inside the ``.msi`` package can be extracted and parsed."

Supported devices
-----------------
The ToolKit file formats are shared by every ToolKit-based Woodward control, so :class:`~peat.modules.woodward.easygen_3500xt.Easygen3500XT` parses files for all of them. The device model is identified from the ToolKit application identifier in the file (see :data:`~peat.modules.woodward.toolkit.TOOLKIT_APPLICATIONS` and :func:`~peat.modules.woodward.toolkit.identify_application`), and is reported as ``unknown`` if the identifier isn't recognized.

.. csv-table::
   :header: "Device", "Software", "Notes"
   :widths: 30, 15, 55
   :align: left

   "easYgen-3100XT, 3200XT, 3400XT, 3500XT (P1, P2, LT, LITE, and RENTAL variants); LS-6XT, GC-3400XT, DSLC-2XT, MSLC-2XT, RP-3000XT", "ToolKit 6.x/7.x", "XT-style application identifiers (``EG3500XTP2 2.17-0_54728``) are decoded into the model, release, and build. Verified with a published easYgen-3500XT-P2 SID and tool file. No public XT settings file was available for testing, and Woodward documents that XT settings files aren't compatible with earlier ones. The container format is expected to be the same."
   "easYgen-3100, 3200, 3400, 3500 (first generation); RP-3000, DSLC-2, MSLC-2", "ToolKit 3.x-6.x", "Verified with two published easYgen-3500 settings files (application ``5418-6722-NEW``, firmware 1.2102). Only known application part numbers are mapped to a model."
   "easYgen-2200, 2300, 2500; LS-5; DTSC-200; MFR 300", "ToolKit 3.x+", "Same file formats. Not tested, as no public files were found."
   "Woodward E3 gas engine controls (Full Authority, Fuel Blending, Lean Burn Trim)", "ToolKit 4.x", "Verified with the settings, SID, and tool files Woodward publishes in its E3 HMI packages. These files use additional parameter types (boolean and lookup table parameters) which are supported."
   "easYgen-1000, easYgen-300, LS-4, MFR 2/11/15", "LeoPC1", "Not supported. These devices don't use ToolKit."
   "easYgen-400, 600, 800, 1400, 1600, 1700, 1800", "ToolKit-SC", "Not supported. ToolKit-SC is a separate product, and its file formats haven't been researched."
   "2301E, 505, Atlas, 723PLUS, MicroNet (Control Assistant tunable files)", "Control Assistant", "``.tc`` files are parsed by :class:`~peat.modules.woodward.wdw_2301e.WDW2301E` (and also by the easYgen module). The layout was taken from PEAT's original parser, as no public example files exist."

Usage
-----
.. code-block:: shell

   # Parse a ToolKit settings file saved from an easYgen
   peat parse -d easygen ./genset-1.wset

   # Parse the published example settings file (stored compressed in the repository)
   gunzip -k ./examples/devices/woodward/easygen-3500/4_MVA_Diesel_20161116.wset.gz
   peat parse -d easygen ./examples/devices/woodward/easygen-3500/4_MVA_Diesel_20161116.wset

   # Parse a SID or tool file from a ToolKit application package
   peat parse -d easygen "./EG3500XTP2 2.17-0_54728.sid"
   peat parse -d easygen ./8440-2088_M_EG3500XTP2_2.17-0_54728.wtool

   # Parse a Control Assistant tunable file saved from a 2301E
   peat parse -d wdw2301e ./2301e-tunables.tc

   # Let PEAT pick the module by file name and signature. Note that .tc files
   # match both Woodward modules and are parsed by each of them.
   peat parse ./toolkit-files/

   # Piped input works too, the file type is detected from its contents
   cat ./genset-1.wset | peat parse -d easygen -

The parsed data is saved as ``parsed-wset.json``, ``parsed-sid.json``, ``parsed-wtool.json``, or ``parsed-tc.json`` in the device's output directory, next to the device data files. A summary of the file is added to the device data under ``extra.wset``, ``extra.sid``, ``extra.wtool``, or ``extra.tc``, the parameter values under ``extra.parameters``, and the application identity to the device description (brand, model, product) and firmware identifier.

Python API:

.. code-block:: python

   from pathlib import Path

   from peat.modules.woodward.parse_wset import parse_wset
   from peat.modules.woodward.parse_sid import parse_sid

   settings = parse_wset(Path("genset-1.wset"))
   print(settings["application"]["product"], settings["num_parameters"])
   for parameter in settings["parameters"]:
       if parameter["kind"] == "logics_manager":
           print(parameter["name"], parameter["expression"])
       else:
           print(parameter["name"], parameter["value"], parameter["units"])

   sid = parse_sid(Path("EG3500XTP2 2.17-0_54728.sid"))
   print(sid["security"]["servlink"]["command_security_levels"])

Settings file (``.wset``) output
--------------------------------
:func:`~peat.modules.woodward.parse_wset.parse_wset` returns the container ``header``, the ``nrbf`` stream information, the ``settings_header`` (SID specification, application identifier, notes, partial settings flags), the ``application`` identity, the ``parameters``, and the LogicsManager command variable list (``logics_manager_inputs``). Each parameter record has:

.. csv-table::
   :header: "Field", "Description"
   :widths: 25, 75
   :align: left

   "``name``, ``group``, ``id``, ``label``", "The full parameter name as stored in the file (e.g. ``Config_Monitoring.Generator.Overfrequency level 2.1910 Limit``), split into its group, parameter number, and label. Internal variables without a parameter number are in the ``(internal)`` group."
   "``kind``", "``basic`` (a stored value), ``computed`` (a scaled view of a basic parameter: ``value = source * multiplier + offset``), ``bit_field`` (one bit of a basic parameter), ``logics_manager`` (a LogicsManager equation), ``lookup_table``/``array``, or ``generic`` (unknown object layout)."
   "``type``", "``integer``, ``float``, ``boolean``, ``enumerated``, ``string``, ``bit_fields``, ``bit_field``, ``logics_manager``, or ``array``."
   "``value``, ``value_text``", "The configured value converted to a Python type, and the text as stored in the file. Enumerated parameters have the option name as value and the number in ``enum_value`` with all ``options``. LogicsManager parameters have the equation as a :class:`dict` and a readable ``expression``, e.g. ``[False 00.01 LM: Flag 1] And [True 00.01 LM: Flag 1] And [True 00.01 LM: Flag 1], delay on 0 s, delay off 0 s``."
   "``initial``, ``minimum``, ``maximum``, ``units``", "The default value, range, and units from the SID descriptor."
   "``read_security_level``, ``write_security_level``, ``access_type``", "The easYgen code (password) levels required to read and change the parameter, and the SID access type."
   "``servlink_handle``, ``canopen_multiplexor``", "The ServLink handle and CANopen multiplexor of the parameter, useful for correlating with live reads from the device."
   "``source``, ``multiplier``, ``offset`` / ``base_parameter``, ``bit_position`` / ``arrays``", "Details of computed, bit field, and lookup table parameters."

SID (``.sid``) output
---------------------
:func:`~peat.modules.woodward.parse_sid.parse_sid` returns the SID ``identifier``, ``specification``, and ``schema``, the ``application`` identity, the ServLink ``security`` configuration (accounts and command security levels), the top-level ``namespaces`` (``PARAMETER``, ``STATUS MENU``, ``ALARM STATUS``, ...), the ``parameters`` (every ``DataItem``, ``LogicManager``, and ``StructureItem`` with its namespace ``path``, type, default, range, units, security levels, and communication handles), the ``enumerations``, ``events``, and ``structures``.

Tunable file (``.tc``) output
-----------------------------
:func:`~peat.modules.woodward.wdw_tc.parse_tc` returns the file metadata (``file_version``, ``firmware_prefix``, ``firmware_date``), the nested ``config`` tree (``Mode > Category > Block Name > Field Name``) with the raw text values, and a flat ``parameters`` list with the ``current``, ``initial``, ``low``, and ``high`` values converted to Python types.

Notes and limitations
---------------------
- The model of a device is only identified when the application identifier is recognized. XT-style identifiers are always decoded. Older part number identifiers are looked up in :data:`~peat.modules.woodward.toolkit.TOOLKIT_APPLICATIONS`, which only contains the applications that could be verified from public files and manuals. Add entries there for the applications of your devices (the part number is printed on the control's nameplate and in the ``.wtool``/``.sid`` file names Woodward publishes).
- Woodward doesn't document the ``.wset`` format. PEAT's parser was reverse engineered from published files saved by ToolKit 4.x and 5.x. Unknown object layouts are still decoded and reported using a best-effort ``generic`` parameter extraction, and the full decoded object graph is available with ``parse_wset(..., include_raw=True)``.
- The meaning of the LogicsManager operator numbers was derived empirically: pass-through (``NoOperator``), ``Not``, ``True``, and ``False`` for the per-input operators and ``And`` and ``Or`` for the binary operators were observed. The remaining binary operators (``Nand``, ``Nor``, ``Xor``, ``Nxor``) follow the order in the easYgen manuals and are unverified.
- ``.tc`` files are matched by both the easYgen and the 2301E modules. Pass ``-d easygen`` or ``-d wdw2301e`` to ``peat parse`` to parse them once with the right module.
- Pulling settings from a live easYgen (``peat pull``) uses ServLink/TCP and FTP and doesn't produce a ``.wset`` file. Save the settings with ToolKit to parse them with PEAT.

Example files
-------------
- ``examples/devices/woodward/easygen-3500/4_MVA_Diesel_20161116.wset.gz``: a real easYgen-3500 settings file (gzip compressed) from the MIT Lincoln Laboratory `EPHCC <https://github.com/PowerSystemsHIL/EPHCC>`__ project (MIT license).
- Woodward publishes ToolKit application packages (``.msi`` files containing the ``.wtool`` and ``.sid`` files) for the easYgen-3000XT series on its `easYgen-3000XT document site <https://wss.woodward.com/manuals/PGC/easYgen-3000XT_series/>`__, and ``.wset``, ``.sid``, and ``.wtool`` files for its E3 engine controls in the E3 HMI packages on `woodward.com <https://www.woodward.com/products/support/software-assets/service-tool/5418-4091-hmi_a/>`__.
- No public ``.tc`` file is known. The unit tests use a hand written example (``tests/modules/woodward/data_files/tunables_synthetic.tc``).
