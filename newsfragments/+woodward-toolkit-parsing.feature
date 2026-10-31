Added parsing of Woodward ToolKit and Control Assistant configuration files, so ``peat parse`` works with the files of easYgen genset controllers (easYgen-3000XT, easYgen-3000, and easYgen-2000 series) and other ToolKit-based Woodward controls:

- ToolKit settings files (``*.wset``): every parameter is extracted with its value, default, range, units, enumeration, security levels, and ServLink handle, including computed values, bit fields, lookup tables, and LogicsManager equations (``peat.modules.woodward.parse_wset``).
- ToolKit Service Interface Definitions (``*.sid``, compressed or plain XML): all data items, LogicsManager equations, enumerations, events, and ServLink security settings (``peat.modules.woodward.parse_sid``).
- ToolKit tool files (``*.wtool``): tool properties, device names, and SID references (``peat.modules.woodward.parse_wtool``).
- Control Assistant tunable files (``*.tc``): rewritten parser with encoding and line ending detection, typed values, and a flat parameter list, shared by the easYgen and 2301E modules (``peat.modules.woodward.wdw_tc``).

The ``Easygen3500XT`` module identifies the files by content (file signatures) as well as by extension, records the device model from the ToolKit application identifier, and writes the parsed data to ``parsed-<type>.json``. A real easYgen-3500 settings file is included in ``examples/devices/woodward/`` and the formats are documented in the new Woodward documentation page.
