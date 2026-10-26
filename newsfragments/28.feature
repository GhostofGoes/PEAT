Added the :class:`~peat.modules.siemens.s7.S7` module for Siemens SIMATIC S7 PLCs (S7-300, S7-400, S7-1200, S7-1500).

- Scan and pull basic information (order number, firmware version, serial number, PLC name, operating mode, block counts) using read-only S7comm System Status List (SZL) reads
- Parse STEP 7 V5.x projects and project archives, TIA Portal projects and archives (metadata), TIA Portal Openness XML (SimaticML) exports, STL/SCL sources, and symbol tables
- Added the ``s7comm`` protocol options (TCP port 102), and ``s7`` module options to the configuration
- Documented S7 engineering software, file formats, public example files, and virtual PLCs that can be used for development in :ref:`siemens-s7`
