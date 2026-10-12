.. _schneider_file_formats:

=======================================
Schneider Electric project file formats
=======================================

.. contents::
   :local:
   :depth: 2

Overview
========
Unity Pro and EcoStruxure Control Expert are the programming software for Schneider Electric Modicon PLCs. This page describes the project files that this software writes.

.. csv-table::
   :header: "Extension", "Name", "Format", "Description"
   :widths: 10, 20, 15, 55

   "``.apx``", "Application file", "Binary", "The binary project that the software sends to the PLC. Refer to :ref:`schneider_apx_format`."
   "``.sta``", "Archive file", "ZIP", "An archive of a built project. It contains an APX file. Refer to :ref:`schneider_sta_format`."
   "``.stu``", "Project file", "ZIP", "The project that the software opens and edits. Refer to :ref:`schneider_stu_format`."
   "``.xef``", "Exchange file", "XML", "An XML export of the complete project. Refer to :ref:`schneider_xef_format`."
   "``.zef``", "Exchange file (compressed)", "ZIP", "A ZIP archive that contains an XEF file and some other files. Refer to :ref:`schneider_xef_format`."

These formats are proprietary. Schneider Electric does not publish a specification for them. This page describes the parts of the formats that are known. Many fields have an unknown meaning. A field name that ends in "maybe" has a meaning that is not certain.

The STA, STU and ZEF files are ZIP archives. Thus, the file extension identifies the type of these files. The first bytes do not.

These Modicon PLC families use these formats:

- M340
- M580
- Quantum (140 series)
- Premium
- Momentum (Unity versions)

.. _schneider_apx_plcs:

PEAT support
------------
PEAT reads APX files with the :class:`~peat.modules.schneider.m340.m340.M340` module. The code is in :mod:`peat.modules.schneider.m340.m340_parse`. The M340 module also reads APX files from Modicon Quantum 140 and Modicon Premium projects.

The PEAT tests use APX files from these projects:

- M340 projects from Unity Pro V8 and Control Expert V15.
- A Premium project from Control Expert V15.
- A Quantum project from Unity Pro V14.1.

.. _schneider_file_format_sources:

Sources
-------
This page uses the sources in this section. It also uses the PEAT source code, and tests on real project files from public projects. Refer to the README files in ``tests/modules/schneider/data_files/`` for the test files.

Vendor documentation
^^^^^^^^^^^^^^^^^^^^
Schneider Electric does not publish the internal structure of these files. These vendor articles tell what each file type is for:

- `What are the differences between .STU, .STA, .ZEF and .XEF files in Control Expert? (FAQ000259996) <https://www.se.com/us/en/faqs/FAQ000259996/>`__. This article refers to the *Control Expert Operating Modes* manual (33003101).
- `What are the different file extensions in Unity Pro? (FA225557) <https://www.se.com/in/en/faqs/FA225557/>`__.
- `List of file extensions used by Unity Pro (FA198016) <https://www.se.com/ae/en/faqs/FA198016/>`__.

These articles give this information:

- **STU** is the working file of a project. It contains all the data of the project. An STU file is specific to a version of the software. You cannot use it to move a project to a different version of the software.
- **STA** is an archive of a project. The software can write it only after it builds (generates) the project. An STA file does not contain the databases, so the software takes more time to open it. The newer versions of the software can open an STA file from an older version. An STA file is approximately 50 times smaller than the STU file.
- **STM** is the binary executable of the project. It is the file that the software sends to the PLC and gets from the PLC. The software cannot show its content.
- **XEF** is an XML export of the source of the complete project. It does not contain the global DTM configuration.
- **ZEF** is an XEF export that also contains the global DTM configuration.
- The software also exports parts of a project to other XML files:

  - ``.XHW``: the I/O configuration.
  - ``.XDD``: DDTs.
  - ``.XDB``: DFBs.
  - ``.XSY``: variables.
  - ``.XST``, ``.XLD``, ``.XIL``, ``.XBD`` and ``.XSF``: program sections in ST, LD, IL, FBD and SFC.

Reverse engineering
^^^^^^^^^^^^^^^^^^^
These third-party sources describe the internal structure of the files:

- `apxutil <https://github.com/finngineering/apxutil>`__ by finngineering (MIT License). The README and the source code describe the APX headers, the compression formats, the CRC16 and the memory layout. apxutil can also extract and assemble STA files. PEAT uses the same layouts.
- `The APX logic file format <http://lirasenlared.blogspot.com/2018/10/the-apx-logic-file-format.html>`__ on the Liras en la red blog (2018). This article describes the sections of an APX file from an M340 PLC. It also tells that the file contains CRC32 and CRC16 values that change each time the software builds the project.
- `Evil PLC Attack: Weaponizing PLCs <https://claroty.com/team82/research/white-papers/evil-plc-attack-weaponizing-plcs>`__ by Claroty Team82 (2022). The white paper describes how the programming software opens STU and STA files and reads the APX file. It tells that one type of APX section contains XML that is compressed with XMill. A defect in the XMill decoder is CVE-2022-26507.
- `Schneider Unity Pro ZEF files <https://pauljohnrickard.com/2020/06/03/schneider-unity-pro-zef-files/>`__ by Paul John Rickard (2020). The article shows that a ZEF file is a ZIP archive that contains XML.
- The Metasploit module `modicon_stux_transfer <https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/scada/modicon_stux_transfer.rb>`__. The module sends an APX file to a Modicon PLC, and gets the APX file from the PLC, with Modbus function code 90 (UMAS). It does not parse the file.

Other information about the protocol that transfers APX files is in :ref:`umas_protocol`.

.. _schneider_apx_format:

APX file format
===============
An APX file contains a complete project for a Modicon PLC. The file has the executable code of the PLC program. It also has all the data that Unity Pro or Control Expert must have to edit the program. Unity Pro and Control Expert send this file to the PLC during a full program download. They get this file from the PLC during a full program upload.

Where APX files come from
-------------------------
You can get an APX file in these ways:

- **From the PLC.** PEAT gets the project file from the PLC with :term:`UMAS` over Modbus/TCP (TCP port 502). Refer to :meth:`~peat.modules.schneider.m340.m340.M340.pull_apx_file`. The result is the same as the ``Station.apx`` file that Unity Pro writes.
- **From an STA file.** The APX file is ``BinAppli/Station.apx`` in the archive. Refer to :ref:`schneider_sta_format`.
- **From an STU file.** The APX file is ``BinAppli/Station.apx`` in the archive, but only if the project was built. Refer to :ref:`schneider_stu_format`.

Byte order and data types
-------------------------
All numbers are little-endian. This page uses these names for data types:

.. csv-table::
   :header: "Name", "Size", "Description"

   "u8", "1 byte", "Unsigned integer"
   "u16", "2 bytes", "Unsigned integer"
   "u32", "4 bytes", "Unsigned integer"

All offsets are byte offsets from the start of the structure. Offsets start at 0.

File structure
--------------
An APX file has two parts:

#. A file header of 32 bytes.
#. A sequence of sections. The sections continue to the end of the file.

Each section has these parts, in this sequence:

#. A section header. The size of the section header changes with the section type.
#. An RTE header. The file header gives the size of the RTE header. The size is 16 bytes in all known files.
#. The section data. Only sections of type 2 have data. The data can be compressed.

The next section starts immediately after the data of the previous section. There is no padding or alignment between sections.

.. code-block:: text

   +-------------------------+
   | File header (32 bytes)  |
   +-------------------------+
   | Section header          |  \
   | RTE header (16 bytes)   |   > Section 1
   | Section data            |  /
   +-------------------------+
   | Section header          |  \
   | RTE header (16 bytes)   |   > Section 2
   | Section data            |  /
   +-------------------------+
   | ...                     |
   +-------------------------+

The name "RTE" possibly means "RunTime Environment" or "RealTime Environment". The section header is possibly related to the APX file format. The RTE header is possibly related to the execution environment in the PLC. This difference is not certain.

File header
-----------
The file header is 32 bytes. The first 3 bytes are the ASCII text ``APX``. PEAT uses these 3 bytes to identify an APX file. Refer to :ref:`schneider_apx_identification`.

.. csv-table::
   :header: "Offset", "Type", "Name", "Description"
   :widths: 8, 8, 25, 59

   "0", "u32", "magic", "The bytes ``41 50 58 00`` (``APX`` and a zero byte)."
   "4", "u16", "version_maybe", "Possibly a format version. The value is ``0x0100`` in all known files."
   "6", "u8", "rte_type", "The type of RTE header in each section. The value is 2 in all known files. Type 1 is possibly for a 16-bit address space. Type 2 is possibly for a 32-bit address space."
   "7", "u8", "header_count_maybe", "Unknown. The value is 1 in all known files."
   "8", "u16", "sdsection_total_size", "The total size of the SD section. This size includes the section header, the RTE header and the section data."
   "10", "u8", "rte_size", "The size of the RTE header in each section, in bytes. The value is 16 for RTE type 2."
   "11", "u32", "sdsection_39_4", "Unknown. The SD section contains the same value at offset 39. The Liras en la red article tells that a CRC32 is at this offset."
   "15", "u32", "sdsection_35_4", "Unknown. The SD section contains the same value at offset 35."
   "19", "u16", "sesection_8_2", "Unknown."
   "21", "11 bytes", "zero_pad_21_11", "Zero bytes in all known files."

This example is the file header of a real M340 project:

.. code-block:: text

   00000000  41 50 58 00 00 01 02 01  10 01 10 13 2c 62 17 4e  |APX.........,b.N|
   00000010  68 05 0b 06 01 00 00 00  00 00 00 00 00 00 00 00  |h...............|

In this example, the RTE type is 2 and the RTE size is 16 (``0x10``). The SD section has a total size of 272 bytes (``0x0110``). This is 16 bytes of section header, 16 bytes of RTE header and 240 bytes of data.

PEAT reads the RTE type and the RTE size from the file header. If the RTE size is 0, PEAT uses 16 bytes. If the RTE type is not 2, PEAT writes a warning and does not decode the RTE header fields.

Section header
--------------
The section header starts with a u16 that gives the section type. The section type sets the size of the section header.

.. csv-table::
   :header: "Section type", "Header size", "Has data", "Seen in real files"

   "0", "8 bytes", "No", "Yes"
   "1", "16 bytes", "No", "Yes"
   "2", "16 bytes", "Yes", "Yes"
   "3", "24 bytes", "No (possibly)", "No"
   "4", "24 bytes", "No (possibly)", "No"

These fields are known:

.. csv-table::
   :header: "Offset", "Type", "Section types", "Description"
   :widths: 8, 8, 14, 70

   "0", "u16", "All", "The section type."
   "4", "u16", "All", "The section number. Some section numbers are possibly fixed. Other section numbers possibly change between projects."
   "10", "u32", "2", "The size of the section data in the file, in bytes. If bit 28 of the RTE attributes is set, the section has no data. Then the size is 0."

The meaning of the other bytes is not known.

If the section type is not in the range 0 to 4, PEAT cannot find the start of the next section. PEAT writes a warning and stops at that location.

.. note::

   PEAT keeps two values for the section number. The ``section_number`` value is the u16 at offset 4. The ``number`` value is the u32 at offset 4. PEAT keeps the ``number`` value for compatibility with older code. Use ``section_number`` in new code.

RTE header
----------
The RTE header follows the section header. This layout is for RTE type 2. The layout for other RTE types is not known.

.. csv-table::
   :header: "Offset", "Type", "Name", "Description"
   :widths: 8, 8, 16, 68

   "0", "u32", "block_count", "Unknown. apxutil uses this name, but the meaning is not known."
   "4", "u32", "size_minus1", "For a section with data, the size of the section data minus 1. For a section without data, the meaning is not known. Section 0x0011 (RT) does not obey this rule."
   "8", "u32", "attributes", "Flags. Refer to :ref:`schneider_apx_attributes`."
   "12", "u16", "crc16", "The CRC16 of the section data. Refer to :ref:`schneider_apx_crc`."
   "14", "u8", "membyte", "The memory area and the memory folio of the section. Refer to the next paragraph."
   "15", "u8", "(unused)", "Possibly not used."

The ``membyte`` field contains two values:

- Memory area: bits 3 to 7 (``membyte >> 3``).
- Memory folio: bits 0 to 2 (``membyte & 0x07``).

The apxutil source code and PEAT use this split. The apxutil README gives a different split (3 high bits for the area and 5 low bits for the folio). It is not certain which split is right.

.. _schneider_apx_attributes:

RTE attributes
^^^^^^^^^^^^^^
The meaning of most attribute bits is not known. These bits are known:

.. csv-table::
   :header: "Bit", "Mask", "Description"

   "13", "``0x00002000``", "The section data is compressed. Refer to :ref:`schneider_apx_compression`."
   "28", "``0x10000000``", "The section has no data in the file. The data size in the section header is 0."

Older PEAT code uses the 4 bytes of the attributes field as a "type" for each section. For example, the type ``03 24 cf e0`` identifies the sections that contain the variables. Refer to :ref:`schneider_apx_content`.

.. _schneider_apx_crc:

CRC16
^^^^^
The ``crc16`` field contains a CRC16/Kermit checksum of the section data, as stored in the file. The checksum uses these parameters:

- Polynomial: ``0x8408`` (reflected form of ``0x1021``).
- Initial value: ``0xFFFF``.
- No final XOR.

PEAT calculates the checksum with :func:`~peat.modules.schneider.m340.m340_parse.crc16_kermit`. PEAT compares the result with the stored value and sets ``crc_valid`` on the section. If the values are different, PEAT writes a warning. The section is possibly damaged or changed.

PEAT does not do the check in these conditions:

- The section is section 0x0011 (RT). The CRC of this section covers more than its data.
- The stored CRC is 0. Some real Quantum projects contain sections with a CRC of 0. A value of 0 possibly means that the software did not calculate the CRC.
- The section has no data.

.. _schneider_apx_compression:

Compression
-----------
If bit 13 of the RTE attributes is set, the section data is compressed. Real files use three compression formats. The first bytes of the data identify the format:

.. csv-table::
   :header: "First bytes", "Format", "How to decompress"
   :widths: 20, 20, 60

   "``50 4B 01 02`` (``PK\x01\x02``)", "ZIP", "Skip a header of 46 (``0x2E``) bytes. The remaining data is a raw deflate stream (no zlib header)."
   "``5A 4C 49 42`` (``ZLIB``)", "zlib", "Skip a header of 16 bytes. The remaining data is a standard zlib stream."
   "``78``", "zlib streams", "The data is one or more zlib streams, one after the other. Decompress each stream and join the results."

All three formats occur in each of the tested files.

PEAT decompresses the data with these rules:

#. If the RTE attributes give the compression state, PEAT uses it.
#. If the data is compressed but the format is not known, or decompression fails, PEAT scans the data for zlib and ZIP signatures. PEAT decompresses all the streams that it finds.
#. If the compression state is not known (RTE type is not 2), PEAT also scans the data.

The ``data`` value of each section is the decompressed data.

.. _schneider_apx_sections:

Special sections
----------------
Two sections have a special function. They are possibly related to the RTE and the memory layout of the PLC. In real files, the first two bytes of the section data identify these sections:

.. csv-table::
   :header: "Section number", "Data starts with", "Description"
   :widths: 15, 15, 70

   "0x0001", "``SD``", "The memory layout of the PLC. Refer to :ref:`schneider_apx_sd`."
   "0x0011", "``RT``", "Unknown content. The ``size_minus1`` and ``crc16`` fields of this section do not obey the usual rules."

.. important::

   The apxutil README gives the names the other way around (0x0001 "RT" and 0x0011 "SD"). Tests on real M340, Premium and Quantum files show that section 0x0001 starts with ``SD`` and section 0x0011 starts with ``RT``. PEAT uses the names from the real files.

.. _schneider_apx_sd:

SD section (memory layout)
^^^^^^^^^^^^^^^^^^^^^^^^^^
The SD section describes the memory areas of the PLC and the folios in each area. This layout comes from apxutil. It is only partially known. PEAT decodes it with :func:`~peat.modules.schneider.m340.m340_parse.parse_sd_section`. PEAT puts the result in ``memory_layout`` in the parsed configuration.

All offsets in this table are from the start of the SD section data.

.. csv-table::
   :header: "Offset", "Type", "Description"
   :widths: 25, 8, 67

   "0", "2 bytes", "The ASCII text ``SD``."
   "4", "u16", "The offset of the memory header."
   "6", "u16", "Data size. The meaning is not certain."
   "12", "u16", "Data flag. The meaning is not certain."
   "Memory header + 0", "u16", "The size of the memory header."
   "Memory header + 2", "u16", "The size of each memory area entry."
   "Memory header + 4", "u16", "The size of each memory folio entry."
   "Memory header + 6", "u8", "The number of memory areas."

The memory area entries start immediately after the memory header. The folio entries of each memory area follow its area entry.

Memory area entry:

.. csv-table::
   :header: "Offset", "Type", "Description"

   "0", "u8", "Area number."
   "1", "u8", "The number of folio entries that follow the area entry."
   "2", "u8", "Area type."
   "3", "u32", "Area address."

Memory folio entry:

.. csv-table::
   :header: "Offset", "Type", "Description"

   "0", "u8", "Folio number. The meaning is not certain."
   "1", "u32", "Folio size."
   "5", "u16", "Folio attributes."
   "9", "u32", "A second folio size. The meaning is not certain."

The tested M340 and Quantum files have three memory areas. The tested Premium file has two memory areas.

.. _schneider_apx_content:

Section content
---------------
Most sections contain project data. Many sections contain XML or a binary form of XML. PEAT identifies some sections by the 4 bytes of the RTE attributes. The table shows the sections that PEAT reads.

.. csv-table::
   :header: "Attribute bytes", "Content", "PEAT function"
   :widths: 20, 45, 35

   "``03 24 cf e0``", "Variables (name, type, address, comment). A section with ``COMExchangeFile`` data contains the configuration of the communication modules (IP addresses, SNMP, bandwidth).", ":func:`~peat.modules.schneider.m340.m340_parse.extract_variables`, :func:`~peat.modules.schneider.m340.m340_parse.parse_config_to_dict`"
   "``00 80 8f e0``", "Initial values of variables.", ":func:`~peat.modules.schneider.m340.m340_parse.extract_initial_values`"
   "``03 20 cf e0``", "Program sections. The data contains ``STExchangeFile``, ``FBDExchangeFile`` or ``LDExchangeFile``.", ":func:`~peat.modules.schneider.m340.m340_parse.extract_logic_blocks`"
   "``00 00 8f e0``", "Project metadata (project name, description, software version, user name and file path). PEAT reads this only from the section with a ``number`` of 20.", ":func:`~peat.modules.schneider.m340.m340_parse.parse_config_to_dict`"
   "``08 00 83 e0``", "Status information.", ":func:`~peat.modules.schneider.m340.m340_parse.parse_config_to_dict`"
   "``00 20 8f e0``", "Rack configuration as XML. The XML contains the modules in the rack and their I/O groups.", ":func:`~peat.modules.schneider.m340.m340_parse.parse_config_to_dict`"

Binary XML
^^^^^^^^^^
Some sections contain a binary form of XML. The data starts with an XML declaration. After the declaration, the data is a sequence of fields. A length comes before each field:

- If the high bit of the length byte is 0, the length is 1 byte. The value is 0 to 127.
- If the high bit of the length byte is 1, the length is 2 bytes. The length is ``(byte1 & 0x0F) * 256 + byte2``.

PEAT reads these fields with :func:`~peat.modules.schneider.m340.m340_parse.strip_xml`.

The Claroty Team82 white paper tells that the software uses XMill to compress the XML in some APX sections. The format that PEAT reads is possibly a form of XMill. This is not certain.

Variable records
^^^^^^^^^^^^^^^^
In a variables section, each variable record starts with the bytes ``06 00``. A list of fields follows. A 2-byte tag identifies each field. A zero byte ends each text field.

.. csv-table::
   :header: "Tag", "Field"

   "(none)", "Variable name, then variable type."
   "``30 00``", "Unknown, 1 byte."
   "``31 00``", "Memory location, 3 bytes, little-endian."
   "``03 00``", "Topological address, for example ``%MW10``."
   "``02 00``", "Comment."
   "``71 00``", "Custom field."

Initial value records
^^^^^^^^^^^^^^^^^^^^^
In an initial values section, each record sets the values of one or more variables. The memory location of the record is the location of the first variable. A record has these fields:

#. A type byte. ``01`` is for coils (1 byte for each value). ``00`` is for registers (2 bytes for each value).
#. A count byte. For coils, the count is the number of values. For registers, the count is the number of bytes.
#. A memory location, 3 bytes, little-endian.
#. One byte that is not known.
#. The values.

Six zero bytes end the list of records.

.. _schneider_apx_identification:

File identification
-------------------
PEAT uses two methods to find APX files:

- **Filename pattern.** The M340 module accepts files that have the ``.apx`` extension.
- **File signature.** The M340 module accepts files that start with the bytes ``41 50 58`` (``APX``). Refer to :class:`~peat.file_signature.FileSignature`. This method finds APX files that have a different name, or data that has no file name.

Known limits
------------
- The meaning of many header fields and attribute bits is not known.
- The layout of RTE types other than 2 is not known.
- PEAT does not convert the executable code in the file.
- PEAT does not find Structured Text in the tested APX files from Unity Pro V8, Control Expert V15 and Unity Pro V14.1. The variables, the metadata and the configuration are available. The program logic is not. The program logic is possibly in a different section, or in a different format, in these versions.
- PEAT does not convert FBD or LD sections to TC6 XML.
- Password protection and encryption are not known.

Write APX files only if you understand the risk. apxutil can assemble an APX file from changed sections. A changed APX file can possibly damage a real PLC.

.. _schneider_sta_format:

STA file format
===============
An STA file is an archive of a built project. The software can write an STA file only after it builds the project. The STA file does not contain the databases of the project. Newer versions of the software can open an STA file from an older version. Refer to :ref:`schneider_file_format_sources`.

An STA file is a ZIP archive. The tested STA files contain these members:

.. csv-table::
   :header: "Member", "Description"
   :widths: 35, 65

   "``BinAppli/Station.apx``", "The APX file. Refer to :ref:`schneider_apx_format`."
   "``BinAppli/Station.apd``", "A 32-byte file that starts with the ASCII text ``APD``. In the tested files, bytes 4 to 6 and 10 to 31 are the same as in the APX file header. The file is possibly an integrity check for the APX file header."
   "``STATION.CTX``", "Project properties as pairs of names and values, for example ``APPLICATION NAME``, ``APPLICATION DATE`` and ``APPLICATION LIBSET``. Refer to :ref:`schneider_ctx_files`."
   "``props.xml``", "Project properties as XML. Refer to :ref:`schneider_props_xml`."
   "``TA.xma``", "A zlib stream. The content is not known."
   "``ThirdParty/DtmAuditRecord.xml``", "Audit records of the DTMs (Device Type Managers) in the project."

To get the APX file, open the ZIP archive and read ``BinAppli/Station.apx``. apxutil can also extract and assemble STA files.

.. _schneider_stu_format:

STU file format
===============
An STU file is the project file that Unity Pro and Control Expert open and edit. It contains all the data of the project. An STU file is specific to a version of the software. An STU file is a ZIP archive. Most members are databases of the programming software. The tested STU files contain these members:

.. csv-table::
   :header: "Member", "Description"
   :widths: 35, 65

   "``*.db``, ``*.DB``, ``*.ODB``", "Databases, for example ``VariableManager.db``, ``TypeManager.ODB``, ``ASPROG.db`` and ``ConfProject.db``. Each database starts with the bytes ``65 58 63 0D 0A 65 6C 6F 6E 0D 64 62 0A`` (``eXc\r\nelon\rdb\n``). This text possibly refers to the eXcelon (ObjectStore) object database. The database format is not known."
   "``BinAppli/Station.apx``", "The APX file. This member is only in the archive if the project was built."
   "``BinAppli/PreviousStation.apx``", "The APX file of an earlier build. This member is not always in the archive."
   "``BinAppli/Station.apd``", "The same as in an STA file."
   "``STATION.CTX``, ``FLAGS.CTX``, ``OMCS.CTX``", "Pairs of names and values. Refer to :ref:`schneider_ctx_files`."
   "``props.xml``", "Project properties as XML. Refer to :ref:`schneider_props_xml`."
   "``Project_Definition.xpdf``, ``Project_Settings.xso``", "Project definitions and project settings as XML."
   "``backend/<number>/gen/asm_int/*.asm``", "Generated assembly code for the program sections, with a ``list_sections.txt`` file. These members are only in some tested files."
   "``<GUID>.stu``", "Other STU files in the archive. The tested M580 Safety project contains these members."

PEAT cannot read the databases. If the project was built, PEAT can read the APX file in the archive.

.. _schneider_props_xml:

props.xml
---------
The ``props.xml`` member is in STA, STU and ZEF files. It is a small XML file with a ``<Properties>`` root element. This example comes from a real STU file:

.. code-block:: xml

   <Properties>
     <ExtendedProperties></ExtendedProperties>
     <CategoryPLC>Micro Basic BMX P34 2000 03.20</CategoryPLC>
     <Author>gestrade</Author>
     <Title>Projet</Title>
     <AppBuilt>FALSE</AppBuilt>
     <ProductVersion>Control Expert 15.30</ProductVersion>
     <Content>Full application</Content>
     <AppProtected>FALSE</AppProtected>
   </Properties>

The ``CategoryPLC`` element gives the PLC family, the CPU part number and the CPU firmware version. The ``ProductVersion`` element gives the software version that wrote the file.

.. _schneider_ctx_files:

CTX files
---------
The ``.CTX`` members contain a list of strings. The strings alternate between a name and a value. Each string has this format:

#. The bytes ``FF FE FF``.
#. A u8 that gives the number of characters.
#. The characters, as UTF-16LE (2 bytes for each character).

This format is possibly the format that the Microsoft Foundation Classes (MFC) use to store Unicode strings.

.. _schneider_xef_format:

XEF and ZEF file formats
========================
An XEF file is an XML export of a complete project. Unity Pro and Control Expert write it when you export the project. They can also import it. An XEF file does not contain the global DTM configuration. An XEF file is plain text, so you can read it and compare it with other versions.

A ZEF file is a ZIP archive. It is an XEF export that also contains the global DTM configuration. The tested ZEF files contain these members:

.. csv-table::
   :header: "Member", "Description"
   :widths: 35, 65

   "``unitpro.xef``", "The project as XML. The root element is ``<ZEFExchangeFile>``. The other content is the same as in an XEF file."
   "``props.xml``", "Project properties. Refer to :ref:`schneider_props_xml`."
   "``Project_Definition.xpdf``", "Project definitions as XML."
   "``DTM/FDTDTMTopology.xml``", "The topology of the DTMs in the project."
   "``DtmAuditRecord.xml``", "Audit records of the DTMs. This member is not always in the archive."

XEF structure
-------------
The root element of an XEF file is ``<FEFExchangeFile>``. The file is UTF-8. These are the main child elements of the root element:

.. csv-table::
   :header: "Element", "Content"
   :widths: 25, 75

   "``fileHeader``", "The software that wrote the file (``product``), the export date and the DTD version."
   "``contentHeader``", "The project name, the project version and the date of the last change."
   "``commParameters``", "The address that the software uses to connect to the PLC."
   "``IOConf``", "The hardware configuration: the PLC, the racks, the power supplies and the modules. ``partItem`` elements give the family, the part number and the version of each item. ``equipInfo`` elements give the topological address and the slot."
   "``EFSource``, ``EFBSource``", "Elementary functions and elementary function blocks from libraries."
   "``FBSource``", "Derived function blocks (DFBs). Each one has its parameters, its variables and its program in ``FBProgram``."
   "``DDTSource``", "Derived data types (DDTs), for example structures."
   "``dataBlock``", "The variables. Each variable has a name, a type, a topological address (for example ``%MW10``), an initial value and a comment."
   "``logicConf``", "The tasks (for example ``MAST``) and the sequence of the program sections in each task."
   "``program``", "One program section. ``identProgram`` gives the name, the type and the task. The code is in an ``STSource``, ``ILSource``, ``LDSource``, ``FBDSource`` or ``SFCSource`` element."
   "``NetworkManager``", "The Ethernet network configuration, for example the IP addresses of devices."
   "``animationTable``, ``IOScreen``", "Animation tables and operator screens of the programming software."
   "``Documentation``", "Project documentation, for example the author."

Dates in the file use this format: ``date_and_time#2021-4-1-17:47:9``. Numbers in the date do not have leading zeros.

The program sections keep the source code of each language:

- Structured Text (ST) and Instruction List (IL) sections contain the source text.
- Function Block Diagram (FBD) sections contain blocks (``FFBBlock``) with their parameters and links between the pins of the blocks (``linkFB``).
- Ladder Diagram (LD) sections contain lines of cells (``typeLine``) with contacts, coils, horizontal links and vertical links.
- Sequential Function Chart (SFC) sections contain steps, transitions, actions and links (``networkSFC``).
