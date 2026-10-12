Improved parsing of Schneider Modicon (M340) APX project files, using format details documented by `apxutil <https://github.com/finngineering/apxutil>`_ (MIT License).
Section and RTE header sizes are now read from the APX file header instead of being hardcoded, section types 3 and 4 no longer stop parsing, and sections flagged as having no data are handled.
The RTE header of each section is decoded (attributes, CRC16, memory area and folio), and the CRC16 of each section's data is verified, with a warning logged for mismatches, which can indicate a corrupted or modified project file.
Section data is now only decompressed when the section is flagged as compressed, which avoids corrupting uncompressed data that happens to contain zlib signatures; the previous scanning behavior is kept as a fallback.
The PLC memory layout from the "SD" section is added to the parsed configuration as ``memory_layout``.
