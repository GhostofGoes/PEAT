# Woodward easYgen-3500 ToolKit settings file example

`4_MVA_Diesel_20161116.wset.gz` is a real settings file saved with Woodward ToolKit from a
Woodward easYgen 3500 genset controller (first generation, non-XT; Operating System
v1.2102, Bootloader v3.0011, ToolKit application `5418-6722-NEW`). It holds the complete
configuration of the controller for a 4 MVA diesel genset in a hardware-in-the-loop
microgrid test bed.

The file and `Firmware Version.txt` are from the MIT Lincoln Laboratory Electric Power HIL
Controls Consortium (EPHCC) repository, where they are published under the MIT license
(see `LICENSE.md`):

- Repository: <https://github.com/PowerSystemsHIL/EPHCC>
- Path: `Components/TyphoonHIL/genset/Controller Files/4_MVA_Diesel_20161116.wset`
- SHA-256 (decompressed): `6eda7f571a882b655097b0af0b9fae79855f33464112ab28d1f93131df4f0f33`

The file is stored gzip compressed to keep the repository small (1.9 MB uncompressed).
Decompress it, then parse it with PEAT:

```shell
gunzip -k ./examples/devices/woodward/easygen-3500/4_MVA_Diesel_20161116.wset.gz
peat parse -d easygen ./examples/devices/woodward/easygen-3500/4_MVA_Diesel_20161116.wset
```

The file is also used by the unit tests in `tests/modules/woodward/`.
