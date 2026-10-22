# SEL relay test data

Test data for the `SELRelay` module (`tests/modules/sel/test_sel_relay_parse.py` and `tests/modules/sel/test_relay_parse.py`).

Real SEL relay settings files with a clear open license are hard to find. As of October 2026, the SEL-710 QuickSet database below was the only one we found. Only real files belong here: please don't add synthetic or hand-written settings files. Tests that need other layouts copy and rearrange these files at test time, and small cases use inline strings in the tests.

Please add real settings files here (sanitized as needed) if you have ones that can be shared.

## Real files

| File | Source | License |
| --- | --- | --- |
| `sel-710_Relay710.rdb` | `rdb-tool/examples/Relay710.rdb` from [AoufNihed/SEL_RDB](https://github.com/AoufNihed/SEL_RDB/blob/6234ad17201873db9e730b7ff4589661db228577/rdb-tool/examples/Relay710.rdb) (commit `6234ad1`) | MIT, Copyright (c) 2025 AOUF Nihed, Ateam Pro-tech. See [`LICENSE-SEL_RDB.txt`](LICENSE-SEL_RDB.txt). |
| `sel-710_rdb_streams/` | Streams extracted from `sel-710_Relay710.rdb` with `olefile`, unmodified. The GLE logic diagrams and other `Misc/` streams aren't included. | MIT (same as above) |
| `sel-710_SET_ALL.TXT` | Derived from `sel-710_rdb_streams/`: `Misc/Cfg.txt`, followed by each `set_*.txt` in `[CLASSES]` order with its `[INFO]` section and the `0x1C` line terminators removed. This matches the layout of a `SET_ALL.TXT` downloaded from a relay. | MIT (same as above) |

The SEL-710 database is a QuickSet template ("New Settings 2") for a motor relay. It includes three settings groups, logic, the front panel, reports, a Modbus map, and settings for Port 1 (Ethernet) and Ports 2-4 and F (serial). The FID's revision and date are masked (`SEL-710-Rxxx-Vx-Z008004-Dxxxxxxxx`).

## Searched, but not used

- [danyill/rdb-tool](https://github.com/danyill/rdb-tool) and [danyill/sel-settings-terminal](https://github.com/danyill/sel-settings-terminal) (GPLv3): no sample files.
- [GuilhermeMarini/sellib](https://github.com/GuilhermeMarini/sellib) and [GuilhermeMarini/pac-ct](https://github.com/GuilhermeMarini/pac-ct) (AGPLv3): no relay settings files. The `sellib` documentation was a useful reference for the RDB layout.
- [AoufNihed/SELConnect](https://github.com/AoufNihed/SELConnect): has a sample RDB, but no license, so all rights are reserved and it can't be redistributed.
- The "case study" `.txt` files in AoufNihed/SEL_RDB aren't in a SEL settings format.
- [jtreew/SELRelay_DataParser](https://github.com/jtreew/SELRelay_DataParser): no files and no license.
- Examples in SEL instruction manuals and application guides are copyrighted by SEL.
