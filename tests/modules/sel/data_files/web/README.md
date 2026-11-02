# SEL web page test data

Test data for parsing the web pages of SEL relays, RTACs, and the SEL-3620 (`tests/modules/sel/test_sel_http_relay_parse.py` and `tests/modules/sel/test_sel_web_parse.py`).

All files here are **synthetic**: they were written by hand for PEAT's tests and are not captures from a device. There are no public samples of these pages. Only the layout is modeled on real output, and every value is made up:

- IP addresses are from the documentation ranges (`192.0.2.0/24` and `198.51.100.0/24`, RFC 5737).
- MAC addresses use SEL's OUI (`00-30-A7`) with made-up device parts.
- Serial numbers, part numbers, CIDs, project IDs, hashes, user names, and host names are made up. Firmware IDs follow the documented `SEL-<model>-R<rev>-V<ver>-Z<settings>-D<date>` format, but aren't from a real device.

Please don't replace these with captures from real devices unless they are sanitized and can be shared. If you add real files, list their source and license here.

## Relay pages (`relay_*.html`)

Relay pages show the output of an ASCII command in a `<pre>` section. The command output is laid out like the examples of the same commands in public SEL instruction manuals, rewritten with other values:

| Files | Command | Layout modeled on |
| --- | --- | --- |
| `relay_451_ver.html`, `relay_311l_ver.html` | `VER` | SEL-421 Instruction Manual (date code 20130627), Reference Manual section 9 (ASCII Command Reference), VER command sample. The order of the sections is the one PEAT's original 451 parser expected, and the 311L file uses two-space indentation, as noted in PEAT's code. |
| `relay_351s_ver.html` | `VER` | SEL-351S Instruction Manual (date code 20171023), section 10 (Communications, Command Explanations), VER command example. |
| `relay_451_eth.html` | `ETH` | The lines PEAT's original 451 parser read (`MAC 1:`, `IP ADDRESS: <address>/<prefix>`, the port table, and the `$$$$$$$` counter overflow described in PEAT's code). |
| `relay_351s_eth.html` | `ETH` | SEL-351S Instruction Manual (date code 20171023), section 10, ETH command example (IP and GOOSE port groups). |
| `relay_451_sho_*.html` | `SHO P n`, `SHO F`, `SHO O` | Settings grouped under headings, separated by blank lines, as in the `SHO P 5` example in the SEL-421 Instruction Manual (date code 20130627), Applications Handbook. The setting names are documented settings, and the values are made up. |
| `relay_351s_shop*.html` | `SHO P n` | SEL-351S Instruction Manual (date code 20171023), section 10, `SHO P` examples. |
| `relay_451_met_*.html` | `MET AMV`, `MET PMV` | The `NAME = value` lines PEAT's original parser read. |
| `relay_351s_mete.html` | `MET E` | SEL-351S Instruction Manual (date code 20171023), section 10, MET E example. |

Some tests also use short inline strings modeled on the SEL-751A Instruction Manual (date code 20130329), section 7 (Communications), ETH and MAC commands.

## RTAC and SEL-3620 pages (`rtac_*`, `sel3620_*`)

These are HTML tables (and a CSV file) with the structure that PEAT's parsers read: the table cells, CSS classes, element IDs, link classes, and CSV column names used in `peat/modules/sel/sel_web_parse.py`. They are not copies of SEL's pages, which have more markup.

| File | Page |
| --- | --- |
| `rtac_device_info.html` | RTAC `device_info.sel` |
| `rtac_diagnostics.html` | RTAC `diagnostics.sel` / `diag_report.sel` |
| `rtac_post_summary.html` | RTAC `post_summary.sel` |
| `rtac_file_repository.html` | RTAC `file_repository.sel` |
| `rtac_user_table.html` | RTAC `user_table.sel` and SEL-3620 `Users.sel` |
| `rtac_soe.csv` | RTAC Sequence of Events log (`soe.csv`) |
| `sel3620_index.html` | SEL-3620 `index.sel` |
| `sel3620_syslog_report.html` | SEL-3620 `SysLogReport.sel` |
| `sel3620_x509.html` | SEL-3620 `X509.sel` |

The SEL-3620 certificate export tests use `tests/protocols/data_files/sel_3530_certificate.cert`.
