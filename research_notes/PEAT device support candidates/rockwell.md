# Rockwell Automation / Allen-Bradley candidates beyond ControlLogix (PEAT device-support research)

Scope note: PEAT baseline for comparison is the existing `peat/modules/rockwell` module (ControlLogix 1756 L7/L8 scan via UDP/TCP EtherNet/IP ListIdentity + CIP Get-Attributes-All, HTTP/SNMP/FTP pulls from EN2T/EWEB, CIP logic pull, firmware push, Studio 5000 .L5X parse) plus an in-repo CIP stack (`peat/protocols/cip`) and a PCCC-over-CIP stack (`peat/protocols/pccc`). PEAT's `pyproject.toml` pins `requires-python = ">=3.11,<3.14"` (local repo). PEAT's `clx_const.py` currently brands devices by hard-coded CIP product codes (ControlLogix: 58/95/115/125/164/166/200/258; MicroLogix: 90 and 185 with a comment that 90 "can also be 1794-AENT FLEX I/O"; PanelView: 183) and has `TODO` comments to replace this with EDS-file lookups (local repo: `peat/modules/rockwell/clx_const.py`, `ab_scan.py` line ~253).

Coordinator weighting applied throughout: the baseline for a new module is **PARSE + SCAN**. Each candidate section ends with an explicit "Parse achievable without hardware? / Scan achievable without hardware?" verdict, weighted by (1) redistributable sample vendor files and (2) a free, network-reachable simulator that answers on real TCP/UDP ports in CI.

Research caveat: the per-turn web-search budget was exhausted before every sub-question was covered; items marked "not searched" in Gaps are budget casualties, not negative findings. Several rockwellautomation.com product/advisory pages returned HTTP 403 to automated fetches; where that happened the finding relies on search-result snippets of the same page and is flagged.

---

## Key Question 1: Which open-source EtherNet/IP simulators are good enough to test CIP scan and tag/program upload in CI, and what are their licenses?

### Takeaway
Only two free, network-reachable targets exist that answer EtherNet/IP ListIdentity on port 44818 with a Rockwell-style Identity Object: **cpppo's `enip_server`** (Python, GPLv3/proprietary dual, configurable Identity) and **Conpot** (Docker image `honeynet/conpot`, wraps cpppo, ships a "1756-L61/B LOGIX5561" identity). Both emulate only unconnected Logix tag read/write — no connected messaging, no program upload, no PCCC — so they validate PEAT *scan/fingerprint* code but not *pull-logic* code. OpENer (adapter/target, C, BSD-style) is a credible third target for generic CIP identity/explicit-messaging tests but is not a Logix emulator. EIPScanner and libplctag are clients, not servers.

### Cited Findings
- cpppo provides "simulation of a subset of the Tag communications capability of a Allen-Bradley ControlLogix 5561 Controller" using Read/Write Tag [Fragmented] services; it answers broadcast List Identity; Identity Object values such as Product Name can be overridden via a `cpppo.cfg` `[Identity]` section; "Only EtherNet/IP 'Unconnected' type connections are supported" and "Cpppo does not implement 'Connected' requests"; run with `python -m cpppo.server.enip` or `enip_server --print SCADA=INT[1000] TEXT=SSTRING[100] FLOAT=REAL`; README claims testing on Python 2.6/2.7 and 3.3–3.5 only; repo shows GPL-3.0, 59 open issues, 391 stars — [cpppo GitHub](https://github.com/pjkundert/cpppo)
- cpppo latest PyPI release is 5.2.5 (Feb 18, 2025); classifiers list only "Python :: 2" and "Python :: 3" (no 3.10/3.11/3.12); license field: "GNU General Public License v3 or later (GPLv3+), Other/Proprietary License (Dual License; GPLv3 and Proprietary)" — [cpppo on PyPI](https://pypi.org/project/cpppo/)
- cpppo's API document table of contents lists GPLv3 terms for in-house vs external use plus "Commercial License" and "Fees" sections (actual commercial terms not retrieved) — [cpppo ENIP API PDF (third-party mirror)](https://30a394fe.dominionrnd-com.pages.dev/pdf/cpppo-enip-api.pdf)
- Conpot's default template defines an ENIP service with `VendorId = 1`, `DeviceType = 14`, `ProductCode = 90`, `ProductRevision = 2562`, `SerialNumber = "7079450"`, `ProductName = "1756-L61/B LOGIX5561"`, `port = 44818`, `mode = "tcp"`, `host = "0.0.0.0"`, and three tags (SCADA SINT @22/1/1, TEXT SSTRING @22/1/2, FLOAT REAL @22/1/3) — [conpot enip.toml](https://raw.githubusercontent.com/mushorg/conpot/master/conpot/templates/default/enip.toml)
- Conpot's default template directory contains `enip.toml`, `bacnet`, `ftp`, `http`, `ipmi`, `modbus`, `s7comm`, `snmp`, `tftp` entries and `template.toml` — [conpot templates/default](https://github.com/mushorg/conpot/tree/master/conpot/templates/default)
- Conpot's README docker-run example maps `-p 44818:44818` alongside Modbus/S7/BACnet/FTP ports; a pre-built `honeynet/conpot` image exists on Docker Hub; Conpot's Python dependencies include cpppo — [conpot GitHub README (quoted via mirror in search)](https://github.com/mushorg/conpot); mirror: [gitee.com/stackw0rm/conpot](https://gitee.com/stackw0rm/conpot)
- OpENer is "an EtherNet/IP stack for I/O adapter devices," supports "multiple I/O and explicit connections," targets POSIX (Linux primary; optional RT mode), Windows (Visual Studio, MinGW) and Cygwin; README is at version 2.3.0 with 1,358 commits; it includes a sample Dockerfile (Ubuntu 20.04), macvlan network notes and docker-compose "swarm" instructions; its fuzzing corpus includes `enip_req_list_identity` (command 0x63) — [OpENer GitHub](https://github.com/EIPStackGroup/OpENer)
- OpENer's original license text is the "SOFTWARE DISTRIBUTION LICENSE FOR THE ETHERNET/IP(TM) COMMUNICATION STACK (ADAPTED BSD STYLE LICENSE)," which permits incorporation into products for sale but explicitly does not grant ODVA's rights (implementing the spec / using the EtherNet/IP mark commercially needs an ODVA license) — [port GmbH wiki quoting the OpENer license](https://portgmbh.atlassian.net/wiki/x/CoCZDQ); a 2021 developer-list reply says a commercial product using OpENer still needs an ODVA license and vendor ID — [eip-stack-group-opener-developers thread](https://groups.google.com/g/eip-stack-group-opener-developers/c/5i1u4HxK234)
- EIPScanner is a "Free implementation of Ethernet/IP scanner in C++" (MIT), features explicit messaging, "Implicit messaging (only point-to-point)" and "Discovery," needs a C++20 compiler, runs on Linux/macOS/Windows; 262 commits, 24 open issues — [EIPScanner GitHub](https://github.com/nimbuscontrols/EIPScanner)
- libplctag is "a C library for Linux, Windows and macOS," dual-licensed MPL 2.0 / LGPL 2+, supporting ControlLogix, Micro 850, "PLC-5 PLCs (Ethernet upgraded to support Ethernet/IP), SLC 500 and MicroLogix with Ethernet via CIP," Omron NX/NJ and Modbus TCP; it is a client (read/write), "in production since early 2012," with minimal Python/C++/Pascal wrappers in-tree — [libplctag GitHub](https://github.com/libplctag/libplctag)
- pycomm3 tests "require a running PLC" (address via `PLCPATH` env var); no mock server is shipped; the tests directory contains an L5X export of the testing program — [pycomm3 GitHub](https://github.com/ottowayi/pycomm3)
- pylogix can connect to "RSEmulate" but "may require additional configuration"; it ships no server — [pylogix GitHub](https://github.com/dmroeder/pylogix)
- FactoryTalk Logix Echo: Rockwell offers "a 30-day license of FactoryTalk Logix Echo to experience the latest controller emulation software risk-free"; the trial "requires a feature-compatible Studio 5000 Logix Designer version"; Rockwell lists "Python support for FactoryTalk Logix Echo SDK" and "sample projects in C# and Python"; one license "can support the creation and communication of multiple chassis" (page fetch returned 403; facts from search snippets of the page) — [Rockwell blog: FactoryTalk Logix Echo 3.0](https://www.rockwellautomation.com/en-us/company/news/blogs/factorytalk-logix-echo-30.html); [Logix Echo product page](https://www.rockwellautomation.com/en-in/products/software/factorytalk/designsuite/logix-echo.html)
- Studio 5000 Logix Emulate: no official price or trial page was found; third-party blog claims (mutually inconsistent) include "Rockwell does not offer a trial or evaluation version of Emulate," a ~$3,000 USD price, and a subscription-only model; one blog says a Studio 5000 Pro license in active support is required to download it — [industrialmonitordirect: Studio 5000 Emulate licensing](https://industrialmonitordirect.com/blogs/knowledgebase/studio-5000-emulate-licensing-requirements-and-download); [industrialmonitordirect: RSLogix 5000 emulator trial alternatives](https://industrialmonitordirect.com/blogs/knowledgebase/rslogix-5000-emulator-trial-alternatives-and-options) (low-reliability sources)

### Inferences
- For PEAT's `broadcast_scan()` (UDP ListIdentity) and `fingerprint_device()`/Get-Attributes-All paths, cpppo's `enip_server` is the only Python-native, pip-installable target; it can be configured per-test with any Rockwell Product Name via `cpppo.cfg`, so one fixture can emulate CompactLogix/Micro800/PanelView identities for brand-detection tests. Caveat: cpppo's Vendor/Product Code/Device Type override capability was not confirmed beyond "Product Name" (see Gaps).
- Conpot's default ENIP identity is internally inconsistent for PEAT's heuristics: Product Code 90 is in PEAT's `MLX_PRODUCT_CODES` (MicroLogix 1400 / 1794-AENT) while the Product Name says "1756-L61/B LOGIX5561"; `get_brand(90)` would report "MicroLogix." This is a useful negative test and an argument for the EDS-based lookup PEAT already has as a TODO.
- Conpot's `mode = "tcp"` suggests UDP ListIdentity broadcast (PEAT's primary discovery path) may not be answered by the Docker image out-of-the-box; PEAT's TCP ListIdentity/unicast path would be the thing to test. Verify.
- cpppo's GPLv3 is license-compatible with PEAT (GPLv3) as a *test dependency*; its stale Python classifiers (no 3.11+) mean a CI smoke test on 3.11–3.13 is needed before relying on it. The Feb-2025 release suggests it is at least minimally maintained.
- OpENer is the right target for generic CIP conformance (Identity object, Get Attributes All, Forward Open) and runs in Docker, but its default identity is not a Rockwell product; whether its vendor/product code are build-time configurable was not confirmed.
- None of the free targets emulate: connected (Class 1/3 Forward-Open) Logix services used by Studio 5000 uploads, PCCC (MicroLogix/SLC), the Logix "Program/Routine object" enumeration PEAT uses for logic pull, or PanelView custom classes. Pull/push testing still needs Logix Echo (30-day, Windows, Studio 5000 dependency) or hardware.

### Gaps
- Whether cpppo's `[Identity]` override supports Vendor ID, Device Type, Product Code and Serial Number (not just Product Name) — README excerpt only showed Product Name; verify in `cpppo/server/enip/device.py`.
- cpppo's actual Python 3.11–3.13 compatibility (classifiers are generic).
- Whether OpENer's vendor ID / product code / product name are compile-time configurable (README silent).
- Logix Echo: emulated controller list (5580 vs 5380), SDK license, headless/CI operation, Docker support — product page 403'd and nothing on Docker was found in search.
- Logix Emulate official pricing/trial — only unreliable blogs found.
- Whether a Docker image of cpppo's `enip_server` with a *CompactLogix/Micro800* identity already exists publicly — not searched (budget).

---

## Key Question 2: Is MicroLogix/SLC program upload via PCCC publicly documented well enough to implement from the DF1 manual plus community code?

### Takeaway
The *data-file* side (N/B/F/T/C/S/etc.) is well documented and implemented in pycomm3's SLCDriver and libplctag (both over PCCC-in-CIP, which PEAT already has). The *program-file upload* side is only partially public: the public DF1 manual (1770-6.5.16, 1996) and Wireshark's CIP dissector enumerate the needed function codes (CMD 0x0F FNC 0x53 "Upload all request", 0x55 "Upload completed", 0x17 "Read bytes physical", 0xA2 "Protected typed logical read with three address fields", CMD 0x07 "Enter upload mode", and a "Ladder Logic File" PCCC file type), but **no open-source implementation of ladder upload was found**, and the ladder-instruction binary encoding (needed to decompile to PLCopen/ST) is not in any public manual found. Expect capture-driven reverse engineering.

### Cited Findings
- The DF1 Protocol and Command Set Reference Manual is publication 1770-6.5.16, dated October 1996, extending the 1991 Data Highway/DH-485 manual; the 1996 revision "added and updated" communication commands "organized alphabetically" (unofficial reposts found; Rockwell Literature Library is the authoritative host) — [manualsdir copy of 1770-6.5.16](https://www.manualsdir.com/manuals/579478/rockwell-automation-1770-d17706516-ref-mnl-df1-protocol-command.html); [manualmachine copy](https://manualmachine.com/rockwellautomation/1770/1709698-user-manual)
- Wireshark's CIP dissector (`packet-cip.c`) defines the PCCC class as `{ 0x67, "PCCC Class" }`, service "Execute PCCC," and function tables: CMD 0x06 (0x03 "Diagnostic status," 0x01 "Read diagnostic counters," ...); CMD 0x07 (0x04 "Enter download mode," 0x05 "Exit download/upload mode," 0x06 "Enter upload mode," 0x00/0x01 disable/enable outputs); CMD 0x0F (0x05 "Download request," 0x06 "Upload," 0x11 "Get edit resource," 0x12 "Return edit resource," 0x17 "Read bytes physical," 0x18 "Write bytes physical," 0x26 "Read-modify-write," 0x29 "Read section size," 0x3A "Set CPU mode," 0x50 "Download all request," 0x52 "Download completed," 0x53 "Upload all request (upload)," 0x55 "Upload completed," 0x67 "Typed write," 0x68 "Typed read," 0x80 "Change CPU mode," 0x81 "Open file," 0x82 "Close file," 0x88 "Execute Multiple Commands," 0xA1/0xA2 protected typed logical read with two/three address fields, 0xA7 "Protected typed file read," 0xA9/0xAA protected typed logical write, 0xAB masked-write, 0xAF "Protected typed file write"); PCCC file-type names include "Ladder Logic File," "Channel Configuration File," Output/Input/Status/Binary/Timer/Counter/Integer/Float data files, force files and function files — [Wireshark packet-cip.c](https://raw.githubusercontent.com/wireshark/wireshark/master/epan/dissectors/packet-cip.c)
- pycomm3's `SLCDriver` is "An Ethernet/IP Client driver for reading and writing of data files in SLC or MicroLogix PLCs"; `read(*addresses)` with multi-word syntax `N120:10{10}`; `write(*address_values)`; it "Does not track request/response size like the CLXDriver" — [pycomm3 SLCDriver API](https://pycomm3.readthedocs.io/en/latest/api_reference/slc_driver.html); the SLCDriver usage page is a literal "TODO" — [pycomm3 SLCDriver usage](https://pycomm3.readthedocs.io/en/latest/usage/slcdriver.html)
- pycomm3 README: SLCDriver provides "basic reading/writing data files in a SLC500 or MicroLogix PLCs," is "considered legacy and it's development will be on a limited basis," and "pycomm3 is no longer actively developed"; MIT; supported "on Python versions from 3.6.1 up to 3.10"; latest 1.2.16 released Dec 22, 2025 — [pycomm3 GitHub](https://github.com/ottowayi/pycomm3); [pycomm3 PyPI](https://pypi.org/project/pycomm3/)
- pylogix: "PLC5, SLC, MicroLogix are not supported" because "they use a different protocol, which I have no plans to support"; Apache 2.0; latest 1.1.6 released Sep 1, 2026 — [pylogix PyPI](https://pypi.org/project/pylogix/); [pylogix GitHub](https://github.com/dmroeder/pylogix)
- libplctag supports PLC-5/SLC 500/MicroLogix "with Ethernet via CIP" for 16-bit INT and 32-bit float read/write (arrays untested on SLC 500), 32-bit L-file on MicroLogix, single bits in B and N files, and DH+-bridged variants — [libplctag GitHub](https://github.com/libplctag/libplctag)
- Third-party knowledge-base posts about MicroLogix program upload over DF1 contradict each other on command/function codes (0x0F typed read with type 0xA1 vs 0x68/0x00 vs file type 0x0A) and on password unlock (CMD 0x09); none cite a primary source — [industrialmonitordirect: MicroLogix program download via DF1](https://industrialmonitordirect.com/blogs/knowledgebase/allen-bradley-micrologix-program-download-via-df1-protocol); [industrialmonitordirect: DF1 PCCC extended file type codes](https://industrialmonitordirect.com/ro/blogs/knowledgebase/df1-pccc-extended-file-type-codes-l-mg-pid-pls-ri-rix-on) (unreliable)
- A third-party post describes reading MicroLogix 1400 data-log (DLG) queues via a pycomm3 fork method `read_data_log_queue` (not in upstream pycomm3) — [industrialmonitordirect: MicroLogix 1400 DLG with pycomm3](https://industrialmonitordirect.com/blogs/knowledgebase/reading-micrologix-1400-dlg-data-logs-with-pycomm3-python) (unverified)
- CISA ICSA-22-354-04: MicroLogix 1100 (all versions) and 1400 A ≤7.000 / B,C ≤21.007 have an "unauthenticated stored cross-site scripting vulnerability in the embedded webserver" (CVE-2022-46670, payload delivered over SNMP, CVSS 7.1) and a web-server DoS (CVE-2022-3166, CVSS 7.5); mitigations include disabling the optional web server and upgrading to Micro800 — [CISA ICSA-22-354-04](https://www.cisa.gov/news-events/ics-advisories/icsa-22-354-04)
- Rockwell notice (SD1790 per search summary) on "restoring access to MicroLogix 1400 and 1100 controllers whose password is unknown" states Rockwell "has become aware of threat actor activity targeting internet-exposed PLCs, specifically Rockwell Automation/Allen-Bradley's MicroLogix 1400 & MicroLogix 1100 series" (date not visible in snippet) — [Rockwell security advisory (URL as returned by search)](https://www.rockwellautomation.com/en-au/trust-center/security-advisories/advisory.PN1010.html)
- Older MicroLogix CISA advisories: ICSA-16-224-01 (SNMP credentials, 2016; metadata updated 2025-06-09), ICSA-17-115-04, ICSA-18-009-01 (1400 B/C), ICSA-19-113-01, ICSA-20-070-06, ICSA-21-145-02 (Micro800 & MicroLogix 1400, May 2021) — [ICSA-16-224-01](https://vulners.com/ics/ICSA-16-224-01); [ICSA-18-009-01](https://www.cisa.gov/ics/advisories/ICSA-18-009-01); [ICSA-21-145-02](https://vulnerability.circl.lu/vuln/icsa-21-145-02); [ICSA-17-115-04](https://vulners.com/ics/ICSA-17-115-04); [ICSA-20-070-06](https://vulners.com/ics/ICSA-20-070-06)
- Lifecycle: Rockwell product pages list MicroLogix 1400 catalog numbers (1766-L32BWA, -L32BWAA, -L32BXB) as "Active Mature" — [1766-L32BWA](https://www.rockwellautomation.com/en-us/products/details.1766-L32BWA.html); [1766-L32BXB](https://www.rockwellautomation.com/en-us/products/details.1766-l32bxb.html); a Rockwell-distributor TechTalk deck gives MicroLogix 1200 "Discontinued date: 28 February 2021" and MicroLogix 1000 discontinued since July 2017 — [TRC TechTalk MicroLogix migrations (PDF)](https://res.cloudinary.com/mcrey/image/upload/v1622139874/trc/documents/TechTalks/TRC-TechTalk-MicroLogix-Controllers-Migrations_hglhce.pdf)
- RSLogix Micro Starter Lite (free): "the software was discontinued around 2017, yet support still exists. As of this writing (Nov 2024), the software is available from Rockwell's Compatibility/Download Center for account holders" — [control.com tutorial](https://control.com/technical-articles/tutorial-rslogix-for-slc-and-micrologix-plcs/); multiple blogs say the free Lite edition supports only MicroLogix 1000/1100 and not the 1400 — [industrialmonitordirect: Starter Lite download](https://industrialmonitordirect.com/blogs/knowledgebase/rslogix-micro-starter-lite-download-and-installation-guide) (secondary)
- RSLogix 500 `.RSS` is a proprietary, unpublished format; third-party pages disagree on whether it is a flat binary or an OLE2/CFBF compound file; no reverse-engineering write-up or open-source reader was found — [industrialmonitordirect: .rss vs .rsp](https://industrialmonitordirect.com/blogs/knowledgebase/rslogix-rss-vs-rsp-file-differences-and-compatibility); [industrialmonitordirect: RSS comparison methods](https://industrialmonitordirect.com/blogs/knowledgebase/rslogix-500-rss-file-comparison-native-tool-optimization-and-alternative-methods) (secondary, conflicting)

### Inferences
- PEAT's existing `peat/protocols/pccc` (PCCC-over-CIP, class 0x67) plus the unintegrated MicroLogix 1100 script already cover the transport. Implementing data-file reads (S: status file for processor type/firmware/mode/fault, I/O config via channel-configuration file, N/B/F/T/C data) is **small effort** and fully specified by the DF1 manual + Wireshark tables + pycomm3 as reference code.
- Program/ladder upload is **medium-to-large effort**: the function codes exist publicly (0x07/0x06 enter upload mode, 0x0F/0x53 upload-all, 0x0F/0x17 read bytes physical, 0x0F/0x55 upload completed), but the "Ladder Logic File" record format and instruction opcodes needed to render logic are undocumented publicly; the only practical route is capturing RSLogix 500 (paid; or free Starter Lite for ML1000/1100) uploads with Wireshark and reverse-engineering, which also implicates the Rockwell EULA (see Key Question 4).
- `.RSS` parsing is not a realistic parse-only module: no public spec, no open-source reader, and sample `.RSS` files are themselves scarce/redistribution-unclear. If the file is CFBF, Python `olefile` could at least enumerate streams — unverified.
- No free MicroLogix/SLC *emulator* exists (RSLogix Emulate 500 availability unconfirmed; it would be Windows-only and would not expose PCCC on 44818 without RSLinx anyway). Therefore **scan** of MicroLogix in CI can only be tested against a generic identity emulator (cpppo with Product Code 90/185 + "1766-L32BWA" style Product Name), not against a PCCC-speaking target.

### Gaps
- No primary-source confirmation of the exact byte layout of PCCC upload-all responses or of the Ladder Logic File encoding (not in any public document found).
- Rockwell Literature Library URL for 1770-6.5.16 not retrieved (only unofficial copies surfaced).
- RSLogix Emulate 500 current availability/licensing — nothing authoritative found.
- SLC 500 and PLC-5 CISA advisories and official lifecycle status — not searched (budget).
- MicroLogix 1100 official lifecycle status — Rockwell product page returned 403.
- Whether PEAT's unintegrated ML1100 script already does S-file reads — not checked (private, not in repo).

---

## Key Question 3: Which Rockwell project/export formats are open XML/text?

### Takeaway
Open text formats confirmed: Studio 5000 **L5X** (baseline), FactoryTalk View **display XML exports** and **tag CSV exports** (per Rockwell help), **EDS** files (ASCII), and Stratix **Cisco IOS running-config** text. Proprietary binary: **.ACD** (archive with compressed XML plus binary databases; parsed by `acd-tools`), **.RSS** (RSLogix 500), **.mer** (compiled HMI runtime), **.apa** (archive; zip-vs-proprietary unconfirmed), **.vpd/.vpdr** (PanelView 5000; format not documented). CCW's **.ccwsln/.ccwarc** structure was not confirmed from a primary source, but Rockwell's own XXE CVE in CCW ≤12 and an "XML error" troubleshooting post indicate the project is XML-based.

### Cited Findings
- FactoryTalk View ME "Graphics Import Export Wizard" "generates complete graphic displays from an XML text file, or exports complete graphic displays to an XML file"; opened by right-clicking Displays > Import and Export; strings export in the application's current language only — [Rockwell FactoryTalk View 16 help: Graphics Import Export Wizard](https://www.rockwellautomation.com/en-us/docs/factorytalk-view/16-00-00/me-help-ditamap/about-graphic-displays/graphics-import-export-wizard.html)
- FactoryTalk View "Tag Import and Export Wizard" imports/exports tag CSV files (for Machine Edition "only tag data can be imported"); a separate "Tag CSV file format" help topic exists — [Rockwell FactoryTalk View 16 help: Import tag CSV files](https://www.rockwellautomation.com/en-us/docs/factorytalk-view/16-00-00/tools-help-ditamap/tag-import-and-export-wizard/import-tag-csv-files.html); [tools help index](https://www.rockwellautomation.com/en-us/docs/factorytalk-view/16-00-00/tools-help-ditamap.html)
- Third-party sources (one vendor KB site) describe `.mer` as the compiled PanelView Plus runtime and `.apa` as the editable archive, but conflict on whether `.apa` is a zip bundle or proprietary and whether `.mer` can be converted back — [industrialmonitordirect: APA vs MER](https://industrialmonitordirect.com/blogs/knowledgebase/factorytalk-view-apa-vs-mer-files-complete-comparison); [plctalk thread on APA/MER to SE](https://www.plctalk.net/threads/how-to-convert-a-pvp-apa-or-mer-file-into-a-view-se-project.126913/) (secondary, conflicting)
- Studio 5000 View Designer (PanelView 5000) projects "are stored in files with a .vpd extension"; a project holds screens, controller references, target HMI device info; a "Runtime Application VPDR file" is saved for transfer to the terminal; a controller reference links the .vpd to a Logix Designer .acd — [Rockwell View Designer help: create a project](https://www.rockwellautomation.com/en-us/docs/studio-5000-view-designer/10-00/studio-5000-view-designer-help-ditamap/-st5k--view-designer-help/create-a-project/create-a-project-for-a--v5ks-.html); [View Designer overview](https://www.rockwellautomation.com/en-us/docs/studio-5000-view-designer/10-00/studio-5000-view-designer-help-ditamap/-st5k--view-designer-help/-vd-.html)
- `.ACD` "is an archive file that contains all the files used by RSLogix / Studio 5000 Logix Designer," containing "version text files, compressed XML metadata, and several proprietary binary database files" (Comps.Dat, SbRegion.Dat, Comments.Dat, Nameless.Dat); `acd-tools` (Apache-2.0) parses tags, programs, ladder rungs, UDTs, AOIs and hardware modules and can "serialise the parsed project back to an L5X XML file"; "Tested against Studio 5000 firmware versions 15–35"; hardware module metadata "not fully round-tripped because Rockwell stores those as opaque CIP identity records"; parsers are generated from Kaitai Struct templates at install time; Python 3.8+ (3.12+ recommended) — [hutcheb/acd GitHub](https://github.com/hutcheb/acd)
- `acd-tools` latest is 0.3a2 (Sep 13, 2026), classified "3 - Alpha"/pre-release; API `ConvertAcdToL5x("MyController.ACD", "MyController.L5X").extract()` — [acd-tools PyPI](https://pypi.org/project/acd-tools/)
- A second PyPI package, `plc-format-converter`, advertises "bidirectional ACD ↔ L5X conversion with validation" (quality/maintenance unverified) — [plc-format-converter PyPI](https://pypi.org/project/plc-format-converter/)
- Rockwell's Library Object Manager can "Export ACD to L5X" but requires the ACD be opened in a matching-or-newer Studio 5000 — [Rockwell Application Code Manager help](https://www.rockwellautomation.com/en-fi/docs/studio-5000-application-code-manager/5-01/library-object-manager-help-ditamap/library-object-manager-overview/library-repositories-overview/add-and-mount-an-acd-repository/export-acd-to-l5x.html)
- A third-party package index listing describes a "Logix Designer SDK" Python wheel that "ships with your own licensed Studio 5000 v36+ install," "cannot be redistributed," Windows + Python 3.12 only (not confirmed from Rockwell) — [pi.dev listing](https://pi.dev/packages/sylo-allen-bradley?page=61) (unverified)
- CCW: Rockwell's getting-started guide covers File > Save Project As; a third-party post says the CCW project file is ".acproj XML UTF-8 encoded, no BOM" and project folders contain `.acproj`, `.acslib`, `.hmi`; a Rockwell-hosted feature summary says you can "Import or Export the entire project including archives, as a CCWARC file type" — [Micro800 quick start 2080-QR001 (mirror)](https://www.engr.siu.edu/staff/spezia/NewWeb438B/labs/2080-qr001_-en-p.pdf); [industrialmonitordirect: CCW 8.0 XML error](https://industrialmonitordirect.com/blogs/knowledgebase/ccw-80-cannot-open-ccw-70-project-xml-error-fix) (secondary)
- CVE-2022-1018: "XML external entity" information-disclosure vulnerability in Connected Components Workbench "version 12.00 and below," fixed in 13.00 — [wiz.io CVE-2022-1018](https://www.wiz.io/vulnerability-database/cve/cve-2022-1018)
- Stratix 5900 user manual documents Cisco IOS privileged-EXEC commands to show the running configuration and the startup configuration in NVRAM — [1783-SR Stratix 5900 user manual p.72 (manualsdir)](https://manualsdir.com/manuals/579957/rockwell-automation-1783-sr-stratix-5900-services-router-user-manual.html?page=72); FactoryTalk Design Studio can "export a Stratix device configuration to a computer for backup" producing one or two files — [Rockwell FactoryTalk Design Studio help](https://www.rockwellautomation.com/en-ie/docs/factorytalk-design-studio/current/contents-ditamap/using-the-software/manage-devices/export-stratix-device-configuration.html)
- `ciscoconfparse2` (successor to ciscoconfparse) parses IOS-style configs for multiple vendors, requires Python 3.7+, is GPLv3 (author "will not release it under any other license"; commercial options offered) — [ciscoconfparse2 PyPI](https://pypi.org/project/ciscoconfparse2)
- EDS files are "used with network configuration tools to identify and commission products" and are distributed via Rockwell's Product Compatibility and Download Center (PCDC) or EPS library — [Rockwell product downloads](https://www.rockwellautomation.com/en-us/support/product/product-downloads); [PCDC EDS search](https://compatibility.rockwellautomation.com/pages/search.aspx?crumb=117&q=EDS%20files); third-party posts disagree on the EDS filename convention (vendor/type/code/revision hex fields) and one notes tools match devices by Identity Object values, not filename — [industrialmonitordirect: EDS naming](https://industrialmonitordirect.com/blogs/knowledgebase/eds-file-identity-naming-convention-for-allen-bradley-devices) (secondary)

### Inferences
- An XXE vulnerability in CCW implies CCW parses XML from project files, corroborating the secondary claim that CCW projects (`.acproj`, inside `.ccwsln` solutions) are XML. A `.ccwarc` is likely a container of that XML (zip is plausible but unconfirmed). A CCW parse module is therefore *probably* tractable, but a sample file must be inspected first — CCW Standard is free, so generating one is zero-cost but Windows-only.
- FactoryTalk View ME display XML + tag CSV are the cleanest HMI parse targets (open text, Rockwell-documented). The runtime `.mer` is a compiled artifact and should be treated as opaque; `.apa` worth a quick `zipfile`/`olefile` probe.
- `.ACD` parsing is feasible via `acd-tools` (Apache-2.0, pip-installable, Python 3.12+ recommended which fits PEAT's 3.11–3.13), but it is alpha-grade, Kaitai-generated at install time (CI must install `kaitaistruct`), and depends on reverse-engineered proprietary databases; the pragmatic design is "convert ACD → L5X with acd-tools, then reuse PEAT's existing L5X parser," isolating PEAT from the ACD internals.
- Stratix config parsing can reuse Cisco IOS tooling (ciscoconfparse2, GPLv3-compatible with PEAT). PEAT has no existing Cisco module (local `peat/modules` has fortinet but no cisco), so a Stratix parser is effectively a generic Cisco IOS config parser with Rockwell-specific identification (hostname/`show version` "Stratix" strings, CIP/SNMP sysDescr).

### Gaps
- Primary-source confirmation of `.ccwsln`/`.ccwarc`/`.acproj` structure (zip? XML schema?) — searches not completed (budget); no Rockwell document found.
- `.apa` internal format (zip vs OLE) — only conflicting secondary sources.
- `.vpd`/`.vpdr` internal format — Rockwell help describes purpose only.
- FactoryTalk View ME alarm/parameter/message-library export formats beyond displays (XML) and tags (CSV) — one secondary source says CSV/Excel; not confirmed in Rockwell help pages retrieved.
- Python EDS parsers on PyPI/GitHub — not searched (budget). EDS redistribution terms from PCDC — not found.

---

## Key Question 4: Where can free sample project/config/log files be obtained legally for test fixtures?

### Takeaway
No Rockwell-hosted sample is confirmed redistributable: the Sample Code Library is login-gated and shows a per-download license agreement whose text could not be retrieved. The only confirmed *redistributable* Rockwell-format fixtures found are in open-source repos: pycomm3's test L5X (MIT) and acd-tools' test assets (Apache-2.0; presence of .ACD fixtures unverified). Self-generated fixtures are free for L5X/ACD (Studio 5000 is paid — but acd-tools' tests imply ACDs exist), CCW projects (CCW Standard is free), FactoryTalk View XML/CSV (View Studio is paid), and Stratix configs (any Cisco IOS config is representative). Rockwell's EULA prohibits reverse engineering of its *software*; parsing files you create with it is a different act, but capture-based reverse-engineering of protocols/formats should be reviewed by counsel.

### Cited Findings
- Rockwell's Sample Code Library lets users "share or download logic, HMI, and drives code"; questions go to RASampleCode@ra.rockwell.com — [Rockwell Sample Code overview](https://www.rockwellautomation.com/global/sample-code/overview.page); [Sample Code help page](https://www.rockwellautomation.com/en-be/support/product/product-downloads/application-code-library/sample-code/help.html) (en-us help page returned 403 to automated fetch)
- When downloading a sample, "you'll be prompted to accept a license agreement. Once you do, you'll be prompted to download a zip file" — [The Automation Blog: Rockwell's Sample Code Library](https://theautomationblog.com/?p=3615)
- A third-party guide notes some samples are Rockwell-authored and others user-uploaded, so "license terms may vary by sample" — [industrialmonitordirect: Sample Code access guide](https://industrialmonitordirect.com/blogs/knowledgebase/rockwell-automation-sample-code-repository-access-guide) (secondary)
- pycomm3's `tests` directory "contains an L5X export of a testing program" (repo is MIT) — [pycomm3 GitHub](https://github.com/ottowayi/pycomm3)
- CCW "free Standard Edition is available from the Product Compatibility and Download Center (PCDC), rok.auto/pcdc" and includes a "demo version of Micro800 Simulator" that "requires no activation"; Developer Edition adds the "full version of Micro800 Simulator and Archive Manager" and "Requires activation" (price not stated) — [Rockwell store: 9328C-CCW](https://commerce.rockwellautomation.com/rockwell/en/USD/p/9328C-CCW/bundleBrand)
- Rockwell EULA (Rev 02/2016 copy): "You may not reverse assemble, reverse engineer, decompile, translate or create derivative works" — [Scribd copy of Rockwell EULA](https://www.scribd.com/document/457220554/License) (unofficial copy); Rockwell says the EULA is installed as `C:\Program Files (x86)\Common Files\Rockwell\license.rtf` — [Rockwell View Designer Legal Notices](https://www.rockwellautomation.com/en-be/docs/studio-5000-view-designer/10-00/studio-5000-view-designer-help-ditamap/legal-notices.html)
- RSLogix Micro Starter Lite remains downloadable from PCDC "for account holders" (Nov 2024) — [control.com](https://control.com/technical-articles/tutorial-rslogix-for-slc-and-micrologix-plcs/)
- EDS files are distributed through PCDC — [Rockwell product downloads](https://www.rockwellautomation.com/en-us/support/product/product-downloads)

### Inferences
- The safest fixture strategy is (a) reuse MIT/Apache test files already published by pycomm3/acd-tools, (b) generate PEAT's own fixtures with free tools (CCW Standard for `.ccwsln/.ccwarc`; cpppo/Conpot for pcap fixtures), and (c) hand-write minimal FactoryTalk View display XML / tag CSV from Rockwell's documented formats. Downloads from the Sample Code Library should be treated as *non-redistributable* unless the per-download agreement says otherwise.
- PCDC (firmware, EDS, CCW, Starter Lite) requires a free Rockwell account; nothing found indicates a paid TechConnect contract is required for these specific downloads, but firmware-kit entitlement rules were not verified.

### Gaps
- Actual text of the Sample Code Library download license — page 403'd; needs manual retrieval by a human with an account.
- Whether acd-tools' repo contains sample `.ACD` files under Apache-2.0 — not verified.
- Whether PCDC firmware downloads (e.g., CompactLogix 5069) require TechConnect — not searched (budget).
- EDS redistribution terms — not found.

---

## Candidate: CompactLogix / GuardLogix / Compact GuardLogix (5370, 5380, 5480)

### Takeaway
Same Logix 5000 object model and the same 1756-PM020 data-access contract as ControlLogix; pycomm3 and pylogix treat CompactLogix identically to ControlLogix, and the L5X schema is shared. PEAT's existing module very likely works with product-code/chassis-enumeration tweaks. **Parse: yes (reuse L5X parser; fixtures = any CompactLogix L5X). Scan: yes via cpppo/Conpot with CompactLogix identity values. Pull/push: untestable without Logix Echo (30-day trial, Windows) or hardware.** Effort: small.

### Cited Findings
- A Rockwell reference manual states "any user or third-party developer of communications software to a ControlLogix or CompactLogix controller must fully follow the Logix 5000 Data Access Programming Manual, 1756-PM020" — [Logix 5000 reference manual (manualmachine mirror)](https://manualmachine.com/rockwellautomation/controllogix/17911447-reference-manual); 1756-PM020 (2009 rev A copy) — [Scribd copy](https://www.scribd.com/document/266813749/LOGIX5000-Data-Access)
- "Beginning with Logix controller families 5380 and 5580, the full implementation and enforcement of the CIP specification standard for ANSI Extended Symbolic 0x91 is required"; older families still accept the legacy 0x61 format (search-result snippet; exact Rockwell page not isolated — treat as needs-verification) — [Rockwell Logix Designer docs (module information)](https://rockwellautomation.com/en-ie/docs/studio-5000-logix-designer/37-00/contents-ditamap/module-information/cip-security-session-error--0x0915-unknown-psk-ide.html)
- pycomm3 LogixDriver targets "ControlLogix, CompactLogix, and Micro800 PLCs" — [pycomm3 GitHub](https://github.com/ottowayi/pycomm3); pylogix targets "ControlLogix, CompactLogix, and Micro8xx PLCs" — [pylogix PyPI](https://pypi.org/project/pylogix/)
- Rockwell SD1693 / CVE-2024-6077: DoS via "specially crafted packets sent to the CIP Security Object" leaving the device unavailable until factory reset; affects CompactLogix 5380 (from v32.011), Compact GuardLogix 5380 SIL 2/SIL 3, CompactLogix 5380 Process; fixed in v33.017, v34.014, v35.013, v36.011+; Rockwell CVSS 3.1 7.4 / 4.0 8.3 (CVE record shows 8.7); mitigation: disable CIP Security per device — [Rockwell SD1693](https://www.rockwellautomation.com/en-us/trust-center/security-advisories/advisory.SD1693.html); [CVE-2024-6077 summary](https://secalerts.co/vulnerability/CVE-2024-6077)
- Logix Echo 30-day trial requires a feature-compatible Studio 5000 — [Rockwell Logix Echo 3.0 blog](https://www.rockwellautomation.com/en-us/company/news/blogs/factorytalk-logix-echo-30.html)

### Inferences
- CompactLogix 5370 (1769-L3x) has no separate backplane-chassis enumeration like 1756; 5380/5480 (5069-) use a different slot/path model and dual-IP/DLR ports — PEAT's `chassis_size=8` enumeration (`ab_scan.py`) will need a per-family path strategy. Not source-confirmed; derive from 5069-UM001 (not retrieved).
- The 0x91 symbolic-segment enforcement on 5380/5580 matters for PEAT's logic pull only if PEAT uses legacy 0x61 segments; worth a code check.
- Identity-based brand detection must be extended with 1769/5069 product codes; the right fix is the EDS lookup already noted as TODO.

### Gaps
- CompactLogix/GuardLogix product-code tables — not found publicly (EDS files on PCDC would supply them; login required).
- 5069-UM001 module-enumeration specifics — not retrieved.
- Logix Echo emulated controller list (5380 vs 5580 only) — 403.
- Firmware kit download entitlement on PCDC — not searched.

---

## Candidate: MicroLogix 1100/1400, SLC 500, PLC-5 (PCCC)

### Takeaway
High security relevance (long CISA history, threat-actor targeting of internet-exposed 1100/1400, embedded HTTP+SNMP) and PEAT already has PCCC-over-CIP plus a ML1100 script. **Scan: yes** — ListIdentity works (MicroLogix answers CIP identity; PEAT already keys codes 90/185) and can be CI-tested with cpppo configured to those identities; MicroLogix's HTTP/SNMP surfaces can also be mocked generically. **Parse: no realistic path** — `.RSS` is proprietary/undocumented with no open reader, and no redistributable `.RSS` fixtures were found. **Pull (data files, S: status, I/O config): small effort, well documented; pull (ladder): medium–large, undocumented encoding.** No free emulator. SLC 500/PLC-5 share PCCC but are end-of-life/obsolescent and were not fully researched.

### Cited Findings
- See Key Question 2 for: DF1 manual (1770-6.5.16), Wireshark PCCC function/file-type tables, pycomm3 SLCDriver (legacy, read/write only), libplctag PCCC support, pylogix non-support, ICSA-22-354-04, threat-actor notice, lifecycle ("Active Mature" 1400; 1200 discontinued 2021; 1000 discontinued 2017), RSLogix Micro Starter Lite (discontinued ~2017 but still on PCDC for ML1000/1100), `.RSS` opacity.
- PEAT's constants already map product code 185 to MicroLogix 1100 and 90 to MicroLogix 1400 (with the 1794-AENT ambiguity note) — local repo `peat/modules/rockwell/clx_const.py`.

### Inferences
- A MicroLogix module reusing `peat/protocols/pccc` for S-file reads (processor type, OS/firmware series & revision, mode, fault code, node address), channel-configuration reads (IP/port config), and data-file dumps would deliver identity/firmware/network/config "pull" with **small** effort and no new protocol work. Logic (ladder) pull would require capture-driven RE.
- Because no free PCCC-speaking emulator exists, pull tests must use recorded pcap/response fixtures (PEAT can capture from the maintainer's ML1100 once and replay).
- A parse-only module is not viable; this candidate is **scan + pull**, not scan + parse — a weakness under the coordinator's weighting.

### Gaps
- SLC 5/05 and PLC-5E CISA advisories, EOL dates (PLC-5 "Discontinued" claim is blog-only) — not verified.
- RSLogix Emulate 500 — availability unknown.
- Whether `.RSS` is CFBF — unverified; a quick `olefile` probe on a real file would settle it.

---

## Candidate: Micro800 (Micro820/850/870) + Connected Components Workbench (CCW)

### Takeaway
Strongest "free tooling" story in the Rockwell portfolio: CCW Standard is free, includes a (time-limited demo) Micro800 Simulator, and the project format is XML-based (CCW had an XXE CVE). Micro800 speaks Logix-style symbolic CIP (supported by pycomm3/pylogix/libplctag with a "no slot path" flag), and the family has a fresh, critical CISA advisory (CVSS 9.8/9.3, Aug 2025). **Parse: likely yes**, but only after inspecting a self-generated `.ccwsln/.ccwarc` (no primary spec, no redistributable samples found; CCW is Windows-only so fixtures must be generated once and committed). **Scan: yes** — CIP identity via cpppo/Conpot with Micro8xx identity; the real Micro800 Simulator is Windows-only and its EtherNet/IP exposure on the host NIC is unconfirmed, so it is not a Linux-CI target. Effort: medium (parse) + small (scan).

### Cited Findings
- CCW Standard Edition is free from PCDC with a "demo version of Micro800 Simulator" needing no activation; Developer Edition has the "full version of Micro800 Simulator and Archive Manager" and requires activation — [Rockwell store 9328C-CCW](https://commerce.rockwellautomation.com/rockwell/en/USD/p/9328C-CCW/bundleBrand)
- The Micro800 Simulator "comes with CCW 12"; the simulated controller is "2080-LC50-48QWB-SIM"; a reader comment: "The Micro800 Simulator only simulated the Micro850"; another comment references steps on why "RSLinx Classic might not see your Micro850 Sim" (paywalled) — [The Automation Blog: How to use the Micro800 Simulator](https://theautomationblog.com/how-to-use-the-micro800-simulator/)
- A user report says that in the free version "after 10 minutes in Run, the simulator will switch back to program" — [The Automation Blog Micro800 category (Q&A)](https://theautomationblog.com/category/micro800/page/3/) (forum-level evidence)
- One secondary post claims the free edition has no offline simulation at all — contradicted by Rockwell's own store listing — [industrialmonitordirect: CCW offline simulation](https://industrialmonitordirect.com/blogs/knowledgebase/ccw-offline-simulation-not-available-in-micro800-workbench)
- pylogix: "If you are working with a Micro8xx PLC, you must set the Micro800 flag since the path is different" (`comm.Micro800 = True`) — [pylogix GitHub](https://github.com/dmroeder/pylogix); libplctag supports "Micro 850 PLCs" "as for ControlLogix where possible" — [libplctag GitHub](https://github.com/libplctag/libplctag); pycomm3 LogixDriver includes Micro800 — [pycomm3 GitHub](https://github.com/ottowayi/pycomm3)
- CISA ICSA-25-226-25 (Aug 14, 2025): Micro820 LC20 <V14.011, Micro850 LC50 / Micro870 LC70 <V12.013, Micro850 L50E / Micro870 L70E V20.011–V22.011; CVE-2023-48691/-48692/-48693 (Azure RTOS NetX Duo / ThreadX, CVSS v3 9.8, v4 9.3) and CVE-2025-7693 (CWE-20, "Improper handling of malformed CIP packets" — malformed CIP Forward Close puts the controller in a solid-red Fault LED state, recoverable fault 0xF015); mitigation is migration to L-series at V23.011+; sectors: Chemical, Critical Manufacturing, Energy, Food and Agriculture, Transportation Systems, Water and Wastewater; no known exploitation — [CISA ICSA-25-226-25](https://www.cisa.gov/news-events/ics-advisories/icsa-25-226-25)
- CISA ICSA-25-352-07 (Dec 18, 2025) covers Micro820/850/870 (details not retrieved) — [GCVE mirror of ICSA-25-352-07](https://db.gcve.eu/vuln/icsa-25-352-07); ICSA-21-145-02 (May 2021) covered Micro800 and MicroLogix 1400 — [ICSA-21-145-02](https://vulnerability.circl.lu/vuln/icsa-21-145-02)
- CCW software CVEs: CVE-2022-1018 XXE (≤12.00) — [wiz.io](https://www.wiz.io/vulnerability-database/cve/cve-2022-1018); PN1648 CefSharp issues fixed in CCW R21 (several underlying CVEs in CISA KEV) — [Rockwell PN1648](https://www.rockwellautomation.com/en-au/trust-center/security-advisories/advisory.PN1648%20%20%20%20%20%20%20%20%20%20%20.html); ICSA-17-047-01 DLL hijacking fixed in 10.00/10.01 — [CISA ICSA-17-047-01](https://cisa.gov/ics/advisories/ICSA-17-047-01)
- CCW project-file claims (secondary): `.acproj` is XML (UTF-8); folders hold `.acproj`, `.acslib`, `.hmi`; whole-project export is `.ccwarc` — [industrialmonitordirect: CCW 8.0 XML error](https://industrialmonitordirect.com/blogs/knowledgebase/ccw-80-cannot-open-ccw-70-project-xml-error-fix); [2080-QR001 quick start](https://www.engr.siu.edu/staff/spezia/NewWeb438B/labs/2080-qr001_-en-p.pdf)

### Inferences
- Micro800 CIP access needs no backplane path and Micro800 does not expose the 1756-style module tree, so PEAT's `chassis_size` enumeration should be skipped for this family; tag/program enumeration via the Logix symbol/template objects may partially work (pycomm3's tag-list support for Micro800 is implied by LogixDriver support but not confirmed).
- Micro800 stores the CCW project in the controller when "download with project" is used; whether PEAT could *pull* the project source over CIP is unknown (not researched). Treat pull as "data tags + identity" only for now.
- The CCW XXE CVE and the "XML error" symptoms strongly indicate XML project internals; a PEAT parser mapping CCW IEC 61131-3 ST/LD/FBD programs into PLCopen TC6 is plausible once the schema is seen. Because the 10-minute demo simulator still runs the full IDE, generating fixtures is free.
- Micro800 is the only Rockwell small-PLC family with a *free* vendor simulator, but Windows-only and GUI-driven; for Linux/macOS CI the identity must be emulated with cpppo.

### Gaps
- Primary confirmation of `.ccwsln`/`.ccwarc`/`.acproj` structure — not obtained (search budget exhausted).
- Whether the Micro800 Simulator answers EtherNet/IP ListIdentity on the host NIC (vs. a loopback/RSLinx-only driver) — paywalled article; unknown.
- Micro800 project upload-from-controller over CIP (2080-UM002) — not searched.
- ICSA-25-352-07 contents — not retrieved.

---

## Candidate: PanelView Plus / PanelView 5000 HMIs and FactoryTalk View ME/SE

### Takeaway
Security-relevant (2023 unauthenticated RCE on PanelView Plus via FactoryTalk View ME, 2024 remote-restart DoS) and PEAT already detects one PanelView product code. **Parse: yes for FactoryTalk View ME display XML and tag CSV exports (Rockwell-documented text formats); no for `.mer` (compiled) and unclear for `.apa`; no for PanelView 5000 `.vpd`.** **Scan: yes** — PanelView Plus answers CIP ListIdentity (PEAT already saw this) and can be emulated with cpppo identity values; its HTTP surface can be mocked generically. No free runtime/emulator found; FactoryTalk View Studio is paid, so XML/CSV fixtures must be hand-authored or obtained from the (non-redistributable) Sample Code Library. Effort: small (scan) + medium (ME XML/CSV parse).

### Cited Findings
- Graphics Import Export Wizard exports/imports complete displays as XML; Tag Import/Export Wizard uses CSV — [Rockwell help: Graphics Import Export Wizard](https://www.rockwellautomation.com/en-us/docs/factorytalk-view/16-00-00/me-help-ditamap/about-graphic-displays/graphics-import-export-wizard.html); [Rockwell help: tag CSV import](https://www.rockwellautomation.com/en-us/docs/factorytalk-view/16-00-00/tools-help-ditamap/tag-import-and-export-wizard/import-tag-csv-files.html)
- `.vpd` project / `.vpdr` runtime for PanelView 5000; controller reference to `.acd` — [Rockwell View Designer help](https://www.rockwellautomation.com/en-us/docs/studio-5000-view-designer/10-00/studio-5000-view-designer-help-ditamap/-st5k--view-designer-help/create-a-project/create-a-project-for-a--v5ks-.html)
- CVE-2024-21914 / Rockwell SD1663 / CISA ICSA-24-086-04: remote attacker can "restart the PanelView Plus 7 terminal without security protections," possibly causing "loss of view or control"; CVSS 3.1 5.3, 4.0 6.9; CWE-400; not in KEV — [Rockwell SD1663](https://www.rockwellautomation.com/en-us/trust-center/security-advisories/advisory.SD1663.html); [NVD CVE-2024-21914](https://nvd.nist.gov/vuln/detail/CVE-2024-21914)
- CVE-2023-2071 "allows unauthenticated attackers to execute remote code via maliciously crafted packets in FactoryTalk View Machine Edition on PanelView Plus," and CVE-2023-29464 lets unauthenticated actors read memory in FactoryTalk Linx; the threat report cites a July 2024 Microsoft blog on PanelView Plus RCE (PDF and Microsoft URLs returned 404 at fetch time; details from search snippet only) — [Hive Pro TA2024262 (PDF, 404 at fetch)](https://hivepro.com/wp-content/uploads/2024/07/TA2024262.pdf)
- A Sept 28, 2023 CISA advisory covers PanelView 800 terminals (2711R-T10T/T7T/T4T) — [Canadian Cyber Centre AV23-590](https://cyber.gc.ca/en/alerts-advisories/control-systems-rockwell-automation-security-advisory-av23-590)
- Secondary (conflicting) descriptions of `.mer` (compiled runtime) vs `.apa` (archive) — [industrialmonitordirect: APA vs MER](https://industrialmonitordirect.com/blogs/knowledgebase/factorytalk-view-apa-vs-mer-files-complete-comparison)
- PEAT already recognizes product code 183 as "PanelView Plus 7 Standard 700" — local repo `clx_const.py`.

### Inferences
- The 2023 RCE research shows PanelView Plus exposes vendor-specific CIP classes that read/write files on the terminal; if those classes were documented by Microsoft's write-up, they would be a direct "pull" path for PEAT (runtime .mer, logs, users). This could not be confirmed this turn (URLs 404) — flag for the report writer as a high-value follow-up.
- Parsing FactoryTalk View ME display XML into PEAT's model yields HMI screens/tag references (useful for "files"/"logic-adjacent" inventory) but not device identity/firmware; tag CSV yields controller shortcuts/addresses (network topology hints). Value is moderate.
- Without a free ME Station runtime, scan testing is identity-emulation only.

### Gaps
- Exact CIP class IDs/services used in CVE-2023-2071 and FactoryTalk View ME fixed versions — Microsoft blog and Hive Pro PDF fetches failed.
- FactoryTalk View ME Station PC runtime demo mode (free time-limited?) — not searched (budget).
- `.apa` and `.vpd` internals — undocumented.
- Whether the Sample Code Library's "HMI code" includes `.apa`/`.mer` and under what license — 403.

---

## Candidate: Stratix industrial switches (Cisco IOS / IOS-XE based)

### Takeaway
Stratix is a Cisco switch with a Rockwell badge: configs are IOS text, SNMP is standard, and a current KEV-listed SNMP RCE/DoS (CVE-2025-20352) makes it security-relevant. **Parse: yes** — IOS running-config parsing via GPLv3 `ciscoconfparse2`, fixtures can be synthetic IOS configs (no Rockwell IP involved). **Scan: partially** — SNMP sysDescr/sysObjectID and SSH/HTTP banners can be mocked with generic SNMP/SSH simulators; CIP identity for Stratix was not confirmed; no free IOS image exists (Cisco licensing), so a full IOS target in CI is not available. Effort: small–medium (parse) + small (scan via SNMP mock).

### Cited Findings
- Rockwell SD1749 / CVE-2025-20352: Cisco IOS/IOS-XE SNMP stack overflow; Stratix 5700/5400/5410 affected up to v15.2(8)E7, Stratix 5200/5800 up to v17.17.01; attacker with read-only community string or SNMPv3 creds can cause reload (DoS), root code execution needs admin creds; CVSS 3.1 7.7 / 4.0 6.3; Rockwell marks Known Exploited Vulnerability "Yes" as of rev 1.1 (Jan 12, 2026) whereas CISA's Oct 9, 2025 republication said no known exploitation at that time; 5200/5800 fix expected March 2026 — [Rockwell SD1749](https://www.rockwellautomation.com/en-us/trust-center/security-advisories/advisory.SD1749.html); [CISA-republished copy (NetServices)](https://www.netservicesgroup.com/?p=13020)
- 2017 Cisco IOS flaws also affected Stratix — [Security Affairs](https://securityaffairs.com/62347/breaking-news/cisco-ios-flaws-rockwell.html)
- Stratix 5900 manual documents IOS `show running-config`/startup-config — [1783-SR manual p.72](https://manualsdir.com/manuals/579957/rockwell-automation-1783-sr-stratix-5900-services-router-user-manual.html?page=72); FactoryTalk Design Studio exports Stratix configuration to a computer — [Rockwell FTDS help](https://www.rockwellautomation.com/en-ie/docs/factorytalk-design-studio/current/contents-ditamap/using-the-software/manage-devices/export-stratix-device-configuration.html)
- A Cisco Community thread notes the Stratix 5700 "normal web config tool does not have" a bulk config print facility (CLI needed) — [Cisco Community: Stratix 5700 configuration print out](https://community.cisco.com/t5/switching/stratix-5700-configuration-print-out/m-p/3719804/highlight/true)
- `ciscoconfparse2`: GPLv3, Python 3.7+ — [PyPI](https://pypi.org/project/ciscoconfparse2)
- PEAT has no existing Cisco module (local `peat/modules`: camlin, fortinet, ge, idirect, openplc, rockwell, sandia, schneider, sel, siemens, uefi, windows, woodward).

### Inferences
- A Stratix module is really a Cisco IOS module; implementing it as `peat/modules/cisco` with Stratix detection (sysDescr/`show version` strings, 1783- catalog numbers) maximizes reuse across many critical-infrastructure networks. `ciscoconfparse2`'s GPLv3 is compatible with PEAT's GPLv3 runtime dependency set.
- Pull via SSH (`show running-config`, `show version`, `show inventory`) is standard IOS and testable against an SSH mock; SNMP pull is testable with snmpsim. These are generic-OT wins and not Rockwell-specific.

### Gaps
- Stratix CIP Identity Object support/product codes (Stratix has a Logix Add-On Profile, which implies CIP) — not verified (search not performed).
- Stratix 5700 user manual (1783-UM007) content — not retrieved.
- Free IOS/IOS-XE emulation legally usable in CI — none known; not researched.

---

## Candidate: EDS files for fleet-wide identity fingerprinting (PowerFlex, Kinetix, POINT/FLEX I/O, 1783/1756 modules)

### Takeaway
EDS files are the canonical source of Vendor/Device Type/Product Code/Revision → product name mappings, and PEAT already has TODOs to use them. They are plain text and downloadable from PCDC (free account), but redistribution terms were not found, so PEAT should ship a *derived* lookup table (vendor/type/code → name) rather than the files. **Parse: yes (EDS is INI-style ASCII; trivial). Scan: yes — this is purely a fingerprint-enrichment layer tested with cpppo identities.** Effort: small (table build) once a bulk EDS source is obtained.

### Cited Findings
- Rockwell: EDS files are "used with network configuration tools to identify and commission products" and are found via PCDC or the EPS library — [Rockwell product downloads](https://www.rockwellautomation.com/en-us/support/product/product-downloads); [PCDC EDS search](https://compatibility.rockwellautomation.com/pages/search.aspx?crumb=117&q=EDS%20files)
- Third-party posts conflict on the EDS filename hex convention; one notes RSLinx/RSNetWorx match by Identity Object values — [industrialmonitordirect: EDS naming](https://industrialmonitordirect.com/blogs/knowledgebase/eds-file-identity-naming-convention-for-allen-bradley-devices) (secondary)
- PEAT: `clx_const.py` "TODO: properly figure these out using Electronic Data Sheet (EDS) files"; `ab_scan.py` "TODO: productCode + productType => lookup in EDS files"; `controllogix.py` already looks for `*.eds` on the EN2T/EWEB FTP share — local repo.
- Conpot's identity (VendorId 1, DeviceType 14, ProductCode 90, "1756-L61/B LOGIX5561") collides with PEAT's MicroLogix code 90 — [conpot enip.toml](https://raw.githubusercontent.com/mushorg/conpot/master/conpot/templates/default/enip.toml); local `clx_const.py`.

### Inferences
- Device Type (14 = Programmable Logic Controller in CIP) must be combined with Product Code; PEAT's current code-only branding is ambiguous (90 = ML1400 or 1794-AENT or, per Conpot, 1756-L61). A (vendor, device_type, product_code) → name table solves this and extends scan coverage to drives/IO/switches for free.
- EN2T/EWEB modules serve EDS files over FTP (PEAT already checks for them), so EDS can also be collected at *pull* time from real devices.

### Gaps
- EDS redistribution/licensing terms from PCDC — not found.
- Existence of a bulk "all EDS" archive on PCDC (blogs claim one; unverified).
- Python EDS parsers on PyPI — not searched (budget).

---

## Candidate: .ACD (Studio 5000 native project) parsing

### Takeaway
Feasible via `acd-tools` (Apache-2.0, pre-release alpha, Python 3.8+/3.12+ recommended, tested v15–35) by converting to L5X and reusing PEAT's L5X parser. **Parse: yes, contingent on acd-tools' stability and on obtaining `.ACD` fixtures (Studio 5000 is paid; acd-tools' own test assets may serve). Scan: n/a (file-only).** Effort: small to wrap; medium if PEAT must harden/own the Kaitai parsers.

### Cited Findings
- See Key Question 3: `acd-tools` structure, capabilities, L5X export, versions tested, alpha status, Kaitai-generated parsers, module metadata caveat — [hutcheb/acd](https://github.com/hutcheb/acd); [acd-tools PyPI](https://pypi.org/project/acd-tools/)
- `plc-format-converter` ACD↔L5X (unverified) — [PyPI](https://pypi.org/project/plc-format-converter/)
- Rockwell's official ACD→L5X export requires Studio 5000 — [Rockwell ACM help](https://www.rockwellautomation.com/en-fi/docs/studio-5000-application-code-manager/5-01/library-object-manager-help-ditamap/library-object-manager-overview/library-repositories-overview/add-and-mount-an-acd-repository/export-acd-to-l5x.html)
- Rockwell EULA forbids reverse engineering/decompiling the *software* — [Scribd EULA copy](https://www.scribd.com/document/457220554/License)

### Inferences
- acd-tools' hardware-module records are "opaque CIP identity records" — exactly the identity tuples PEAT wants; even partial decoding would populate PEAT's hardware inventory.
- Using a third party's reverse-engineered parser avoids PEAT performing RE itself, but Sandia counsel should still review given the EULA language.

### Gaps
- Whether hutcheb/acd ships redistributable `.ACD` test files — not verified.
- acd-tools behavior on Studio 5000 v36–v37+ ACDs — only "15–35" claimed.

---

## Candidate: FactoryTalk Linx / RSLinx Classic / FactoryTalk AssetCentre

### Takeaway
Not researched beyond incidental findings (budget). Only data point: CVE-2023-29464 — unauthenticated memory read in FactoryTalk Linx (paired with the PanelView Plus RCE). **Parse/scan: unknown; no evidence either is achievable without hardware/paid software.** Deprioritize.

### Cited Findings
- CVE-2023-29464 in FactoryTalk Linx "lets unauthenticated actors access memory data" — [Hive Pro TA2024262 (search snippet; PDF 404 at fetch)](https://hivepro.com/wp-content/uploads/2024/07/TA2024262.pdf)

### Inferences
- RSLinx Classic Lite is historically free and FactoryTalk Linx is bundled with Studio 5000, but neither produces device-config artifacts PEAT would parse; AssetCentre exports could carry controller backups but require a paid server product. Low fit.

### Gaps
- RSLinx Classic Lite current availability, FactoryTalk Linx free tier, AssetCentre export formats — not searched.

---

## Shortlist ranking under the PARSE + SCAN weighting (sample files + free network-reachable simulator)

### Takeaway
1. **CompactLogix/GuardLogix** — parse (shared L5X) and scan (cpppo/Conpot identity) both achievable now with small effort; fixtures: any CompactLogix L5X (pycomm3's MIT test L5X is from a Logix controller — family unverified). 2. **EDS-based identity enrichment** — tiny parse, directly improves scan across all Rockwell families; blocked only on EDS redistribution clarity. 3. **Micro800/CCW** — free vendor IDE + simulator, XML project (probable), fresh critical CISA advisory; parse needs one Windows session to generate fixtures and confirm the format; scan via cpppo. 4. **Stratix** — parse via Cisco IOS tooling with synthetic fixtures; scan via SNMP mock; broad CI applicability. 5. **FactoryTalk View ME exports / PanelView Plus** — parse of XML/CSV is open but fixtures need paid View Studio or hand-authoring; scan via identity emulation. 6. **.ACD** — parse-only via alpha acd-tools; no scan. 7. **MicroLogix/SLC/PLC-5** — high security relevance and PEAT has PCCC, but **no parse path** (.RSS opaque) and no PCCC emulator; it is a scan + data-file-pull candidate. 8. **FactoryTalk Linx/AssetCentre** — insufficient evidence.

### Cited Findings
- All supporting citations appear in the sections above.

### Inferences
- For CI, a single shared fixture — cpppo `enip_server` launched with per-test `cpppo.cfg` Identity values (or the `honeynet/conpot` image for a Docker-only path) — covers scan tests for every Rockwell family in this list; none of the free targets covers pull of logic or PCCC.

### Gaps
- Whether pycomm3's test L5X is CompactLogix or ControlLogix — not checked.
