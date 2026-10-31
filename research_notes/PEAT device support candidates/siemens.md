# Siemens industrial-automation and energy-automation devices as PEAT support candidates

Scope: SIMATIC S7-300/400, S7-1200/1500 (S7comm, S7comm-plus, Web API), TIA Portal/STEP 7 files and Openness XML, WinCC/HMI, LOGO! 8, SCALANCE, SIPROTEC 5/DIGSI 5, S7-1500V / Software Controller, Industrial Edge / IOT2050. Existing PEAT SIPROTEC 4 HTTP/SNMP and TP700 WinCE routes are excluded except as extension notes.

Research method note: web search budget (shared across parallel researchers) was exhausted about halfway through this task; the second half relied on direct fetches of known primary URLs and on local installation/testing of the Python libraries in a venv (Python 3.13, 2026-10-31). Items that could not be verified are listed under Gaps rather than asserted.

Coordinator clarification applied: the ranking inputs at the end weight (1) redistributable sample vendor files for a parser and (2) a free, network-reachable simulator that answers on real TCP/UDP ports for scan testing in CI. Pull/push are secondary. Parse and scan feasibility without hardware is stated explicitly per candidate in the final section.

PEAT repo context verified locally: `pyproject.toml` lines 191-192 contain `# Siemens Snap7 protocol (Required for: S7 [not yet integrated in PEAT])` / `# "python-snap7==0.11",`; existing Siemens code is `peat/modules/siemens/siprotec.py` plus compiled MIBs in `peat/modules/siemens/mibs/` (SipEthernet, SipGoose, SipOptical, SIEMENS-SMI). The pinned 0.11 is a pre-3.x ctypes-wrapper era version; see Inferences in the first section.

---

## Key question 1: Does python-snap7 ship a snap7 server that can emulate an S7 PLC well enough to test scan/pull in CI, and what does it emulate? (S7-300/400 classic S7comm candidate)

### Takeaway
Yes. python-snap7 3.x is now a pure-Python (no C library) MIT package whose `snap7.server.Server` listens on any TCP port (non-privileged ports work), and in local testing it answered SZL 0x0011/0x001C/0x0131/0x0232 with a fixed "CPU 315-2 PN/DP / 6ES7 315-2EH14-0AB0" identity, block list, block info, protection level, PLC state and clock, which is exactly what a PEAT scan/fingerprint would query; block upload handlers exist but returned "block not found" for an unregistered OB1, so logic-pull testing against the emulator is at best partial.

### Cited Findings
- python-snap7 3.3.1 was released Oct 28, 2026 under MIT; it is "a pure-Python library for communicating with Siemens S7 PLCs" for Python >=3.10 "without native dependencies", the wheel is `py3-none-any`, and the page points to a "separate, younger project" `s7commplus` for S7-1200/1500 when PUT/GET is disabled or optimized/symbolic access is needed — [PyPI python-snap7](https://pypi.org/project/python-snap7/)
- Version 3.0 "implements the entire protocol stack in pure Python" replacing the earlier C snap7 wrapper; "No Snap7 shared library or platform-specific binary is required"; optional extras are `cli` (the `s7` command), `demo`, `discovery` (PROFINET DCP), `ppi` (experimental S7-200 serial PPI); the last pre-3.0 release is 2.1.1 (`pip install "python-snap7<3"`) — [python-snap7 installation docs](https://python-snap7.readthedocs.io/en/latest/installation.html)
- GitHub repo shows 865 stars, 284 forks, 683 commits; README says it supports S7-300/400 and S7-1200/1500 ("the latter only with PUT/GET enabled") on Windows, Linux and macOS — [gijzelaerr/python-snap7](https://github.com/gijzelaerr/python-snap7)
- `snap7.server.Server(log=True, max_clients=64)` "emulates a Siemens S7 PLC for testing and development purposes"; methods include `register_area(area, index, userdata)`, `set_cpu_status(0|4|8)`, `start(tcp_port=102)`, `start_to(ip, tcp_port)`, event callbacks; helper `snap7.server.mainloop(tcp_port=1102, init_standard_values=False)` "starts a pure Python S7 server" — [python-snap7 Server API](https://python-snap7.readthedocs.io/en/latest/API/server.html)
- The `s7` CLI (`pip install python-snap7[cli]`) provides `server` (emulated PLC, default port 1102), `demo` (live server exposing host CPU/memory/disk/network metrics in DB1, writable controls in DB2), `read`, `write`, `dump`, `info` ("CPU info, state, order code, protection level, and block counts") and `discover` (PROFINET DCP, raw sockets, may need root) — [python-snap7 CLI docs](https://python-snap7.readthedocs.io/en/latest/cli.html)
- Discovery API: `discover(ip, timeout=5.0)` sends a DCP "Identify All" and returns `Device` objects with `name`, `ip`, `mac`, `netmask`, `gateway`, `family`; `identify(ip, mac)` targets one device; depends on the `pnio-dcp` library and raises `NotImplementedError` on unsupported platforms — [python-snap7 Discovery API](https://python-snap7.readthedocs.io/en/latest/API/discovery.html)
- The documentation index lists API modules for Client/AsyncClient, Server, Partner, Logo, PPI, Tags, "SZL Parsers (including `parse_cpu_info_szl()` and `parse_order_code_szl()`)", Discovery and Demo Server — [python-snap7 docs index](https://python-snap7.readthedocs.io/en/latest/)
- Local test (python-snap7 3.3.1 installed from PyPI into a venv on Linux, 2026-10-31; source: [PyPI python-snap7](https://pypi.org/project/python-snap7/)): `Server().start(tcp_port=11102)` (unprivileged port) accepted a `Client.connect("127.0.0.1", 0, 1, tcp_port=11102)`; `get_cpu_info()` returned ModuleTypeName `CPU 315-2 PN/DP`, SerialNumber `S C-C2UR28922012`, ASName `SNAP7-SERVER`, Copyright `Original Siemens Equipment`; `get_order_code()` returned `6ES7 315-2EH14-0AB0` V3.3.0; `get_cp_info()` MaxPduLength 480 / MaxConnections 32; `get_cpu_state()` Run; `get_protection()` sch_schal=1; `get_plc_datetime()` host time; `list_blocks()` DB:1 (the registered area); `read_szl(0x0011)` and `read_szl(0x001C)` succeeded; `read_szl_list()` returned IDs 0x0000, 0x0011, 0x001C, 0x0131, 0x0232; `get_block_info(DB,1)` returned Author `SNAP7EMU`, Family `EMULATOR`; `full_upload(OB,1)` raised `S7ProtocolError (class=0xd2, code=0x09) block not found`.
- Local source inspection of `snap7/server/__init__.py` (same install): handlers exist for START_UPLOAD/UPLOAD/END_UPLOAD, `_handle_block_info`, `_handle_list_all_blocks`, `_handle_list_blocks_of_type`, `_handle_plc_control`, `_handle_clock`, and `_get_szl_data` hard-codes 0x001C (`CPU 315-2 PN/DP`), 0x0011 (`6ES7 315-2EH14-0AB0`), 0x0131 and 0x0232; `available_ids = [0x0000, 0x0011, 0x001C, 0x0131, 0x0232]`.
- The original Snap7 C library (Davide Nardella) is LGPLv3; latest file is `snap7-iot-arm-1.4.2.tar.gz`, project last updated 2025-06-24, 975 downloads/week; platforms Linux, Windows, Mac, Solaris, BSD, Raspberry Pi — [SourceForge snap7](https://sourceforge.net/projects/snap7/)
- Snap7 C Server: presents itself to STEP 7/TIA as a "CPU 315-2PN/DP"; implements read/write of DB/M/I/Q/T/C, block list / block info, simulated Run/Stop, simulated date/time, Read SZL, simulated password; does NOT implement block upload/download (refused with a security-level error), programming functions or cyclic I/O; has no MC7 program or SDBs; ISO-TCP port 102 "cannot be changed" and on Unix requires root or SUID; sample log shows SZL IDs 0x0132, 0x0000, 0x0111, 0x0424, 0x0F74, 0x0074 answered — [Snap7 Server page](https://snap7.sourceforge.net/snap7_server.html)
- Snap7 client target compatibility: Read SZL supported on S7-300/400/WinAC/Snap7 server/S7-1200/1500/CP/SINAMICS; "Directory" (list blocks) NOT on S7-1200/1500; "Block Upload/Down/Delete" supported on S7-300/400/WinAC/CP/SINAMICS but NOT on Snap7 server or S7-1200/1500 (other PG operations on 1200/1500 "must follow the extended protocol, not (yet) covered by Snap7"); Security (password) only 300/400/WinAC/Snap7S; Date/Time and Run/Stop not on 1200/1500; S7-1200/1500 DB access requires global DBs, "optimized block access" off, access level "full", "Permit access with PUT/GET" enabled — [Snap7 Client page](https://snap7.sourceforge.net/snap7_client.html)
- Wireshark wiki: S7comm is a Siemens proprietary protocol (S7-300/400), carried in COTP over ISO-on-TCP (RFC 1006) on TCP 102, first byte always 0x32; the dissector is "partially functional"; display filter `s7comm`; the wiki hosts six sample .pcap files (block download DB1, block list, PLC status, read/set PLC time, two libnodave demos) — [Wireshark wiki S7comm](https://wiki.wireshark.org/S7comm)
- Conpot (ICS honeypot) is GPL-2.0, ships a `Dockerfile` and `docker-compose.yml`, and its protocol packages include `s7comm`, `modbus`, `snmp`, `http`, `bacnet`, `enip`, `ftp`, `tftp`, `ipmi`, `iec104`, `kamstrup`, `guardian_ast` — [mushorg/conpot](https://github.com/mushorg/conpot); [Conpot docs](https://conpot.readthedocs.io/en/latest/)
- Conpot's default `s7comm.toml`: enabled, host 0.0.0.0, port 10201; SZL 0x1C component identification fields system_name=`SystemName`, module_name=`SystemDescription`, plant_ident=`FacilityName`, copyright, serial=`s7_id`, module_type_name=`s7_module_type`; SZL 0x11 module/hardware/firmware identification entries are empty; memory areas DB1 256 bytes, merkers 128, inputs 32, outputs 32 — [conpot s7comm.toml](https://raw.githubusercontent.com/mushorg/conpot/master/conpot/templates/default/s7comm.toml)
- NetToPLCsim (LGPLv3, v0.7.2, last update 2023-10-23, Windows .NET) is a "TCP/IP-Network extension for the PLC simulation software Siemens PLCSim (Step 7 V5.4/5.5)" — [SourceForge nettoplcsim](https://sourceforge.net/projects/nettoplcsim/)
- A Siemens forum post describes the TIA Portal V20 trial package (STEP 7 V20 incl. Safety, WinCC V20 and S7-PLCSIM V20) "for testing over 21 days" for registered users — [Siemens forum post 1233927](https://support.industry.siemens.com/forum/ww/en/post/1233927) (page returned HTTP 403 to direct fetch; quoted from search-result snippet)

### Inferences
- For PEAT CI: `python-snap7` 3.x server is the best available free S7-300/400 emulator — pip-installable, pure Python, cross-platform (Linux/Windows/macOS runners), runs on an unprivileged port, and answers the exact SZL IDs (0x0011 order code, 0x001C component ID, 0x0131 CP info, 0x0232 protection) that a scan/fingerprint module would issue. A PEAT S7 module's scan tests can run against it the same way the OpenPLC module is tested against Docker.
- Pull testing is partial: block list and block info work, but logic upload from the emulator fails for unregistered blocks; whether registering a block (e.g., via a server-side block table) enables upload was not tested. Real S7-300/400 upload returns MC7 binary (compiled code), not source — so a "pull logic" feature would store MC7 blobs; decompiling MC7 to STL/PLCopen is a large effort and out of scope for a first module.
- Conpot (GPLv2) is a second, independent S7comm responder usable as a Docker test fixture (its identity strings are configurable via TOML), which is useful to prove PEAT's fingerprinting does not overfit the snap7 emulator's constants. Being GPLv2 it should only be used as an external container, never linked into GPLv3 PEAT.
- PEAT's pinned `python-snap7==0.11` and the private snap7 script predate the pure-Python rewrite; a new module should target 3.x (API "largely the same") and drop the C-library dependency, which also removes the Windows/macOS DLL packaging problem.
- Port 102 is only relevant for real devices; emulators can use any port, so CI does not need root.

### Gaps
- Not tested whether the pure-Python server can serve real block uploads when blocks are registered (no `register_block`-style API found by grep; handlers exist).
- Snap7 (C) server's exact SZL payload values were not documented on the vendor page; only the pure-Python server's values were verified locally.
- Wireshark version that mainlined the `s7comm` dissector was not found on the wiki page.

---

## Key question 2: What can be pulled from S7-1200/1500 over S7comm-plus and the documented Web API (JSON-RPC), and is there any public emulator?

### Takeaway
S7-1200/1500 natively speak S7comm-plus (proprietary, reverse-engineered, now implemented in the MIT `s7commplus` Python package with a built-in V1/V2/V3 emulator that reports an order number during connect) and expose an officially documented HTTPS JSON-RPC Web API at `/api/jsonrpc` (login/token, `Api.*`, `PlcProgram.*`, `WebApp.*`, `Modules.Browse`, `Modules.ReadIdentificationMaintenance`, backup download/restore); no free public emulator of the Web API exists — the only simulator with a functioning web server is S7-PLCSIM Advanced (Windows, 21-day trial).

### Cited Findings
- `s7commplus` 0.3.0 (Oct 20, 2026; MIT; author Gijs Molenaar/gijzelaerr; Python 3.10+; Development Status Beta) is a "pure-Python S7CommPlus client for Siemens S7-1200 and S7-1500 PLCs" supporting protocol versions V1, V2 (TLS) and V3, sync and asyncio clients, "a server emulator for testing", legacy V1 SessionKey auth derived from HarpoS7 (MIT), `device_name`/`device_family` helpers with a `DEVICE_NAMES` table, and a CLI with `browse` and `read`; validated on real S7-1200, S7-1500 and S7-PLCSIM Advanced; "Classic S7-300/400 is out of scope" — [PyPI s7commplus](https://pypi.org/project/s7commplus/)
- README: "the order number a PLC reports during connect can be mapped to a module name and family" (e.g., `6ES7 512-1DK01-0AB0` -> `CPU 1512SP-1 PN`); `DEVICE_NAMES` covers S7-1200/1500, SIPLUS, software controllers and PLCSIM; clients "try a bounded set of bundled keys on fresh sessions for some older PLCs"; unofficial, "Test against an isolated controller before using it in production" — [gijzelaerr/s7commplus](https://github.com/gijzelaerr/s7commplus)
- Docs list client capabilities: raw DB/controller-area read/write, "symbolic browsing and LID-based access for optimized blocks", data and alarm subscriptions, "block upload/download and CPU-state operations"; some firmware-dependent operations are marked experimental — [s7commplus docs](https://s7commplus.readthedocs.io/)
- Local inspection of installed `s7commplus/server.py` (0.3.0): class `S7CommPlusServer` "Emulates an S7-1200/1500 PLC for integration testing without real hardware", handling COTP, CreateObject session handshake, Explore (browse registered DBs/variables), GetMultiVariables/SetMultiVariables, "V2 protocol emulation with TLS and IntegrityId tracking", V3 HMAC; public API `register_db`, `register_raw_db`, `start(port=11020, use_tls=..., tls_cert=..., tls_key=...)`, `stop`, `cpu_state`, `get_db`; the identity string emitted is `"1;6ES7 215-1AG40-0XB0 ;V4.2"` (a CPU 1215C at firmware V4.2); `DEVICE_NAMES` contains 105 entries — verified from [PyPI s7commplus](https://pypi.org/project/s7commplus/) install.
- Rogue7 (Biham, Bitan, Carmel, Dankner — Technion; Malin, Wool — Tel Aviv University; Black Hat USA 2019): "The S7 protocol is proprietary and little is published about it"; the newer S7CommPlus (protocol number 0x72) adds session-key exchange and message integrity (MAC); S7-1200 "does not support integrity protection"; protocol sub-versions P2 (up to TIA V12 / S7-1500 FW 1.5) and P3 (TIA V14/V15, FW 1.8/2.0/2.1); after reverse-engineering the authors built a rogue engineering station that can start/stop the PLC, download attacker logic, and perform a "stealth program injection" that modifies running code while the source presented to the engineering station stays unchanged — [Rogue7 whitepaper](https://i.blackhat.com/USA-19/Thursday/us-19-Bitan-Rogue7-Rogue-Engineering-Station-Attacks-On-S7-Simatic-PLCs-wp.pdf)
- S7Comm-Plus Wireshark dissector: as of Aug 2021 "not yet part of Wireshark"; source lives in the SourceForge `s7commwireshark` project, appears GPLv2, actively committed — [wireshark-dev thread](https://lists.wireshark.org/archives/wireshark-dev/202108/msg00017.html); a third-party blog claims Wireshark 3.6+ includes `s7comm_plus` and that newer S7-1500 traffic is TLS-protected — unverified and conflicting with the mailing list ([industrialmonitordirect blog](https://industrialmonitordirect.com/blogs/knowledgebase/monitoring-s7-plc-traffic-with-wireshark-in-tia-portal-v16)). SourceForge project pages returned 404 to direct fetch ([s7commwireshark](https://sourceforge.net/projects/s7commwireshark/)).
- S7-1500 Web server Function Manual (11/2019, A5E03484625-AG), section 3.20: the Web API is JSON-RPC 2.0 posted over HTTPS to `/api/jsonrpc`; `Api.Login(user, password)` returns a `token`; methods shown include `Api.Login`, `Api.GetPermissions`, `Api.GetMethods`, `Api.Logout`, `Api.Ping`, `PlcProgram.Read`, `PlcProgram.Write`, `PlcProgram.Browse`; the TOC also lists `Api.Browse`, `Api.Version`, `Api.GetCertificateUrl`; several calls can be sent as a bulk JSON array — [manualslib S7-1500 manual p.169](https://manualslib.com/manual/1662475/Siemens-Simatic-S7-1500.html?page=169), [p.189](https://manualslib.com/manual/1662475/Siemens-Simatic-S7-1500.html?page=189)
- Siemens' official .NET client `siemens/simatic-s7-webserver-api` (MIT; NuGet `Siemens.Simatic.S7.Webserver.API` 3.3.92, 10/14/2026, 76K total downloads) describes the API as "standardized JSON-RPC via HTTPS communication with a Simatic-specific data model" and implements `Api.Browse`, ticket browse/close, `WebApp.*` (create/browse/create resource/set default page/browse resources), `PlcProgram.Browse/Read/Write`, `Modules.Browse`, `Modules.ReadIdentificationMaintenance`, file upload/download, directory browse/deploy/update/delete, and backup download/restore; compatibility table covers S7-1500 (incl. R/H), S7-1200 G2 and S7-1200 firmware; "the library supports more API calls than the S7-1200 (G2) currently does"; usage examples live in unit tests; repo is tagged `plcsim` — [siemens/simatic-s7-webserver-api](https://github.com/siemens/simatic-s7-webserver-api), [NuGet page](https://www.nuget.org/packages/Siemens.Simatic.S7.Webserver.API)
- Newer manual editions (11/2023, A5E03484629-AK, "S7-1500, ET 200SP, ET 200pro, SIMATIC Drive Controller Web server", chapter 5 API) exist under Siemens entry IDs 109766665 / 59193560 per search results, but the Siemens support pages require JavaScript and the cached PDF URL returned 404 — [Siemens SIOS document 59193560](https://support.industry.siemens.com/cs/document/59193560)
- S7-PLCSIM Advanced Function Manual V6.0 UPD1 (03/2024): "A license is available for the limited period of 21 days" (Trial License, 3.1.4); runs only on Windows (Pro/Server; not Home); API for C++/C# co-simulation; communication via Softbus (local only) or "PLCSIM Virtual Ethernet Adapter" TCP/IP; Table 4-1: OPC UA server and Web server reachable only via TCP/IP mode, HTTPS to web server with TIA V17+; "Each S7-PLCSIM Advanced instance can simulate its own Web server" with restrictions (no topology info, no FW updates, some pages incomplete); "supports backup and restore via web servers" over TCP/IP — [PLCSIM Advanced manual PDF](https://cache.industry.siemens.com/dl/files/578/109955578/att_1267815/v1/s7-plcsim_advanced_function_manual_en-US.pdf)
- SIMATIC S7-1500V (Siemens webinar slides): "virtual SIMATIC S7-1500 PLC @SIEMENS Edge Runtime", TIA Portal compatible, delivered as an "Edge Runtime App @ Edge Marketplace", drawn as a Docker container on an Industrial Edge Device alongside HMI/WinCC apps, "available for Industrial Edge Device for IPCs and Virtual Edge Devices" (VMware ESXi shown), PROFINET RT 1 ms, CPU 1517V, multi-instance and safety "planned for future versions"; requires Industrial Edge Management and Industrial Edge Hub (Siemens-operated license management) — [Siemens virtual PLC slides](https://assets.new.siemens.com/siemens/assets/api/uuid:f8d80591-b51c-41eb-8bfb-dab025123374/virtuel-plc.pdf); trade press: shipped 2023, shown at Hannover Messe 2023 — [process-worldwide](https://www.process-worldwide.com/virtual-plc-exhibited-at-hannover-messe-2023-a-8d8bb2e6e9d462242170fb78e81a02e1/), [industrial-production.de](https://www.industrial-production.de/control-technology/first-virtual-simatic-controller.htm)
- S7-1500 Software Controller for Linux is sold as "SW Package für SIMATIC IPC227G und IPC277G" on Industrial OS V3 (purchased license, not a trial) — [Siemens datasheet 6ES7672-7AD02-6YG0](https://static.mercateo.com/58/585b11f7aee245c3bdbc3ecc0f108384/pdf/6ES76727AD026YG0_datasheet_de.pdf); CPU 1507S single licence with key download — [Siemens Mall 6ES7672-7AC01-0YG0](https://mall.industry.siemens.com/mall/en/us/Catalog/Product/6ES76727AC010YG0)

### Inferences
- Scan/fingerprint of S7-1200/1500 without hardware is achievable in CI: the `s7commplus` emulator runs on a configurable port and completes the CreateObject handshake that yields the order number (`6ES7 215-1AG40-0XB0`, FW V4.2) which PEAT can map to model/family via the 105-entry `DEVICE_NAMES` table. V2/TLS emulation also allows testing TLS-based fingerprinting.
- Pull of identity, DB contents and (experimentally) blocks from S7-1200/1500 over S7comm-plus is plausible with `s7commplus`, but the Rogue7 paper shows the protocol's security design relies on key material Siemens does not publish; `s7commplus` ships "bundled keys" derived from HarpoS7, which is a legal/ethical caveat to flag for Sandia counsel before shipping in a GPLv3 tool.
- The Web API is the cleanest officially documented pull path (identity via `Modules.ReadIdentificationMaintenance`, program browse/read, backups, files, web apps) and fits PEAT's `requests` stack with a few hundred lines; however, no free emulator exists, so Web API tests would need recorded JSON fixtures (mocked HTTP) rather than a live endpoint in CI. Generating those fixtures requires PLCSIM Advanced on Windows (21-day trial) or hardware.
- S7-1500V and the Software Controller are commercial, licensed runtimes behind Industrial Edge Management / IPC bundles; neither is a free Docker image for CI. PLCSIM Advanced is Windows-only and trial-limited, so it cannot be a recurring CI dependency.

### Gaps
- The full method list of current Web API versions (Plc.ReadOperatingMode, DiagnosticBuffer.Browse, Alarms.Browse, DataLogs.*, Syslog.Browse, Failsafe.*, Redundancy.*, Project.ReadLanguages etc.) could not be confirmed from a primary source; Siemens' JS-only support portal blocked fetches and the search budget was exhausted. The 11/2019 manual confirms only the `Api.*` and `PlcProgram.*` core.
- Minimum firmware for the Web API (reported in the assignment as V2.9+) was not confirmed from Siemens text in this session.
- No validated firmware list for `s7commplus` (PyPI/README omit versions).
- S7-1500V list price and trial status not found.

---

## Key question 3: Where can one obtain real TIA Portal Openness XML (SimaticML) exports, STEP 7 source exports, or TIA/STEP 7 project files for parse test fixtures?

### Takeaway
The formats are open and well documented (Siemens' TIA Openness V20 manual on docs.tia.siemens.cloud describes XML export of blocks, tag tables, UDTs, HMI screens and AutomationML hardware), but no redistributable public corpus of SimaticML exports was found; the practical route is to generate fixtures with the 21-day TIA Portal trial and Openness (Windows), or to hand-author minimal SimaticML, and to confirm redistribution terms before committing them.

### Cited Findings
- Siemens publishes "TIA Portal Openness: API for automation of engineering workflows" (TIA Portal V20, 01/2025) on a public docs site; its TOC includes "Importing/exporting data of a PLC device", "Blocks", "XML structure of the block interface section", "Exporting DBs with snapshots", "Exporting blocks with know-how protection", "Export/Import of SCL blocks", "Exporting PLC tag tables", "Exporting user data type", "Export/Import of UDT & DB", HMI "Structure of an XML file", "Exporting all screens of an HMI device", "Text lists", "Graphic lists", "Connections", "Export Document information to SimaticML file", "Version Specific Simatic ML Import", hardware "AML file format", "Pruned AML", "Export of CAx data", and "Export of data in OPC UA XML format" — [TIA Openness V20 manual](https://docs.tia.siemens.cloud/r/en-us/v20/tia-portal-openness-api-for-automation-of-engineering-workflows)
- The GitHub `tia-openness` topic lists ~22 repos (e.g., Czarnak/tia-portal-mcp 104 stars, Repsay/tia-openness-api-client 54, Parozzz/TiaUtilities 39 "import/export XML files", Repsay/tia-portal-xml-generator 22, caprican/SimaticML 12, Vyenkor/TIA-Export-Fb2Xml 5); none is described as a sample-export/fixture corpus and no Python SimaticML parser or PLCopen converter appears there — [GitHub topic tia-openness](https://github.com/topics/tia-openness)
- `simaticml-decoder` (Czarnak) 0.2.3 (Jul 20, 2026; Python >=3.11; CI on Ubuntu 3.11-3.14 and Windows 3.11) converts exported SimaticML FC/FB LAD/FBD (`FlgNet`) and SCL networks into readability-first SCL plus JSON; GRAPH/STL deferred; UDT and tag-table XML unsupported; it ships no sample XML — its probes come from a third-party repo and are "not a distributable fixture corpus"; license not stated on PyPI — [PyPI simaticml-decoder](https://pypi.org/project/simaticml-decoder/), [repo](https://github.com/Czarnak/simaticml-decoder)
- `Repsay/tia-portal-xml-generator` (MIT, graduation project, 18 commits) generates DB/FB/OB XML for Openness import; no sample XML visible — [repo](https://github.com/Repsay/tia-portal-xml-generator); `Repsay/tia-openness-api-client` (MIT, Python 3.11) exports blocks via Openness but the author "cannot test the code myself due to the unavailability of TIA Portal and TIA Openness" — [repo](https://github.com/Repsay/tia-openness-api-client)
- `caprican/SimaticML` (.NET) describes SimaticML as the XML standard for program blocks and HMI screens and AML as the XML format for hardware (CAx) data; links Openness manuals V16-V19 — [repo](https://github.com/caprican/SimaticML)
- `Speedstuff/TiaExportBlocks` exports SCL, DB, UDT and PLC tag tables (XML) from an open TIA V15.1 project; requires .NET 4.7.2 and membership in the Windows group "Siemens TIA Openness" — [repo](https://github.com/Speedstuff/TiaExportBlocks)
- Siemens-affiliated org `tia-portal-applications` (verified siemens.com domain, 19 repos) hosts Openness/Add-In libraries (e.g., `tia-portal-openness-unified-library`, `TIA-Add-In-ShowScripts` which exports WinCC Unified screen JavaScripts) but no sample projects or exported XML — [github.com/tia-portal-applications](https://github.com/tia-portal-applications)
- Siemens SIOS entry 108716692 ("TIA Portal Openness: Introduction and demo application", per search results) could not be read: the page renders only "Loading... Please enable javascript" — [SIOS 108716692](https://support.industry.siemens.com/cs/ww/en/view/108716692)
- TIA Portal V20 trial (STEP 7 incl. Safety, S7-PLCSIM V20, WinCC V20) is downloadable by registered users for 21 days — [Siemens forum post](https://support.industry.siemens.com/forum/ww/en/post/1233927) (snippet; fetch returned 403). Third-party blogs disagree on whether reinstalling resets the trial ([blog A](https://industrialmonitordirect.com/blogs/knowledgebase/simatic-tia-portal-trial-licensing-duration-and-legal-options), [blog B](https://industrialmonitordirect.com/blogs/knowledgebase/siemens-tia-portal-free-license-renewal-and-retention-guide)) — unverified.
- Third-party (Qualys VMDR OT help) lists DIGSI 5 project exports as `.zip,.dz5`; the page now redirects to docs.qualys.com — [Qualys help (redirected)](https://qualysguard.qg2.apps.qualys.com/ics/help/assets/generating_a_project_file.htm) — unverified against Siemens.

### Inferences
- Parse support for SimaticML is realistic and cheap-to-medium: it is plain XML with a published structure, maps naturally onto PEAT's data model (blocks -> PLCopen/ST, tag tables -> variables, AML -> hardware inventory and network interfaces/IPs, HMI connections -> network peers). The limiting factor is fixtures, not format.
- Fixture strategy without hardware: install the 21-day TIA Portal trial on a Windows VM, build a small project, export blocks/tag tables/UDTs/HMI screens/CAx AML via Openness (or TIA's GUI "Export CAx data" and "Generate source from blocks" for .scl/.awl text), and store those outputs as test fixtures. Because they are project-author-created content rather than Siemens-copyrighted files, redistribution risk is low, but the trial EULA should be read for restrictions on using trial output in an open-source project (not verified here).
- STEP 7 Classic/TIA "external source" files (.awl/.scl/.db) are plain text and the lowest-effort parse target; confirming public sample availability (GitHub repos with .scl/.awl) was not possible after the search budget ran out.
- The TIA project container (.ap1x and its internal PEData.plf) remains undocumented in sources reached; treat it as proprietary binary and do not plan parse support.

### Gaps
- No primary source reached on `.ap1x`/`.ap2x` internal structure (PEData.plf, IM folders) — search budget exhausted.
- Location/availability of SimaticML XSD schema files (shipped inside the TIA Portal installation per community knowledge) not verified.
- SIOS application-example download terms (login requirement, redistribution) not verified because the portal is JS-only.
- No GitHub repository containing redistributable SimaticML fixtures was confirmed; code-search via `gh` is blocked in this session (repository-scoped API).

---

## Key question 4: Which Siemens formats are plain text / XML / JSON and therefore cheap to parse?

### Takeaway
Cheap targets are SimaticML and AutomationML (XML) from TIA Openness, STEP 7/TIA source exports (.scl/.awl/.db text), the S7-1500 Web API (JSON-RPC 2.0), SCALANCE "RunningCLI" and "LogFile" exports (plain text), IEC 61850 SCL files (ICD/CID/SCD, XML) from DIGSI 5, and DIGSI 4 XML parameter exports; proprietary/encrypted ones are TIA project containers, MC7 compiled blocks, SCALANCE Config/ConfigPack/Debug/Firmware, WinCC runtime files, and LOGO! .lsc (unverified).

### Cited Findings
- SimaticML/AML XML exports and "Export/Import of SCL blocks" are documented Openness operations — [TIA Openness V20 manual](https://docs.tia.siemens.cloud/r/en-us/v20/tia-portal-openness-api-for-automation-of-engineering-workflows)
- Web API is JSON-RPC 2.0 over HTTPS at `/api/jsonrpc` — [S7-1500 web server manual p.169](https://manualslib.com/manual/1662475/Siemens-Simatic-S7-1500.html?page=169)
- SCALANCE S615 WBM manual (11/2019, C79000-G8976-C388-08) Load&Save file list: `RunningCLI` = "text file of the current configuration as CLI commands" with passwords shown as `[PASSWORD]`; `LogFile` = text file of event log entries ("plain ASCII text"); `MIB` = private MSPS MIB file; `Config` = start configuration incl. users/roles/rights (passwords stored in a separate "Users" file); `ConfigPack` = start configuration + users + certificates (password-protectable); `ConfigPackBackup` = ZIP of backups; `Debug` = encrypted diagnostics; `Firmware` = "signed and encrypted, so only Siemens-created firmware can be loaded"; `HTTPSCert` = certificates/keys — [S615 WBM manual p.123](https://manualslib.com/manual/1933699/Siemens-Simatic-Net-Scalance-S615.html?page=123)
- SCALANCE X-200 manuals document "Save & Load HTTP" and "Save & Load TFTP" and "Configuration via SNMP" — [X-200 manual](https://www.manualsdir.com/manuals/150778/siemens-scalance-x-200.html?page=82); XM-400 CLI manual has `show loadsave files`, `load tftp`, `save filetype`, `tftp load/save` — [XM-400 CLI manual TOC](https://manualslib.com/manual/1247021/Siemens-Scalance-Xm-400.html?page=110)
- DIGSI 5 "supports the SCL (substation configuration description language) configuration files from the IEC 61850-6 through import or export of all formats (ICD/IID/CID/SCD/SSD/SED)" — [DirectIndustry DIGSI 5 listing](https://www.directindustry.com/prod/siemens-energy-automation-and-smart-grid/product-30064-1198697.html); Siemens tender text: "openness through large spectrum of exchange formats e.g. IEC 61850, XML-based and XRIO-Formats" — [Siemens tender text DIGSI 5](https://ausschreibungstexte.siemens.com/tiplv/Data/English/Electrical_Distribution,_Industrial_Controls,_Building_Technologies/Energy_Automation_and_Smart_Grid_Products/Engineering_Tools_for_Protection/Engineering_tool_DIGSI_5/(LV_Q3FR3VYRA4YMD3NTZ84BCWA6DR))
- DIGSI 4 offers XML import/export with "standard-conform XML tags that reflect the structure of the parameter set"; a Siemens forum user exports a relay's `.dex` to XML for a separate tool — [Siemens forum post 837073](https://support.industry.siemens.com/tf/ww/en/post/837073/); DIGSI 4 V4.94 update notes mention a compact version and XML export features — [devicebase DIGSI 4 V4.94](https://devicebase.net/en/siemens-wincc/updates/digsi-4-v4-94-update-compact-version-and-xml-export-features/gd)
- Real S7-300 CPUs store compiled MC7 code, not SCL source, so uploaded blocks cannot be turned back into editable SCL (third-party blog, low reliability) — [industrialmonitordirect](https://industrialmonitordirect.com/blogs/knowledgebase/resolving-s7-300-scl-upload-blocked-in-tia-portal-v17); consistent with Snap7's statement that its server has "no MC7 program" — [Snap7 Server](https://snap7.sourceforge.net/snap7_server.html)
- WinCC flexible runtime (.fwx) "cannot be decompiled or reversed to recover the original source files"; WinCC Unified tag logs are `.db3` segment files; Unified project export is `.zap21` (all third-party blog claims, low reliability) — [blog: flexible backtransfer](https://industrialmonitordirect.com/blogs/knowledgebase/recovering-wincc-flexible-project-from-runtime-backtransfer-not-supported), [blog: Unified tag logs](https://industrialmonitordirect.com/blogs/knowledgebase/export-wincc-unified-tag-logs-to-csv-via-javascript-on-tia-v18), [blog: V21 .zap21](https://industrialmonitordirect.com/blogs/knowledgebase/wincc-unified-v21-project-startup-rdf-file-error-resolution)

### Inferences
- A parse-only "Siemens exports" module could cover several candidates at once with one XML/text toolchain: SimaticML (blocks/tags/UDTs/HMI), AML (hardware/network), .scl/.awl text, SCALANCE RunningCLI/LogFile, IEC 61850 SCL and DIGSI 4 XML — all map onto PEAT's normalized model (device identity, firmware, interfaces, users/roles for SCALANCE RunningCLI, events for LogFile, logic for SimaticML/SCL).
- SCALANCE `RunningCLI` is the most valuable single text artifact (full switch configuration incl. users/roles, interfaces, VLANs, SNMP, services), and `LogFile` gives events; `Config`/`ConfigPack` binary blobs should be stored as files only.

### Gaps
- LOGO! `.lsc` internal format (text vs binary) not verified.
- WinCC Unified `.zap` container contents not verified from a Siemens source.
- No sample SCALANCE RunningCLI or LogFile export found publicly (search budget exhausted).

---

## Candidate: SIMATIC HMI / WinCC (TIA), WinCC flexible, WinCC Unified, Comfort Panels

### Takeaway
Realistic parse support is limited to TIA Openness XML exports of HMI objects (screens, tag tables, text/graphic lists, connections) and Unified scripting exports; runtime/project binaries are not parseable from public documentation, and no free HMI runtime emulator reachable over the network was identified (WinCC Unified runtime is a licensed TIA product; the TP700 WinCE route already exists in PEAT).

### Cited Findings
- Openness exports HMI "Screens" ("Exporting all screens of an HMI device"), "Tag tables", "Text lists", "Graphic lists", "Connections" with a documented "Structure of an XML file" — [TIA Openness V20 manual](https://docs.tia.siemens.cloud/r/en-us/v20/tia-portal-openness-api-for-automation-of-engineering-workflows)
- Siemens' `TIA-Add-In-ShowScripts` exports all WinCC Unified screen JavaScripts to files plus an Excel overview; `wincc-unified-on-IE` (MIT) runs WinCC Unified as an Industrial Edge app — [tia-portal-applications](https://github.com/tia-portal-applications), [industrial-edge org](https://github.com/industrial-edge)
- Official Siemens page (German) documents exporting WinCC Unified tags through its OPC UA server (RT Unified, V20, 06/2025) — [docs.tia WinCC Unified OPC UA export](https://docs.tia.siemens.cloud/r/de-de/v20/simatic-runtime-manager-rt-unified/variablen-uber-den-opc-ua-server-exportieren-rt-unified)
- Third-party claims (low reliability): Unified Comfort Panel parameter-set exports are TSV; tag logs `.db3`; flexible `.fwx` not reversible; the TIA V20 trial excludes WinCC Advanced (forum) — see URLs in Key question 4 and [TIA trial forum snippet](https://support.industry.siemens.com/forum/ww/en/post/1233927)

### Inferences
- Parse: achievable without hardware only for Openness XML (same toolchain as PLC blocks) and OPC UA XML exports; fixtures again require the TIA trial. Effort small-medium once SimaticML parsing exists.
- Scan: WinCC Unified/Comfort runtimes expose HTTPS/OPC UA/VNC-like services on hardware or licensed runtime; no free network-reachable simulator was found, so scan cannot be CI-tested. Low priority relative to PLC and SCALANCE work.

### Gaps
- No Siemens primary source for WinCC project/runtime file formats reached.
- WinCC Unified PC runtime trial availability and whether it exposes network services in demo mode not verified.

---

## Candidate: Siemens LOGO! 8 logic modules

### Takeaway
LOGO! 8 speaks an S7-protocol subset (V-memory as DB1 via TSAP-based connections) that python-snap7 covers via its `Logo` API, but identity/SZL, block listing and upload are not available over S7 (program transfer uses a separate undocumented "PG protocol"); no Siemens source on a free LOGO! Soft Comfort demo was reachable, and LOGO! 9 / Soft Comfort V9 now exists with Linux/macOS support and Modbus TCP/MQTT/web server.

### Cited Findings
- Snap7: LOGO uses two Ethernet protocols — the PG protocol (used by LOGO!Soft Comfort for upload/download, run/stop, configuration) "is not covered by Snap7", and the S7 protocol for data exchange; only the LOGO V area is accessible, "seen by Snap7 as DB 1"; connect with `SetConnectionParams(ip, 0x0300, 0x0200)` matching TSAPs configured as a "Server Connection" in LOGO!Soft Comfort — [Snap7 LOGO page](https://snap7.sourceforge.net/logo.html)
- A Snap7 ticket reports newer LOGO!8 firmware/LogoSoft Comfort can disable the S7 protocol and it "was disabled by default" — [Snap7 ticket 30](https://sourceforge.net/p/snap7/tickets/30)
- python-snap7 docs include a `Logo` API module — [python-snap7 docs index](https://python-snap7.readthedocs.io/en/latest/)
- Siemens LOGO! page: LOGO! Soft Comfort V9 lets you "develop and test your application on Windows, macOS or Linux", combines programming, simulation and web visualization; LOGO! 9 supports Modbus TCP/IP, MQTT, a web server for browser access, KNX via CMK2000; Web Editor projects migrate to V9; S7 and demo availability are not mentioned on the page — [Siemens LOGO! product page](https://www.siemens.com/global/en/products/automation/systems/industrial/plc/logo.html)
- Third-party blogs conflict on the Soft Comfort demo: one says the demo allows "full program development, offline simulation" with only hardware transfer blocked; another says it "blocks upload, download, and online monitoring"; a third says LOGO! 8.3/8.4 require V9 — all low reliability — [blog 1](https://industrialmonitordirect.com/blogs/knowledgebase/logo-soft-comfort-license-recovery-and-demo-options), [blog 2](https://industrialmonitordirect.com/blogs/knowledgebase/resolving-logosoft-comfort-demo-transfer-greyed-out-issue), [blog 3](https://industrialmonitordirect.com/blogs/knowledgebase/siemens-logo-soft-comfort-v8-license-v82-upgrade-and-v9)
- The CISA/NSA AA26-231A S7 advisory lists S7-200/300/400/1200/1500 but not LOGO! — [AA26-231A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-231a)

### Inferences
- Scan: a LOGO! answers on TCP 102 only if an S7 server connection is configured; without SZL identity support there is little to fingerprint beyond "ISO-TCP accepted on this TSAP". python-snap7's server could stand in for the TSAP handshake in CI, but it would not validate LOGO!-specific behavior. Weak scan candidate.
- Parse: `.lsc` format unknown/likely proprietary; no public fixtures found. Weak parse candidate.
- Pull: V-memory read only; program (PG protocol) is undocumented. Overall low priority; small effort to add a "LOGO! V-area read" option to the S7 module, but low intelligence value.

### Gaps
- Official LOGO! Soft Comfort demo availability/limits (Siemens source) not found.
- LOGO! 8 web server pages/API and `.lsc` structure not researched due to search budget.
- No CISA/ProductCERT LOGO! advisory could be fetched (IDs unknown without search).

---

## Candidate: SCALANCE X/XC/XM/S/M switches, routers and security appliances (incl. SINEMA)

### Takeaway
SCALANCE fits PEAT's existing SNMP/HTTP(S)/Telnet/SSH stack and exports a plain-text `RunningCLI` configuration, ASCII `LogFile`, and private MIB via its Load&Save (HTTP/TFTP/SFTP) mechanism, making pull and parse straightforward in principle; but no emulator exists, firmware is signed and encrypted, and no public sample exports were found, so scan/pull can only be tested against generic SNMP/HTTP mocks rather than a Siemens-specific simulator.

### Cited Findings
- Load&Save file types (S615 WBM manual 11/2019): Config, ConfigPack, ConfigPackBackup, Debug (encrypted), Firmware ("signed and encrypted"), HTTPSCert, LogFile (ASCII text), LoginWelcomeMessage, MIB (private MSPS MIB), RunningCLI (text config as CLI commands, passwords masked) — [S615 WBM manual p.123](https://manualslib.com/manual/1933699/Siemens-Simatic-Net-Scalance-S615.html?page=123)
- X-200 family: configuration save/load via HTTP and TFTP from WBM; "Configuration via SNMP" chapter — [X-200 manual](https://www.manualsdir.com/manuals/150778/siemens-scalance-x-200.html?page=82); XC-200 operating instructions defer configuration to the "SCALANCE XB-200/XC-200/XF-200BA/XP-200/XR-300WG Web Based Management" manual; XB/XC-200 CLI manual includes "Configuration Save & Restore" and tftp load/save (search summaries) — [XC-200 operating instructions PDF (mirror)](https://www.siemens-pro.ru/docs/scalance/x-200/BA_SCALANCE-XC-200_76.pdf); XM-400 CLI manual TOC: `show loadsave files`, `load tftp`, `save filetype`, `tftp load/save` — [XM-400 CLI manual](https://manualslib.com/manual/1247021/Siemens-Scalance-Xm-400.html?page=110)
- Desigo CC integration ships SNMP configuration templates for SCALANCE XC-208/XC-224, evidencing standard SNMP manageability — [Desigo CC help](https://gbscampus.vu.nl/WebApp/Help/EngineeringHelp/en-US/14784677387.html)
- Third-party blog: the MIB file is downloadable from the SCALANCE WBM "Downloads" area (XB-200 series) — [industrialmonitordirect](https://industrialmonitordirect.com/ko/blogs/knowledgebase/configuring-wincc-v74-scada-with-scalance-xb205-snmp-opc-server) (low reliability; consistent with the S615 MIB file type)
- AA26-231A mitigations include "remove default SNMP community strings" and blocking TCP 102 at perimeter firewalls — [AA26-231A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-231a)
- CISA's advisory search shows a Siemens vendor facet with 38 entries and seven result pages for "Siemens SCALANCE", but the list did not render to the fetcher — [CISA advisories search](https://www.cisa.gov/news-events/cybersecurity-advisories?f%5B0%5D=advisory_type%3A95&search_api_fulltext=Siemens%20SCALANCE)

### Inferences
- Pull: SNMP (sysDescr/sysObjectID/ifTable plus private MSPS MIB), HTTPS WBM login + Load&Save download of RunningCLI/LogFile/MIB, and CLI over SSH/Telnet are all within PEAT's existing protocol code; effort small-medium. Firmware images are encrypted, so firmware pull is "store blob only".
- Parse: RunningCLI (text) and LogFile (ASCII) are easy parse targets mapping to users/roles, interfaces/VLANs/IPs, services (SNMP/HTTP/SSH/Telnet enable state) and events; effort small — but fixtures must be created on hardware or obtained from an operator, none were found publicly.
- Scan: no SCALANCE emulator exists; CI scan tests would use a generic SNMP simulator (e.g., snmpsim with a recorded SCALANCE walk) or an HTTP mock — Siemens-specific only if someone contributes a real SNMP walk capture. Scan logic itself (SNMP sysObjectID under Siemens enterprise OID, WBM HTTP banners) is small effort.
- SINEMA (Remote Connect / Server) was not researched (search budget); treat as out of scope.

### Gaps
- Exact XC-200 WBM Load&Save file list not read (only S615 and XM-400 TOC); likely identical family behavior but unverified.
- SCALANCE firmware download terms on SIOS (free with login?) not verified.
- Specific CISA/ProductCERT SCALANCE advisory IDs not captured.

---

## Candidate: SIPROTEC 5 relays and DIGSI 5 (plus DIGSI 4 .dex comparison)

### Takeaway
DIGSI 5 has no free edition found (Compact is a paid single-device license; Standard/Premium add IEC 61850 configurator and test suite; a "Premium Scientific" academic edition exists), its project/archive format was not confirmed from Siemens sources, and no device simulator was identified; the realistically parseable artifacts are IEC 61850 SCL XML exports and DIGSI 4 XML exports — generic XML work with low Siemens-specific payoff and no scan path without hardware.

### Cited Findings
- Siemens tender text: DIGSI 5 Compact is for "configuring and using individual SIPROTEC 5 protection devices" with "projects limited to a single device"; Standard removes the device limit and adds the IEC 61850 system configurator and CFC/single-line/device-configuration editors; Premium adds integrated test/startup sequences and flexible IEC 61850 engineering; each sold as single license on DVD/USB or download in 1/5/10 packs; no free or trial statement — [Siemens tender text DIGSI 5](https://ausschreibungstexte.siemens.com/tiplv/Data/English/Electrical_Distribution,_Industrial_Controls,_Building_Technologies/Energy_Automation_and_Smart_Grid_Products/Engineering_Tools_for_Protection/Engineering_tool_DIGSI_5/(LV_Q3FR3VYRA4YMD3NTZ84BCWA6DR))
- Siemens US product page: "Choose from Compact, Standard or Premium editions"; "DIGSI 5 Premium Scientific" for universities/research with a download ordering process; purchasing via SiePortal; no trial, simulator or file-format statements — [Siemens DIGSI 5 page](https://www.siemens.com/en-us/products/siprotec/digsi-5)
- DIGSI 5 imports/exports IEC 61850-6 SCL ICD/IID/CID/SCD/SSD/SED — [DirectIndustry listing](https://www.directindustry.com/prod/siemens-energy-automation-and-smart-grid/product-30064-1198697.html)
- DIGSI 4 XML export/import reflects the parameter-set structure; users export `.dex` to XML — [Siemens forum 837073](https://support.industry.siemens.com/tf/ww/en/post/837073/)
- Third-party (Qualys) lists DIGSI 5 exports as `.zip,.dz5` — [Qualys help (redirected)](https://qualysguard.qg2.apps.qualys.com/ics/help/assets/generating_a_project_file.htm) — unverified
- SIPROTEC 5 marketing page mentions SIPROTEC 5 Compact and the 7SX800 universal relay but lists no protocols, security features, simulators or sample files — [Siemens SIPROTEC 5 page](https://www.siemens.com/global/en/products/energy/energy-automation-and-smart-grid/protection-relays-and-control/siprotec-5.html)

### Inferences
- Parse: IEC 61850 SCL (ICD/CID/SCD) is a standard XML schema; a generic SCL parser would serve SIPROTEC 5 and other vendors (SEL, GE) and yield IED identity, IP configuration (Communication section), and data model — medium effort, but it is not Siemens-specific and fixtures would come from any IEC 61850 source (unverified availability). `.dz5` archives are unconfirmed and likely proprietary.
- Scan: SIPROTEC 5 Ethernet services (DIGSI 5 protocol, IEC 61850 MMS port 102, web/homepage) cannot be emulated by any free tool found; MMS port 102 overlaps with S7comm port detection and would need protocol disambiguation (ISO-TCP + MMS vs S7comm 0x32). Not CI-testable without hardware.
- Extension of existing PEAT SIPROTEC 4 support: add DIGSI 4 XML parameter export parsing (XML, documented) — small effort if a sample export can be obtained; `.dex` itself remains unverified binary.

### Gaps
- DIGSI 5 trial availability (if any), `.dz5` confirmation, SIPROTEC 5 protocol/port list and ProductCERT advisories not reached (search budget exhausted; Siemens pages are marketing-only).
- No public SIPROTEC 5 ICD/CID samples located.

---

## Candidate: Siemens Industrial Edge and SIMATIC IOT2050

### Takeaway
IOT2050 is the most "open" Siemens device — an MIT-licensed Debian/Isar BSP with a QEMU target you can build and boot headless — but it is a Linux gateway rather than an OT controller, so PEAT value is modest (generic Linux SSH pull); Industrial Edge is a licensed container platform with MIT sample apps on GitHub and no free virtual device found.

### Cited Findings
- `siemens/meta-iot2050` is MIT ("MIT – see COPYING.MIT"), an Isar/Debian board support package built with kas (`./kas-container build kas-iot2050-example.yml` -> `.wic` image); variants include minimal, example (with Node-RED and SSH, preconfigured `192.168.200.1/24` on `eno1`), A/B SWUpdate; Docker as optional fragment; a `kas-iot2050-qemu.yml` "Emulated target config" exists (eMMC install not available for QEMU); no prebuilt image linked on the page — [siemens/meta-iot2050](https://github.com/siemens/meta-iot2050)
- Siemens forum: IOT2050 supports two OS options, "Example Image" and "SIMATIC Industrial OS (IndOS)"; application examples are in the SIMATICmeetsLinux GitHub — [Siemens forum 1251782](https://support.industry.siemens.com/forum/ww/en/post/1251782)
- `industrial-edge` GitHub org (verified siemens.com, 80 repos) hosts MIT-licensed samples such as `S7-Connector-data-handling-getting-started`, `wincc-unified-on-IE`, `performance-insight-getting-started`, IEC 61850 connectivity examples; no free Industrial Edge Device/Virtual Device or developer image is mentioned — [github.com/industrial-edge](https://github.com/industrial-edge)
- S7-1500V runs as an Edge Runtime App on Industrial Edge Devices and Virtual Edge Devices managed by Industrial Edge Management — [Siemens virtual PLC slides](https://assets.new.siemens.com/siemens/assets/api/uuid:f8d80591-b51c-41eb-8bfb-dab025123374/virtuel-plc.pdf)

### Inferences
- IOT2050: scan (SSH/HTTP/Node-RED ports) and pull (Debian package list, network config, users via SSH) are CI-testable by building the QEMU image, but this duplicates generic Linux interrogation rather than vendor-specific OT parsing. Medium effort for the image build pipeline, low OT payoff. Parse: nothing vendor-specific beyond Debian files.
- Industrial Edge: not feasible without licenses; out of scope.

### Gaps
- No download of prebuilt IOT2050 example image confirmed (SIOS pages are JS-only).
- Industrial Edge Virtual Device trial terms not researched.

---

## Cross-cutting: security relevance (CISA / Siemens ProductCERT / notable research)

### Takeaway
Siemens S7 PLCs are the subject of an August 2026 joint NSA/CISA/FBI/DOE/EPA advisory on active adversary reconnaissance using python-snap7 and snap7.dll over S7comm — which both raises the priority of S7 support in PEAT and means PEAT's own S7 module will look exactly like the adversary tooling, so documentation and detection-friendliness matter; S7-1500 CPUs also carried a 2025 advisory with hundreds of Linux-subsystem CVEs.

### Cited Findings
- AA26-231A "Defending Against an Active Threat to Siemens S7 Series PLCs" (Aug 19, 2026; NSA, CISA, FBI, DOE, EPA): actors conduct reconnaissance/capability development against U.S. Siemens PLC installations using "AI-generated exploitation scripts disguised as legitimate OT monitoring tools" built on `snap7.dll` and `python-snap7` over S7comm; targets S7-200 (all), S7-300 (all incl. 314/315/317), S7-400 (all), S7-1200 (1211C-1217C), S7-1500 (all incl. F-series); sectors include Energy, Water, Chemical, Critical Manufacturing; indicators include TCP 102 scanning and "CPU property enumeration"; mitigations include inventorying all S7 PLCs, verifying firmware against a "gold copy" backup, enabling protection levels and know-how protection, blocking port 102 at the perimeter, removing default SNMP community strings, disabling unneeded web servers, and alerting on unauthorized PUT/GET — [CISA AA26-231A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-231a)
- ICSA-25-162-05 (June 12, 2025; republication of Siemens SSA-082556): SIMATIC/SIPLUS S7-1500 CPU 1518(F)-4 PN/DP MFP V3.1.5+, 63 CVEs in third-party components (OpenSSH, glibc, curl, OpenSSL, Linux kernel...), CVSS v4 8.7, no fix at publication; CISA no longer updates Siemens advisories after initial release — [CISA ICSA-25-162-05](https://www.cisa.gov/news-events/ics-advisories/icsa-25-162-05), [CISA June 12 2025 release](https://www.cisa.gov/news-events/alerts/2025/06/12/cisa-releases-ten-industrial-control-systems-advisories)
- Siemens SSA-082556 (published 2025-06-10, V1.7 updated 2026-10-13): "Vulnerabilities in the additional GNU/Linux subsystem of the SIMATIC S7-1500 CPU 1518(F)-4 PN/DP MFP V3.1.5", CVSS v3.1 10.0 / v4 8.7, roughly 316 distinct CVEs, remediation "Update to V3.1.6 or later" via SIOS entry 109478459 — [Siemens ProductCERT SSA-082556](https://cert-portal.siemens.com/productcert/html/ssa-082556.html)
- Canadian Cyber Centre summary of CISA advisories Feb 10-16, 2025 lists "Siemens SIMATIC S7-1500 CPU – multiple models, versions 3.1.0 to versions prior to V3.1.2" — [cyber.gc.ca AV25-085](https://cyber.gc.ca/en/alerts-advisories/control-systems-cisa-ics-security-advisories-av25-085)
- Rogue7 (Black Hat USA 2019) demonstrated rogue-engineering-station attacks on S7-1500 via reverse-engineered S7comm-plus cryptography, including stealth logic injection — [Rogue7 whitepaper](https://i.blackhat.com/USA-19/Thursday/us-19-Bitan-Rogue7-Rogue-Engineering-Station-Attacks-On-S7-Simatic-PLCs-wp.pdf)

### Inferences
- AA26-231A's mitigation list (inventory, gold-copy comparison, protection-level review, logic-change review) is essentially PEAT's mission statement for S7, which is a strong justification for prioritizing S7-300/400/1200/1500 over LOGO!, SCALANCE or SIPROTEC 5.
- Because adversaries use the same libraries, PEAT's S7 module should be clearly identifiable (e.g., distinctive client banner/behaviour where the protocol permits, and documentation for defenders) — a design consideration, not a blocker.

### Gaps
- SCALANCE, LOGO!, SIPROTEC 5 specific CISA/ProductCERT advisory IDs were not captured (search exhausted; CISA list pages do not render to the fetcher).

---

## Cross-cutting: legal and licensing caveats

### Takeaway
All candidate Python libraries are permissively licensed (python-snap7 MIT, s7commplus MIT, Snap7 LGPLv3, NetToPLCsim LGPLv3; Conpot GPLv2 for container-only use), so GPLv3 PEAT can depend on them; the open legal questions are (a) use of reverse-engineered S7comm-plus key material bundled in `s7commplus`, (b) redistribution of fixtures generated with Siemens trial software, and (c) Siemens EULAs for TIA Portal/PLCSIM Advanced trials, none of which were verified in Siemens text.

### Cited Findings
- python-snap7: MIT — [PyPI](https://pypi.org/project/python-snap7/); s7commplus: MIT, V1 SessionKey code "derived from HarpoS7 (MIT)", bundled legacy keys probed unless `allow_legacy_key_fallback=False` — [PyPI s7commplus](https://pypi.org/project/s7commplus/), [README](https://github.com/gijzelaerr/s7commplus); Snap7 C library: LGPLv3 — [SourceForge snap7](https://sourceforge.net/projects/snap7/); NetToPLCsim: LGPLv3 — [SourceForge nettoplcsim](https://sourceforge.net/projects/nettoplcsim/); Conpot: GPL-2.0 — [mushorg/conpot](https://github.com/mushorg/conpot); Siemens Web API client: MIT — [siemens/simatic-s7-webserver-api](https://github.com/siemens/simatic-s7-webserver-api); meta-iot2050: MIT — [siemens/meta-iot2050](https://github.com/siemens/meta-iot2050); S7Comm-Plus Wireshark plugin "appears to be GPLv2" — [wireshark-dev](https://lists.wireshark.org/archives/wireshark-dev/202108/msg00017.html)
- `simaticml-decoder` states its probe files are "not a distributable fixture corpus" and its PyPI page lists no license — [PyPI simaticml-decoder](https://pypi.org/project/simaticml-decoder/)
- PLCSIM Advanced trial is 21 days per the Siemens manual; third-party claims that the trial is "restricted to evaluation, lab, and educational use" are unverified — [PLCSIM Advanced manual](https://cache.industry.siemens.com/dl/files/578/109955578/att_1267815/v1/s7-plcsim_advanced_function_manual_en-US.pdf), [blog](https://industrialmonitordirect.com/blogs/knowledgebase/obtaining-siemens-step-7-and-s7-plcsim-advanced-trial-software)
- Rogue7 documents that the S7comm-plus session-key mechanism was reverse engineered from TIA/firmware — [Rogue7 whitepaper](https://i.blackhat.com/USA-19/Thursday/us-19-Bitan-Rogue7-Rogue-Engineering-Station-Attacks-On-S7-Simatic-PLCs-wp.pdf)

### Inferences
- Prefer the Web API (officially documented, Siemens-published MIT client) and classic S7comm (long-public, snap7) for shipped pull features; treat S7comm-plus via `s7commplus` as "scan/identity only" until counsel reviews the bundled-key question.
- Fixture provenance should be recorded (self-generated with trial software vs. operator-donated) and Siemens trial EULAs read before committing exports.

### Gaps
- TIA Portal / PLCSIM Advanced / LOGO! Soft Comfort EULA text not reviewed.
- SIOS download terms (registration, redistribution of application-example projects) not reviewed (JS-only portal).

---

## Per-candidate parse/scan feasibility without hardware, effort, and ranking inputs

### Takeaway
Only two Siemens candidates have a free, pip/Docker-installable, network-reachable emulator for CI scan tests: classic S7comm (python-snap7 server, plus Conpot) and S7comm-plus (s7commplus emulator); none has a confirmed redistributable public fixture corpus, so every parse target requires generating fixtures with 21-day Siemens trials (TIA Portal/Openness, PLCSIM Advanced) or operator-donated exports.

### Cited Findings
- Evidence for each row is cited in the sections above; key anchors: python-snap7 server identity/SZL behaviour ([PyPI](https://pypi.org/project/python-snap7/), local test), s7commplus emulator ([PyPI](https://pypi.org/project/s7commplus/)), Conpot s7comm.toml ([raw](https://raw.githubusercontent.com/mushorg/conpot/master/conpot/templates/default/s7comm.toml)), Web API ([manual p.169](https://manualslib.com/manual/1662475/Siemens-Simatic-S7-1500.html?page=169), [Siemens client](https://github.com/siemens/simatic-s7-webserver-api)), PLCSIM Advanced ([manual](https://cache.industry.siemens.com/dl/files/578/109955578/att_1267815/v1/s7-plcsim_advanced_function_manual_en-US.pdf)), Openness XML ([manual](https://docs.tia.siemens.cloud/r/en-us/v20/tia-portal-openness-api-for-automation-of-engineering-workflows)), SCALANCE Load&Save ([S615 manual](https://manualslib.com/manual/1933699/Siemens-Simatic-Net-Scalance-S615.html?page=123)), DIGSI 5 editions ([tender text](https://ausschreibungstexte.siemens.com/tiplv/Data/English/Electrical_Distribution,_Industrial_Controls,_Building_Technologies/Energy_Automation_and_Smart_Grid_Products/Engineering_Tools_for_Protection/Engineering_tool_DIGSI_5/(LV_Q3FR3VYRA4YMD3NTZ84BCWA6DR))), LOGO! ([Snap7 LOGO](https://snap7.sourceforge.net/logo.html)), IOT2050 ([meta-iot2050](https://github.com/siemens/meta-iot2050)), AA26-231A ([CISA](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-231a)).

### Inferences
Each row: SCAN without hardware? / PARSE without hardware? / notes / effort (small = days, medium = weeks, large = months).

1. SIMATIC S7-300/400 (classic S7comm, TCP 102) — SCAN: YES, CI-testable against python-snap7 3.x pure-Python server (SZL 0x0011/0x001C/0x0131/0x0232, block list, protection, state, clock) and against Conpot in Docker as a second responder. PARSE: PARTIAL — STEP 7 `.awl/.scl/.db` text sources are cheap to parse but no public fixture corpus was confirmed; MC7 uploaded blocks are binary (store only). PULL: identity/SZL/block list/block info/protection/clock verified against emulator; block upload only testable on hardware or via PLCSIM+NetToPLCsim (Windows). Fit: new protocol code (S7comm over ISO-TCP) but a tiny dependency (pure Python, MIT); AA26-231A makes it the highest security-relevance item. Effort: scan small; pull small-medium; text parse small-medium; MC7 decompile large (not recommended).
2. SIMATIC S7-1200/1500 via S7comm-plus — SCAN: YES, CI-testable with `s7commplus` `S7CommPlusServer` (V1/V2-TLS/V3; reports order number `6ES7 215-1AG40-0XB0` V4.2; 105-entry model table). PARSE: via TIA Openness XML (see row 4). PULL: DB/symbol browse and experimental block upload exist in the library but rely on reverse-engineered key material (legal review). Effort: scan small-medium; pull medium (plus legal review).
3. SIMATIC S7-1200/1500 Web API (HTTPS JSON-RPC `/api/jsonrpc`) and web server — SCAN: PARTIAL — HTTPS banner/`Api.Version`/`Api.Browse` probes can be unit-tested with mocked HTTP responses, but no live free emulator; PLCSIM Advanced (Windows, 21-day trial) is the only simulator with a working web server/Web API. PARSE: YES for JSON responses (fixtures recordable from PLCSIM Advanced within the trial). PULL: identity (`Modules.ReadIdentificationMaintenance`), program browse/read, backups, files — officially documented; fits PEAT `requests`. Effort: small-medium; fixture generation requires a Windows machine with the trial.
4. TIA Portal Openness XML (SimaticML blocks/tags/UDTs/HMI; AutomationML hardware) and STEP 7/TIA text sources — SCAN: N/A (parse-only). PARSE: YES in principle — open, documented XML; maps to PLCopen/ST, variables, hardware inventory, network interfaces; fixtures must be self-generated with the 21-day TIA trial (Windows) because no redistributable public corpus was found; `simaticml-decoder` (Python 3.11+, license unstated) shows LAD/FBD->SCL is tractable. Effort: medium (SimaticML LAD/FBD/SCL to PLCopen), small for tag tables/AML/.scl text. Project containers (.ap1x/.zap) — do not attempt.
5. SIMATIC HMI / WinCC — SCAN: NO free network-reachable runtime found. PARSE: PARTIAL via Openness HMI XML and OPC UA XML exports (same toolchain as row 4); runtime files not parseable. Effort: small once row 4 exists. Low priority.
6. LOGO! 8/9 — SCAN: WEAK — S7 over TSAP with no SZL identity; emulator would not model LOGO! specifics. PARSE: NO (.lsc unverified/proprietary; no fixtures). PULL: V-memory only. Effort: small but low value. Low priority.
7. SCALANCE X/XC/XM/S/M — SCAN: PARTIAL — SNMP/HTTP(S)/SSH/Telnet probes testable only against generic mocks (e.g., snmpsim with a donated walk), no Siemens emulator. PARSE: YES for `RunningCLI` (text config incl. users/roles) and `LogFile` (ASCII events) if samples are obtained — none public; Config/ConfigPack/Firmware are binary/encrypted (store only). PULL: fits existing PEAT stack (SNMP, HTTPS Load&Save, CLI). Effort: parse small, pull small-medium, scan small. Strong fit, fixture-blocked.
8. SIPROTEC 5 / DIGSI 5 — SCAN: NO (no simulator; DIGSI 5 is paid; MMS/DIGSI ports need hardware). PARSE: PARTIAL/GENERIC — IEC 61850 SCL XML (ICD/CID/SCD) and DIGSI 4 XML exports; `.dz5` unconfirmed. Effort: medium for a generic SCL parser; small for DIGSI 4 XML as an extension of existing SIPROTEC 4 support. Low Siemens-specific priority.
9. S7-1500V / S7-1500 Software Controller — SCAN/PULL: would reuse rows 2-3, but both runtimes are commercial (Industrial Edge Marketplace / IPC bundles); no free image. Not a CI asset.
10. IOT2050 / Industrial Edge — SCAN: YES via QEMU-built MIT Debian image (generic Linux services). PARSE: nothing vendor-specific. Effort: medium (image build pipeline), low OT payoff. Industrial Edge: out of scope (licensed).

Suggested priority for a PARSE+SCAN baseline: (1) S7-300/400 + S7-1200/1500 scan module using python-snap7 server and s7commplus emulator in CI, with identity/SZL pull; (2) TIA Openness XML/.scl parse module with self-generated fixtures; (3) S7-1500 Web API pull with recorded JSON fixtures; (4) SCALANCE pull/parse once RunningCLI/LogFile samples are donated; (5) everything else.

### Gaps
- No public, redistributable Siemens fixture corpus was confirmed for any format in this session; this is the single biggest risk for the PARSE baseline and should be the first follow-up (GitHub code search for `SW.Blocks.CompileUnit`, `.scl`/`.awl` repos, SCALANCE RunningCLI samples, IEC 61850 ICD samples) once search budget is available.
- Not verified: Web API minimum firmware and full current method list; whether python-snap7's server can serve block uploads for registered blocks; LOGO! demo terms; DIGSI 5 trial; SCALANCE/LOGO!/SIPROTEC 5 CISA advisory IDs; TIA project container internals; Siemens trial EULAs.
