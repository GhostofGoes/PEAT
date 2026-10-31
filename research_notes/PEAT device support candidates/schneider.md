# Schneider Electric OT Device Support Candidates for PEAT

Research notes evaluating Schneider Electric OT devices/software (beyond Modicon M340 and Sage RTUs) as candidates for new PEAT modules, achievable without purchasing hardware. Scope, criteria, and candidate list per assignment. Sections are organized around the four stated key questions, followed by one section per candidate cluster (each framed as its own evaluation question). The M340 and Sage modules are referenced only as a baseline.

Baseline facts pulled from the PEAT codebase itself (for the report writer's context; not re-evaluated):
- PEAT's M340 module already calls Modbus/TCP Function Code 43 to ID the device (`peat/modules/schneider/m340/m340.py` line ~213, "Method #1: Use Modbus/TCP Function Code 43 to ID the device"), and carries a full custom UMAS implementation in `umas_codes.py` (dict `UMAS_CODES` mapping 0x01 INIT_COMM, 0x02 READ_ID, 0x03 READ_PROJECT_INFO, 0x04 READ_PLC_INFO, 0x06 READ_CARD_INFO, 0x10/0x11 reservation, 0x20 READ_MEMORY_BLOCK, 0x22/0x23 READ/WRITE_VARIABLES, 0x24/0x25 READ/WRITE_COILS_REGISTERS, 0x30-0x35 upload/download, etc.) and `umas_packets.py`. There is also `peat/heat/umas_extractor.py`.
- PEAT docs (`docs/tcp_ip_protocols_used_by_peat.csv`) still reference a `peat.modules.schneider.ion.ion.ION` class using FTP(21), SSH(22), Telnet(23), HTTP(80), HTTPS(443), and a proprietary "ION" protocol on TCP 7700/7701/7702 ("Used for reading and updating device configuration, firmware updates, and general communications between ION Setup software and an ION meter. ION uses port 7700 by default, but can also use ports 7701 or 7702"). The Python code for this ION module is not in the open-source tree, confirming a prior internal ION module existed.

---

## Key Question 1: Does the Control Expert simulator expose UMAS over TCP/502 for regression-testing PEAT's M340 code, and is it free/trial?

### Takeaway
Yes. The EcoStruxure Control Expert (formerly Unity Pro) built-in PLC simulator listens on TCP/502 and speaks UMAS (Cisco Talos documented sending a full UMAS strategy-programming command sequence to the simulator), and Control Expert ships with a 30-day trial license. This is the single strongest finding: PEAT's existing M340 UMAS scan/pull code is very likely regression-testable against the free Control Expert simulator with no hardware, though the simulator is a Windows GUI app (not headless/Docker), so CI integration is manual.

### Cited Findings
- The Schneider Unity Pro / Control Expert PLC simulator, when started, opens `0.0.0.0:502` on the host (all interfaces, not just localhost) and accepts UMAS commands; "When the simulator mode is started, it opens 0.0.0.0:502 on the host, allowing for any supported UMAS command to be sent and executed by the system." Programming a strategy requires a specific six-command UMAS sequence beginning with a `TAKE_PLC_RESERVATION` request — confirming the simulator implements the UMAS reservation/session state machine, not just plain Modbus. — [Cisco Talos TALOS-2019-0771](https://talosintelligence.com/vulnerability_reports/TALOS-2019-0771)
- Schneider FAQ: when using the simulator the "IP address of the equipment is the IP address of the PC running the simulator," the PC must open TCP port 502, and if HMI and PLC simulation run on the same PC the address is 127.0.0.1. — [se.com FAQ000223132](https://www.se.com/au/en/faqs/FAQ000223132)
- Control Expert "comes with a 30 day trial license that is automatically activated during first launch"; "if you do not activate your license within 30 days, Control Expert will no longer run once the trial period has expired." — [se.com FA369070](https://www.se.com/us/en/faqs/FA369070)
- The installer (e.g. `Control_Expert_V16.2.iso`) is distributed from Schneider's download pages and requires a free Schneider account/login to download. — [se.com EcoStruxureControlExpert_V162](https://www.se.com/be/en/download/document/EcoStruxureControlExpert_V162)
- UMAS runs over Modbus/TCP 502 with Modbus function code 0x5A (90) marking the payload as UMAS; after the 0x5A byte comes a one-byte session key, then the UMAS function code. Research used Control Expert (Unity Pro) as the client against a physical M340 (the article does not itself use the simulator as the DUT, but confirms the wire protocol PEAT must match). — [Kaspersky ICS-CERT "Secrets of Schneider Electric's UMAS protocol"](https://ics-cert.kaspersky.com/publications/reports/2022/09/29/the-secrets-of-schneider-electrics-umas-protocol/)

### Inferences
- Because the Control Expert simulator implements the UMAS reservation handshake and runs on 502, PEAT's existing M340 scan + pull-logic code (INIT_COMM, READ_ID, READ_PLC_INFO, memory-block reads, upload) should be exercisable against it for regression tests covering M340/M580/Quantum/Premium (all Control Expert targets share the UMAS stack). Effort to stand up a test fixture: small (days), limited mainly by the simulator being a Windows GUI requiring manual start.
- The simulator is not a Docker/headless artifact, so it cannot run on PEAT's Linux/macOS GitHub Actions runners unattended. Realistic use is a developer running it on a Windows VM for manual regression, not automated CI. Treat the Talos finding as evidence the protocol surface exists, but confirm current V15.x/V16.x simulator still exposes 502 (the Talos report is from 2019 on "Unity Pro L"; Schneider may have hardened or firewalled it in later/secure versions).

### Gaps
- Not confirmed whether the simulator in a specific current version (V15.1+/V16.2) honors the newer "secure UMAS" authentication (M580 4.x) when simulating a secure CPU, or whether it only simulates legacy unauthenticated UMAS. Needs hands-on test.
- Could not confirm whether the 30-day trial fully enables the simulator (some Schneider trials disable download-to-hardware but keep the simulator — likely favorable here, but unverified for Control Expert specifically).

---

## Key Question 2: Are .XEF/.ZEF exports plain XML with a public schema, and where can sample projects be downloaded?

### Takeaway
.XEF is a documented plain-XML source export of a Control Expert project (ZEF is the same plus the global DTM configuration, and is also effectively a zipped/compressed XML archive). Schneider does not publish a formal XSD, but the format is officially described and sample `.xef` demo projects (Quantum and Premium) ship with Control Expert and are also attached to a public Schneider FAQ — usable as parse fixtures, subject to EULA.

### Cited Findings
- Control Expert has four formats: STU (default working file, not portable across versions), STA (compressed archive, ~50x smaller than STU, for forward compatibility/transfer), ZEF (export incl. global DTM configuration), and XEF (export "in an XML source format," excludes global DTM configuration). XEF and ZEF can be created at any project stage. — [se.com FAQ000259996](https://www.se.com/au/en/faqs/FAQ000259996)
- XEF "contains all unprotected project information: I/O configuration, sections, SR program modules, event processing, unprotected DFB types, DDTs, variables, animation tables, and references to protected DFB types." Authoritative format reference is the Schneider manual "EcoStruxure Control Expert - Operating Modes" (doc 33003101K01000), section "User Application and Project File Formats." — [se.com FAQ000259996](https://www.se.com/au/en/faqs/FAQ000259996)
- Control Expert install includes demo projects ("demounitypro...") in the default project path; a Schneider FAQ attaches the Control Expert V15.1 demos including two `.xef` files (a Quantum demo and a Premium demo). If prompted for a password on open, it is blank. Schneider states it does "not provide full application specific sample code" beyond these demos. — [se.com FA364303](https://www.se.com/be/en/faqs/FA364303)

### Inferences
- XEF being plain XML (text) means a parse-only PEAT module (device identity, firmware/CPU model, I/O module inventory, DDT/variable lists, program sections → PLCopen/Structured Text) is tractable and reuses PEAT's existing PLCopen TC6 XML generator. Effort: medium (weeks) to map the XEF schema to PEAT's normalized model; no hardware needed. ZEF is XEF-plus-DTM and likely a zip container, so unzip-then-parse.
- The bundled demos + FAQ-attached `.xef` files give immediate, legally-obtained parse fixtures (they come from Schneider's own installer/FAQ). Redistribution inside PEAT's test suite is the open legal question (see legal caveats); safest is to document how to obtain them rather than commit them.
- No public XSD means the schema must be reverse-engineered from sample XEFs — adds risk but is standard for PEAT's parse modules.

### Gaps
- No public XSD/DTD for XEF located; schema must be inferred from samples. Could not retrieve the actual XML structure of a `.xef` in this research (would require downloading a demo and inspecting).
- Whether ZEF is literally a ZIP of XML (vs a proprietary compressed container) is not confirmed by a primary source; STA is described as "very compressed" but its container format is unstated.

---

## Key Question 3: Is the ION protocol documented publicly enough to pull meter config, and is there an ION simulator?

### Takeaway
Partially. The ION architecture is documented in the public "ION Reference" manual (7EN02-0290), and ION meters also expose standard Modbus register maps (documented in each meter's user manual, exportable as CSV from ION Setup) plus FTP/Telnet/HTTP — all of which PEAT already has protocol support for. But the native ION protocol on TCP 7700-7702 is proprietary and not fully specified publicly, and no ION simulator was found. A PEAT ION module is most realistic via Modbus + FTP/HTTP rather than the native ION protocol. (Note: an internal ION module previously existed in PEAT.)

### Cited Findings
- The "ION Reference" manual is Schneider doc 7EN02-0290 (latest located: 7EN02-0290-12, 01/2023); it documents ION architecture and modules. A copy is publicly hosted (Sonepar CDN, Scribd). — [se.com FA355255](https://www.se.com/au/en/faqs/FA355255); mirror [7EN02-0290 PDF](https://res.cloudinary.com/sonepar-fr/raw/upload/s--o0SmDON0--/v1/documents/1887/7EN02-0290.pdf)
- ION meters' default Modbus register map is published in each meter's user manual under the "3rd party protocols" section; ION Setup lets you add custom Modbus registers (address 40001-41800) on the "Modbus Slave" tab and export the map as CSV. — [se.com ION Modbus FAQ FA210264](https://www.se.com/be/fr/faqs/FA210264)
- ION8650 product help lists protocol documents available for DNP 3.0, DLMS, Modicon Modbus, IEC 61850, and MV-90 ("each protocol document contains information explaining how the product interacts with a protocol"). — [product-help.schneider-electric.com ION8650](https://product-help.schneider-electric.com/PowerLogic-ION8650/en-us/content/01-overview/additional-information.htm)
- Security relevance (strong, for critical-infra ranking): CISA ICSA-23-229-03 (Aug 2023) covers PowerLogic ION8650/ION8800 — CVSS v3 8.8, cleartext transmission of sensitive info (CWE-319), "all versions" affected, remotely exploitable, low complexity. — [CISA ICSA-23-229-03](https://www.cisa.gov/news-events/ics-advisories/icsa-23-229-03)
- Schneider SEVD-2021-040-01 (PowerLogic power metering) covers ION7400/7650/8650; notes HTTP/Telnet web functionality can be disabled, "a mitigation does not exist for Telnet access" for some, ION7650 fixed in V415+. CVE-2021-22713 (buffer issue) affects ION8650 (<4.40.1) and ION7650 (<376). — [SEVD-2021-040-01 PDF](https://download.schneider-electric.com/doc/SEVD-2021-040-01/SEVD-2021-040-01_PowerLogic_Power_Metering_Security_Notification.pdf)
- ION meters expose FTP, Telnet, and a web server (confirmed by the above advisories referencing disabling Telnet/HTTP). ION Setup is Schneider's config tool; the public FAQs point to it but did not yield a confirmed free direct-download link or stated license cost in this research. — [se.com FA309352](https://www.se.com/ae/en/faqs/FA309352)

### Inferences
- A PEAT ION module is achievable without hardware primarily as: (1) scan/fingerprint via Modbus FC43 + ION's known ports; (2) pull config/registers via Modbus register map and FTP/HTTP (all already in PEAT's stack); (3) parse of CSV register-map exports or web/FTP config files. Native ION-protocol pull (7700-7702) would require reverse engineering with no simulator — high effort, low payoff given Modbus covers most config. Overall effort: medium for Modbus/FTP/HTTP pull+parse; large if native ION protocol is required.
- The prior internal PEAT ION module (ION HTTP, ION Telnet, ION parsing per the commented docs) suggests Sandia already prototyped the HTTP/Telnet path — reviving/re-implementing that is lower risk than the native protocol.
- Strong CISA/security relevance (metering is widespread in energy/utility infrastructure) makes ION a high-value target despite the proprietary native protocol.

### Gaps
- No ION protocol wire specification (7700-7702) found publicly; the "ION Reference" documents the data model/modules, not the socket protocol framing. No ION simulator/emulator found anywhere.
- Could not confirm whether ION Setup is free (vs requiring a license) or obtain a direct installer URL. No public sample `.ipf`/`.fwn`/`.ion` files located as parse fixtures.
- No existing open-source Python ION library found.

---

## Key Question 4: Is Machine Expert - Basic's .smbp a zipped XML that is simple to parse, and are sample projects available?

### Takeaway
Unconfirmed and likely not simple. The only sources describing `.smbp` internals are low-quality and say it is XML-based but with encrypted contents (garbled in a text editor), i.e. not a clean zip-of-XML. Machine Expert - Basic itself is a genuinely free download (unlike the CODESYS-based full Machine Expert). No reliable public `.smbp` sample projects were located, and the M221's programming protocol has documented authentication/encryption weaknesses (Claroty) but no open protocol spec.

### Cited Findings
- EcoStruxure Machine Expert - Basic (formerly SoMachine Basic) is distributed as a free installer zip (e.g. `MachineExpertBasic_V1.2_SP1.zip`); current versions include V1.3 (Apr 2024) and V1.4 (Nov 2025). — [se.com Machine Expert Basic V1.2 SP1](https://www.se.com/us/en/download/document/Machine_Expert_Basic_V1_2_SP1); [se.com V1.4](https://www.se.com/be/en/download/document/MachineExpertBasicV1_4/)
- Weak/unverified source claims `.smbp` is a SoMachine Basic project file that is XML-based but with encrypted contents, so it appears garbled in a text editor; legacy `.smbp` files can usually be imported after version check. Treat as unverified. — [mime-types.pages.dev .smbp](https://mime-types.pages.dev/file-extension/smbp)
- Claroty Team82 M221 research: attacker capturing traffic between M221 and Machine Expert - Basic could learn the device's authentication/encryption; precomputed rainbow tables can crack the Diffie-Hellman key exchange. CVEs: CVE-2020-7565 (inadequate encryption strength), CVE-2020-7566 (small space of random values / CWE-334, recoverable 4-byte XOR key), CVE-2020-7567 (missing encryption of sensitive data), CVE-2020-7568, CVE-2020-28214; Schneider advisory SEVD-2020-315-05 (covers M100/M200/M221). — [Claroty M221 research blog](https://claroty.com/2020/11/10/blog-research-schneider-m221-plcs/); [Claroty CVE-2020-7565/66/67/68/28214 dashboard](https://blog.claroty.com/team82/disclosure-dashboard/cve-2020-7565-cve-2020-7566-cve-2020-7567-cve-2020-7568cve-2020-28214)
- The M221 uses a UMAS-variant "Programming protocol"; Schneider mitigation guidance is to disable the unused Programming protocol in the M221 application. — [Claroty M221 research blog](https://claroty.com/2020/11/10/blog-research-schneider-m221-plcs/)

### Inferences
- If `.smbp` is encrypted (not merely zipped XML), a parse-only PEAT module is blocked unless the key/scheme is recovered — the Claroty work suggests the crypto is weak (4-byte XOR / small keyspace) but implementing a decryptor is non-trivial and legally sensitive (EULA anti-RE). Effort: medium-to-large and risky; downgrade priority relative to the XML-based Control Expert XEF path.
- M221 live pull over the Programming protocol is poorly documented publicly and the simulator path (Machine Expert - Basic has a simulator) is the better route to capture/understand traffic without hardware — but still requires reverse engineering. Realistic near-term PEAT function: scan/fingerprint only (Modbus FC43), unless `.smbp` decryption is solved.

### Gaps
- Could not confirm whether `.smbp` is a ZIP container (PK magic bytes) or a custom encrypted blob — needs a sample file inspected directly. No reliable public `.smbp` samples found.
- No open-source Python library for `.smbp` or the M221 protocol found.
- Machine Expert - Basic's own simulator and its trial/runtime terms not confirmed in detail.

---

## Candidate Cluster: Modicon M580 / Quantum / Premium / Momentum (UMAS family)

### Takeaway
These share the UMAS-over-Modbus/502 stack with the M340 that PEAT already implements, so they are the lowest-effort expansion — largely a matter of broadening identity/CPU parsing. The main complication is M580's "secure UMAS" (firmware 4.x) which adds client-side authentication; PEAT's existing unauthenticated UMAS code works against legacy/unsecured configs and the Control Expert simulator.

### Cited Findings
- M340 and M580 both use UMAS; M340 CPUs are BMXP34*, M580 CPUs are BMEP*/BMEH*. The protocol itself is the same; differences cited are only fix versions (M340 3.50, M580 4.10). UMAS session key: fixed 0x01 on M340 firmware <2.7, random 1-byte (256 values) on 2.7+. Application Password introduced M340 3.01; the secure handshake uses a client nonce, deterministic PLC nonce, SHA-256 over PLC-response+hash+client-nonce, then session ID used with UMAS function 0x38. — [Kaspersky ICS-CERT UMAS report](https://ics-cert.kaspersky.com/publications/reports/2022/09/29/the-secrets-of-schneider-electrics-umas-protocol/)
- Authentication-bypass CVEs: CVE-2020-28212 (bypass without Application Password — reuse/brute-force session key on 2.7+) and CVE-2021-22779 (bypass with Application Password, client-side secret + deterministic nonce). Fixed in M340 3.50 / M580 4.10 (Control Expert 15.1 updated alongside). — [Kaspersky ICS-CERT UMAS report](https://ics-cert.kaspersky.com/publications/reports/2022/09/29/the-secrets-of-schneider-electrics-umas-protocol/)
- M580 "secure" firmware message-integrity issue CVE-2023-6408 (CWE-924), with related CVE-2023-6409 (hard-coded credentials) and CVE-2023-27975; advisory SEVD-2024-044-01; some entries show fixed version <4.20. Separate Kaspersky-reported M340/M580 authentication-bypass-by-spoofing affects M580 firmware prior to 4.10. — [CVE-2023-6408 (circl)](https://cve.circl.lu/vuln/CVE-2023-6408); [SEVD-2024-044-01](https://www.se.com/ng/en/download/document/SEVD-2024-044-01/)
- Open-source UMAS tooling for reuse/validation: biero-el-corridor's "Wireshark-UMAS-Modicon-M340-protocol" dissector (Lua; ~18 stars, last updated ~3 years ago) and an accompanying Medium write-up using Scapy (Python) to craft UMAS packets (confirms UMAS = Modbus function 0x5A). — [GitHub biero-el-corridor Wireshark-UMAS](https://github.com/biero-el-corridor/Wireshark-UMAS-Modicon-M340-protocol); [Medium reverse of a Schneider protocol](https://medium.com/@biero-llagas/reverse-of-a-schneider-network-protocol-1e94980faa57)

### Inferences
- Adding M580/Quantum/Premium/Momentum scan+pull is small-to-medium effort: reuse PEAT's `umas_codes.py`/`umas_packets.py`, extend CPU-model/identity decoding and I/O-module inventory parsing per family. PEAT already ran against a Quantum 140 with partial success (per assignment), supporting the low-effort assessment.
- For M580 secure (4.x) with authentication enabled, pull would require implementing the nonce/SHA-256 handshake — medium effort and legally sensitive; but the unsecured path + simulator covers regression testing today.
- The Control Expert simulator (Key Question 1) can simulate these CPU families, giving a no-hardware test bed for all four.

### Gaps
- Momentum-specific UMAS behavior (older platform) not separately confirmed; it may differ from M340/M580.
- Whether PEAT's current code already handles random session keys (2.7+) vs only 0x01 not verified from code in this pass.

---

## Candidate Cluster: Machine Expert (CODESYS-based) for M241 / M251 / M258 / M262 / LMC

### Takeaway
These controllers run the CODESYS runtime and are programmed by EcoStruxure Machine Expert (not "- Basic"), whose projects are CODESYS `.project` files and whose toolchain includes a CODESYS soft-PLC simulator (CODESYS Control Win). This opens a potential CODESYS-generic path, but Machine Expert is a licensed product (trial), the `.project` format is a proprietary CODESYS container, and support/simulation of M262 specifically is inconsistently documented.

### Cited Findings
- Machine Expert simulation uses the CODESYS Control Win soft-PLC: start the Control Win systray controller, then the simulation; the simulator component installs separately from the IDE and depends on the CODESYS Gateway service. — [industrialmonitordirect Machine Expert Simulator guide](https://industrialmonitordirect.com/blogs/knowledgebase/ecostruxure-machine-expert-simulator-setup-and-usage-guide) (low-reliability third-party; verify)
- Sources conflict on simulator device coverage: one lists TM221/TM241/TM251/M258/LMC058 (no M262); Schneider's own FAQ (FAQ000239445) lists M262 as applicable but page body not retrieved. — [se.com FAQ000239445](https://www.se.com/us/en/faqs/FAQ000239445/)
- Schneider provides a general "FileFormatUtility Library" app guide for reading/writing XML in Machine Expert (not the `.project` format itself). — (noted in Machine Expert Basic search results, se.com)

### Inferences
- If PEAT ever targets CODESYS broadly, the M241/M251/M258/M262/LMC share the CODESYS runtime and a CODESYS-native pull path (the CODESYS runtime has documented services) could cover multiple vendors at once — strategically attractive but large effort.
- `.project` is a proprietary CODESYS binary/container (not plain XML), so a near-term parse module is low-value; the realistic near-term PEAT function is scan/fingerprint (Modbus FC43; these also often expose Modbus TCP and a web server). Effort for meaningful pull/parse: large.
- The CODESYS Control Win simulator is a Windows soft-PLC (not headless/Docker), same CI limitation as Control Expert.

### Gaps
- Machine Expert (full) trial terms, cost, and whether the simulator is included free not confirmed. `.project` internal format not confirmed. No confirmed public sample `.project` files. M262 simulator support unresolved (conflicting sources).

---

## Candidate Cluster: EcoStruxure Geo SCADA Expert (ClearSCADA)

### Takeaway
A strong parse/integration candidate: it is a widely deployed SCADA host in US water and oil & gas, offers a free trial download (full operation needs a purchased license), and exposes well-documented integration APIs (.NET Client API, COM Automation Interface, SOAP/XML web interface, ODBC) with GitHub code examples and Python access via Pythonnet. This is software, not a device — PEAT value is config/database export parsing and API-based pull on a running server.

### Cited Findings
- Geo SCADA Expert integration: .NET Client API is the preferred route (usable from C#/VB.NET, and from Python via Pythonnet), with a Client API Guide in the Start Menu and code examples on GitHub; also COM Automation Interface, SOAP/XML web interfaces, and ODBC (version 1 — some modern tools only speak ODBC v3 and may not connect). — [community.se.com Geo SCADA .NET API / Web Interfaces](https://community.se.com/t5/Geo-SCADA-Knowledge-Base/Net-API-Automation-Interface-and-Web-Interfaces-SOAP-and-XML/ba-p/279096)
- Latest Geo SCADA Expert is a free download from the Schneider Exchange Shop; a purchased license is needed to run the server in full operation (i.e. a free trial exists). Downloads are on the Geo SCADA Knowledge Base. — [community.se.com Geo SCADA downloads blog](https://community.se.com/t5/Remote-Operations-Blog/EcoStruxure-Geo-SCADA-Expert-downloads-on-SE-Exchange-Shop-amp/ba-p/265919)
- Client DLL officially supports .NET Framework 4.8 (a later fix tested with 4.8 and .NET 7). — [community.se.com .NET Core thread](https://community.se.com/t5/EcoStruxure-Geo-SCADA-Expert/FYI-Applications-built-on-Net-Core-worked-with-Geo-SCADA-2019/td-p/437868)

### Inferences
- PEAT could pull live config/points/users via the .NET Client API (through Pythonnet) or ODBC, and parse database/config exports — a medium-effort module, Windows-centric. The free trial makes a no-hardware dev environment feasible.
- Prevalence in US water/oil&gas makes it security-relevant; the documented APIs reduce reverse-engineering risk versus proprietary device protocols.
- The Windows/.NET dependency clashes with PEAT's cross-platform Linux/macOS CI — pull would realistically run only on Windows.

### Gaps
- Exact database export file formats (e.g. configuration export schema) not pinned to a primary source in this pass. No public REST API confirmed (SOAP/XML and .NET/ODBC are the documented surfaces). Prevalence claim ("US water/oil&gas") is widely held industry knowledge but not cited to a specific authoritative figure here.

---

## Candidate Cluster: SCADAPack 300E/470/474/570/575 RTUs + RemoteConnect / Workbench

### Takeaway
Moderate candidate. The x70 RTUs (470/474/570/575) are CODESYS/IEC 61131 and are configured with RemoteConnect (which bundles Control Expert); the older E-series (300E etc.) use SCADAPack E Workbench. Configuration software is freely downloadable from Schneider, the RTUs speak DNP3 and Modbus, but no simulator was found and project/config formats are undocumented publicly.

### Cited Findings
- RemoteConnect for SCADAPack x70 is a free Schneider download that bundles RemoteConnect + x70 Utilities + x70 Extensions Library + EcoStruxure Control Expert; latest listed version 3.5.3 (Feb 2026). RemoteConnect targets the 57x/47x RTUs; E-series use Workbench. — [community.se.com RemoteConnect 2.7.3 blog](https://community.se.com/t5/Remote-Operations-Blog/RemoteConnect-2-7-3-for-SCADAPack-x70-Smart-RTUs-now-available/ba-p/399408); [se.com FAQ000272686 download list](https://www.se.com/ae/en/faqs/FAQ000272686/)
- SCADAPack E Workbench "no longer requires a license to run" but "still requires a license for the legal right to be used." — [community.se.com SCADAPack E Workbench blog](https://community.se.com/t5/Remote-Operations-Blog/SCADAPack-E-Workbench-and-Utilities-8-18-1-now-available-for/ba-p/268945)
- Full Remote Operations download list (SCADAPack x70, RemoteConnect, E Workbench, Realflo, Telepace Studio, Trio TVIEW+, etc.) is published by Schneider. — [se.com FAQ000272686](https://www.se.com/ae/en/faqs/FAQ000272686/)

### Inferences
- Because RemoteConnect embeds Control Expert and the x70 line is CODESYS-based, the x70 RTUs likely share the UMAS and/or CODESYS surfaces already discussed — a scan/fingerprint module (Modbus FC43, DNP3, Modbus) is small effort; config pull/parse is medium-large and undocumented.
- DNP3 is a notable gap in PEAT's current stack (assignment lists Modbus/UMAS/FTP/SNMP/etc. but not DNP3); supporting SCADAPack pull over DNP3 would be new protocol work.

### Gaps
- No simulator/emulator for any SCADAPack found. Project/config file formats (RemoteConnect `.*`, Workbench) not documented publicly. No sample files or Python libraries found. 300E vs x70 tooling split needs confirming per model.

---

## Candidate Cluster: Easergy / MiCOM P-series relays + Sepam + T300 (protection relays)

### Takeaway
Moderate parse-oriented candidate. Protection relays (MiCOM P14x/P44x/P64x) use the Courier protocol (documented in relay technical manuals, with deeper specs on request) and MiCOM S1 Agile / Easergy Studio settings software producing `.set` settings files and IEC 61850 SCL exports; Sepam uses SFT2841. The ecosystem is now split between Schneider and GE Vernova (which acquired the MiCOM/Grid line), complicating sourcing. IEC 61850 SCL (standardized XML) is the most parse-friendly artifact.

### Cited Findings
- MiCOM settings files are `.set` files produced by MiCOM S1 Agile (the P40 Agile settings application); a sample settings report (P94VP) includes Courier rear-port comms settings, confirming `.set` files carry communication config. Easergy Studio is used to convert settings files between MiCOM generations (Px2x/Px3x/Px4x). — [se.com FA221098 (convert MiCOM settings)](https://www.se.com/us/en/faqs/FA221098/)
- Courier protocol: documented as a chapter in each relay's technical manual ("enough detail for most users"); deeper protocol documents R6511/R6512 available on request; "detailed protocol mappings, semantics, profiles and interoperability tables are not provided within this manual — separate documents are available per protocol." P40 Agile technical manuals (with Courier chapters) are published by GE Vernova. — [GE Vernova P345 technical manual PDF](https://www.gevernova.com/grid-solutions/products/manuals/P345-AD-EN-1.pdf); [GE Vernova P14x technical manual PDF](https://www.gevernova.com/electrification/sites/default/files/2026-08/P14x-VH-EN-3.5.pdf)

### Inferences
- The highest-value, lowest-risk PEAT path here is parsing IEC 61850 SCL exports (CID/ICD/SCD — standardized XML) and `.set` settings reports, giving device identity, comms settings, and configuration without hardware. Effort: medium. Courier (serial/Modbus-family) live pull is possible but less documented and PEAT's serial path would be exercised.
- The Schneider↔GE Vernova split means authoritative manuals and the free Easergy Studio/MiCOM S1 Agile software are partly on GE Vernova's site now — a sourcing (not technical) complication.
- Relays are highly security-relevant (transmission/distribution protection) — good ranking value — but PEAT already has SEL relay modules, so Schneider relays may be lower marginal priority.

### Gaps
- Whether Easergy Studio / MiCOM S1 Agile is free and where to download it now (Schneider vs GE Vernova) not confirmed. `.set` file internal format (binary vs text) not confirmed. No public sample `.set`/SCL files located. Sepam/SFT2841 and Easergy T300 not researched in depth. No Python Courier library found.

---

## Candidate Cluster: Modbus FC43 (Read Device Identification) fingerprinting of Schneider devices

### Takeaway
Low-effort, high-coverage win. Modbus function 43/14 (0x2B/0x0E) Read Device Identification is a standard, documented request returning vendor/product/version objects; many Schneider devices implement it, and PEAT's M340 module already issues FC43. A generic Schneider (even generic Modbus) FC43 fingerprinting scan could cheaply fingerprint the whole Modbus-speaking Schneider fleet, and pymodbus/other OSS libraries already implement the call.

### Cited Findings
- Read Device Identification is Modbus function code 43 / MEI type 14 (0x2B / 0x0E); object 0x00 = VendorName (mandatory), with ProductCode/version objects following; "not all Modbus devices support this function." — [control.com forum: Modbus device info](https://control.com/forums/threads/is-there-a-way-to-send-device-info-over-modbus.30891/post-30891); [Brooks Automation Modbus ReadDeviceID](https://www2.brooksautomation.com/Controller_Software/Software_Reference/GPL_Dictionary/Modbus/mb_readdeviceid.htm)
- Schneider explicitly implements FC43: BMENOC modules "return vendor name, product name, and version through function code 43." — [se.com FA406524](https://www.se.com/th/en/faqs/FA406524)
- Open-source implementations exist to reuse/validate (e.g. AMWD.Protocols.Modbus implemented 0x2B/43 for TCP, defining VendorName as object 0x00 mandatory). pymodbus exposes device-information request/response classes (search its source for "ReadDeviceInformationRequest"). — [AMWD.Protocols.Modbus commit](https://gitea.am-wd.de/am-wd/AMWD.Protocols.Modbus/commit/24f7cc74a704dde8dab900e2c14c255008774400)

### Inferences
- PEAT's existing FC43 code in the M340 module is reusable as a generic Schneider (or vendor-agnostic) Modbus fingerprinting scan feature — effort: small (days). This is the cheapest way to broaden Schneider device coverage at the scan level across M580/Quantum/Premium/SCADAPack/ION/Easergy that implement Modbus.

### Gaps
- Which specific Schneider product families return which FC43 objects (and whether identity strings are distinctive enough to classify model) not enumerated. The 0x0E vs "MEI type 13" discrepancy in one source should be resolved against the Modbus Application Protocol spec (0x0E/14 is correct).

---

## Candidate Cluster: Simulators summary (cross-cutting)

### Takeaway
The Control Expert simulator is the one high-confidence, free, UMAS-speaking simulator usable to regression-test PEAT's M340/UMAS code without hardware; all other Schneider simulators are either absent (ION, SCADAPack, relays) or Windows soft-PLCs (CODESYS Control Win for Machine Expert) unsuitable for headless CI.

### Cited Findings
- Control Expert / Unity Pro simulator listens on 0.0.0.0:502 and speaks UMAS. — [Cisco Talos TALOS-2019-0771](https://talosintelligence.com/vulnerability_reports/TALOS-2019-0771)
- Machine Expert simulation uses CODESYS Control Win soft-PLC (Windows, separate install, needs CODESYS Gateway). — [industrialmonitordirect Machine Expert Simulator guide](https://industrialmonitordirect.com/blogs/knowledgebase/ecostruxure-machine-expert-simulator-setup-and-usage-guide) (low reliability)
- Generic Modbus-TCP server simulators that can publish arbitrary identity (and could be scripted to answer FC43 with Schneider-like strings) exist in the market but none are confirmed to replay UMAS. — [industrialmonitordirect Modbus server simulator MSS](https://industrialmonitordirect.com/blogs/knowledgebase/modbus-tcp-server-simulator-mss-v10-review-and-configuration-guide) (low reliability)

### Inferences
- For CI, PEAT's realistic options are: (1) a generic Modbus simulator scripted to answer FC43 for scan-level tests (any OS, scriptable — good for Linux/macOS runners); (2) a lightweight homemade UMAS responder (PEAT could build one from its own `umas_packets.py` to self-test without Schneider software); (3) the Control Expert simulator on a Windows VM for high-fidelity manual regression.
- No Docker images of any Schneider simulator were found.

### Gaps
- No confirmed Docker/headless Schneider simulator. Whether current Control Expert versions still expose 502 unauthenticated (post-2019 hardening) needs hands-on verification.

---

## Cross-cutting: Legal caveats (criterion h)

### Takeaway
Schneider software is under EULAs that typically prohibit reverse engineering, and sample projects/manuals are copyrighted — so PEAT should favor documented formats/APIs and avoid redistributing Schneider sample files or decompiling.

### Cited Findings
- Control Expert, Machine Expert, ION Setup, Geo SCADA, RemoteConnect are all licensed Schneider products requiring account login to download; Geo SCADA full operation and SCADAPack E Workbench explicitly require purchased licenses for legal use. — [community.se.com Geo SCADA downloads](https://community.se.com/t5/Remote-Operations-Blog/EcoStruxure-Geo-SCADA-Expert-downloads-on-SE-Exchange-Shop-amp/ba-p/265919); [community.se.com SCADAPack E Workbench](https://community.se.com/t5/Remote-Operations-Blog/SCADAPack-E-Workbench-and-Utilities-8-18-1-now-available-for/ba-p/268945)

### Inferences
- Parse modules built from documented formats (XEF XML, IEC 61850 SCL, Modbus register-map CSV, FC43) and APIs (Geo SCADA .NET/ODBC) are on firm legal footing. Decrypting `.smbp` or reverse-engineering the native ION protocol carries anti-RE EULA risk and should be flagged. PEAT's test suite should reference how to obtain Schneider demo files rather than redistributing them.

### Gaps
- Exact EULA clause text for each product not quoted (not retrieved in this pass); the report writer should treat anti-RE/no-redistribution as the conservative default.

---

## Overall synthesis for the report writer (PARSE + SCAN baseline ranking)

Per the maintainer's clarification, the baseline for a new module is PARSE + SCAN, weighted most heavily on (1) redistributable sample vendor files to build/test a parser, and (2) a free, network-reachable simulator/soft-runtime answering on real TCP/UDP ports so a scan/fingerprint can be tested in CI without hardware. PARSE and SCAN feasibility (no hardware) are stated explicitly for every candidate below.

### Key cross-cutting constraints for scan-in-CI
- No Schneider vendor simulator is headless/Docker; the Control Expert and CODESYS Control Win simulators are Windows GUI apps that open real ports (502) but cannot run on PEAT's Linux/macOS GitHub Actions runners unattended. — [Cisco Talos TALOS-2019-0771](https://talosintelligence.com/vulnerability_reports/TALOS-2019-0771)
- The realistic CI scan path is therefore a generic, scriptable Modbus-TCP simulator answering FC43 (0x2B/0x0E) with Schneider-like identity strings, and/or a small PEAT-built UMAS responder derived from PEAT's own `umas_packets.py`. Modbus FC43 is a documented standard that Schneider devices implement. — [se.com FA406524 (BMENOC returns identity via FC43)](https://www.se.com/th/en/faqs/FA406524); [AMWD.Protocols.Modbus FC43 impl](https://gitea.am-wd.de/am-wd/AMWD.Protocols.Modbus/commit/24f7cc74a704dde8dab900e2c14c255008774400)
- On redistributable fixtures: Schneider demo/sample files (e.g. the `.xef` demos) are downloadable but Schneider-copyrighted, so committing them into PEAT's repo is legally questionable; IEC 61850 SCL (ICD/CID/SCD) is a vendor-neutral XML standard with sample files circulating in open-source repos, making it the most redistribution-friendly fixture source. (Redistribution terms not confirmed per file — treat as restricted unless a file's own license says otherwise.)

### Per-candidate PARSE / SCAN feasibility without hardware

| Candidate | PARSE w/o hardware? | SCAN w/o hardware (CI)? | Redistributable sample files? | Free CI-reachable simulator? |
|---|---|---|---|---|
| **M580 / Quantum / Premium / Momentum** | Yes — via Control Expert XEF (XML) export, same format as M340; reuses PEAT PLCopen generator | Yes — reuse existing UMAS/FC43 code; CI-testable via generic Modbus FC43 sim or PEAT-built UMAS responder; high-fidelity only on Windows Control Expert sim | Demo `.xef` ship w/ Control Expert + public FAQ, but Schneider-copyrighted (restricted) | Control Expert sim (502/UMAS, Windows GUI, not headless); generic Modbus sim works for FC43 scan in CI |
| **Modbus FC43 generic Schneider fingerprint** | N/A (scan feature) | Yes — strongest CI story; scriptable Modbus sim answers on 502, cross-platform | N/A | Yes — any OSS Modbus-TCP server, scriptable, runs on Linux/macOS CI |
| **Control Expert XEF parse (all UMAS CPUs)** | Yes — plain XML, documented | (covered by UMAS row) | Demo `.xef` downloadable, Schneider-copyrighted (restricted) | n/a for parse |
| **Easergy / MiCOM relays** | Yes — IEC 61850 SCL (standard XML) and `.set` reports | Partial — relays expose HTTP/IEC 61850/Courier; no free simulator found, so scan not CI-testable without hardware unless a generic IEC 61850 server is used | SCL samples broadly available (vendor-neutral); Schneider `.set` samples not located/restricted | No Schneider relay simulator found; generic IEC 61850 server (e.g. libIEC61850) could stand in |
| **Geo SCADA Expert (ClearSCADA)** | Partial — documented config/DB exports via ODBC/.NET; exact export file schema unconfirmed | Yes but Windows-only — free trial server listens on real ports; not headless Linux CI | No public sample DB/config exports found | Free trial server (Windows), real ports, not Linux CI |
| **ION power meters** | Partial — parse Modbus register-map CSV / web/FTP config; no `.ipf`/`.ion` samples found | Yes for Modbus/FC43 fingerprint via generic Modbus sim; native ION 7700-7702 scan not CI-testable (no sim) | No public ION sample files found | No ION simulator found; generic Modbus sim covers Modbus-level scan only |
| **M221 / Machine Expert - Basic `.smbp`** | Blocked/hard — `.smbp` likely encrypted (unverified), anti-RE EULA risk | Partial — Modbus FC43 scan CI-testable via generic sim; Machine Expert-Basic has a Windows sim (not headless) | No public `.smbp` samples found | Machine Expert-Basic sim (Windows, not headless) |
| **M241/M251/M258/M262/LMC (CODESYS Machine Expert)** | Hard — `.project` is proprietary CODESYS container (not plain XML) | Partial — Modbus FC43 scan CI-testable via generic sim; CODESYS Control Win sim is Windows soft-PLC (not headless) | No public `.project` samples found | CODESYS Control Win (Windows soft-PLC, not headless) |
| **SCADAPack 300E/470/474/570/575** | Hard — RemoteConnect/Workbench project formats undocumented | Partial — Modbus FC43 scan CI-testable; DNP3 scan is new protocol work for PEAT; no simulator | No public samples found | No SCADAPack simulator found |

### Recommended shortlist under the new weighting
1. **Generic Schneider Modbus FC43 fingerprint scan** — best CI scan story (scriptable cross-platform Modbus sim, reuses PEAT's existing FC43), small effort. Scan: yes in CI. (No parser; it is a scan primitive that benefits every Modbus-speaking Schneider device.)
2. **M580/Quantum/Premium/Momentum** — parse via XEF XML (reuses M340 code/PLCopen generator) and scan via existing UMAS/FC43 testable in CI with a generic Modbus/UMAS responder. Both parse and scan achievable without hardware; only caveat is sample-`.xef` redistribution (restricted) — mitigate by shipping a tiny hand-authored/synthetic XEF fixture or documenting how to obtain the demo.
3. **Easergy/MiCOM relays (parse-first)** — IEC 61850 SCL is the most redistribution-friendly fixture (vendor-neutral XML, OSS samples exist); parse achievable without hardware. Scan weaker (no free Schneider relay simulator). Security-critical, though PEAT already has SEL relays.
4. **ION meters** — parse achievable via Modbus register-map CSV / web config (prior PEAT ION module existed); scan achievable only at Modbus level in CI; no redistributable samples found and no simulator — ranks below the above on both weighted criteria despite strong CISA relevance.
5. **Geo SCADA Expert** — parse+scan both achievable but Windows/.NET-only (not Linux CI) and no public sample exports — strong product relevance, weak on both weighted criteria.
6. **Lowest on new criteria:** M221/`.smbp` (likely-encrypted format, no samples), M241/M262 `.project` (proprietary, no samples), SCADAPack (undocumented formats, no samples, no simulator) — all fail criterion (1) redistributable samples and lack a CI-reachable simulator beyond generic Modbus FC43 scan.
