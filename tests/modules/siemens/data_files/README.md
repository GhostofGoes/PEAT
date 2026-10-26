# Siemens S7 test files

Public example files used to test the parsers in `peat/modules/siemens/s7_parse.py`.
The files are unmodified copies from the open source projects listed below (only
renamed where noted), and remain under the licenses of those projects.

| Directory | Source project | Commit | License | Files |
| --- | --- | --- | --- | --- |
| `dotnetsiemensplctoolboxlibrary/` | [dotnetprojects/DotNetSiemensPLCToolBoxLibrary](https://github.com/dotnetprojects/DotNetSiemensPLCToolBoxLibrary) | `77999b3` | LGPL-2.1 | `ToolBoxLibUnitTests/S7Blocks/UnitTest Simatic Project.zip` (renamed to `UnitTest_Simatic_Project.zip`), a STEP 7 V5.x project archive. `ToolBoxLibUnitTests/S7Blocks/TestProjekt.zap19`, a TIA Portal V19 project archive with a CPU 1515-2 PN. |
| `codegeneratoropenness/` | [mking2203/CodeGeneratorOpenness](https://github.com/mking2203/CodeGeneratorOpenness) | `7ceff73` | GPL-3.0 | `Sample/plcBlock_LAD_Block_Logic.xml` (TIA Portal V16 LAD FB) and `Sample/GraphJump.xml` (TIA Portal V14 SP1 GRAPH FB), Openness XML exports. |
| `tia-portal-openness-mcp/` | [1748477582/tia-portal-openness-mcp](https://github.com/1748477582/tia-portal-openness-mcp) | `a41d931` | MIT (see `LICENSE`) | `templates/mcp-full-e2e-verify/plc/blocks/MCPVerify_FC_SCL_E2E.xml` (SCL FC), `templates/plc/block-xml/DB_HMI_Interface.xml` (global DB), and `templates/mcp-full-e2e-verify/import/MCP_E2E_Tags.xml` (PLC tag table), TIA Portal V21 Openness XML. |
| `step7-classic-algorithms/` | [LeoSunSET/SIEMENS_SIMATIC_STEP7_Classic_Algorithms](https://github.com/LeoSunSET/SIEMENS_SIMATIC_STEP7_Classic_Algorithms) | `2a2a950` | MIT (see `LICENSE`) | `support_functions/timers/TON_D_ms.awl`, a STEP 7 V5.x STL source. |
| `awlsim/` | [mbuesch/awlsim](https://github.com/mbuesch/awlsim) | `1443360` | GPL-2.0-or-later | `tests/tc999_projects/trafficlights_2.awl` (STL source) and `tests/tc999_projects/trafficlights_2.asc` (STEP 7 symbol table export). |
| `s7-plc-snippets/` | [thomas-v2/S7-PLC-Snippets](https://github.com/thomas-v2/S7-PLC-Snippets) | `a869c92` | LGPL-3.0 | `TIA-Put-Get-OUC/GET_OUC.scl` (TIA Portal SCL source) and `Step7-Formelparser-SCL/Globaldaten.scl` (STEP 7 V5.x SCL source with a DB and UDT). |

All of these licenses are compatible with redistribution alongside PEAT (GPL-3.0).
