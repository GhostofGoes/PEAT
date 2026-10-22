# SEL RTAC test data sources

These are public SEL RTAC project exports, made with ACSELERATOR RTAC (SEL-5033).
Each tarball has the XML files of one project export, without changes, and the
license file(s) from the source repository. Only the XML files of each export are
included. Other files in the source folders (for example `.selaprj` IEC 61850
projects, `.hprb` HMI projects, `.exp` CODESYS exports and spreadsheets) are not.

All of the files have a license that permits redistribution. PEAT is GPL-3.0,
so the GPL-3.0 and LGPL-3.0 files are compatible with it.

| Tarball | Source | Commit | License | RTAC model, schema |
| ------- | ------ | ------ | ------- | ------------------ |
| `ephcc-microgrid-rtac.tar.gz` | [PowerSystemsHIL/EPHCC](https://github.com/PowerSystemsHIL/EPHCC/tree/2f0c93b2d7b899f9628781fbaab65033b997b37b/SimulationTools/RTAC) `SimulationTools/RTAC` | `2f0c93b2d7b899f9628781fbaab65033b997b37b` | MIT (Copyright 2016 Massachusetts Institute of Technology; folder `license.txt`: Copyright 2018 Alliance for Sustainable Energy, LLC) | 3530, schema 22 |
| `ephcc-iec61850-loopback-rtac.tar.gz` | [PowerSystemsHIL/EPHCC](https://github.com/PowerSystemsHIL/EPHCC/tree/2f0c93b2d7b899f9628781fbaab65033b997b37b/SimulationTools/RTAC_iec61850/RTAC_Loopback) `SimulationTools/RTAC_iec61850/RTAC_Loopback` | `2f0c93b2d7b899f9628781fbaab65033b997b37b` | MIT (same as above) | 3530, schema 22 |
| `pv-rtpp-rtac.tar.gz` | [mutito/PV-RTPP](https://github.com/mutito/PV-RTPP/tree/f62476a059be435889c1ff0bb5d4aa38a0ff399f/RTPP_CALC) `RTPP_CALC` | `f62476a059be435889c1ff0bb5d4aa38a0ff399f` | MIT (Copyright 2026 John K) | 3555, schema 36 |
| `iec-checker-selxml-rtac.tar.gz` | [iec-checker/iec-checker](https://github.com/iec-checker/iec-checker/tree/d3e5dae2c9b5096a197e4134d7d0549201f3a953/test/selxml) `test/selxml` | `d3e5dae2c9b5096a197e4134d7d0549201f3a953` | LGPL-3.0 | 3530, schema 32 |
| `cross-task-library-example-rtac.tar.gz` | [KupipiKuki/Cross-Task-Library-Example-RTAC](https://github.com/KupipiKuki/Cross-Task-Library-Example-RTAC/tree/ed8bb49ef5c9cd70a3eecdc17641e44035c917df) (whole repository) | `ed8bb49ef5c9cd70a3eecdc17641e44035c917df` | GPL-3.0 | 3530 (host name shows 3530-4), schema 33 |
| `pmu-data-corrector-rtac.tar.gz` | [dilanspsenaratne/PMUDataCorrector](https://github.com/dilanspsenaratne/PMUDataCorrector/tree/b52583ea16fbe18428c0c896db9eacfd835c2103/RTAC%20Implementation/RTAC_PMUDataCorrector_Library%20XML%20Files) `RTAC Implementation/RTAC_PMUDataCorrector_Library XML Files` | `b52583ea16fbe18428c0c896db9eacfd835c2103` | GPL-3.0 | 3555, schema 29 |

## What each export has

- `ephcc-microgrid`: a microgrid controller. 23 Modbus/TCP clients (circuit breakers
  and power electronics), 2 UDP access points, 19 IEC 61850 GOOSE subscriptions and
  1 GOOSE publication, 2 virtual tag lists for an HMI, Structured Text programs and
  data types, and a user library.
- `ephcc-iec61850-loopback`: GOOSE loopback test. 19 GOOSE subscriptions and 1
  publication, and the system items.
- `pv-rtpp`: only user logic (no `Project Info.xml` or system items). Function
  blocks, a program, a GVL and a data type, exported from a SEL-3555.
- `iec-checker-selxml`: small test programs for a static analyzer, with both a
  `SEL_RTAC` folder (`POU`) and a shared `POUs` folder (`LogicEngineObject`).
- `cross-task-library-example`: the only export with "Advanced Read-in Items"
  (`RTACBackupableObject`): the Ethernet interfaces (IP and MAC addresses) and
  the web server settings (host name). Also a visualization and a library manager.
- `pmu-data-corrector`: synchrophasor data. C37.118 clients and servers, C37.118
  tag lists, and a large Structured Text library, exported from a SEL-3555.

## Making the tarballs

The tarballs are reproducible. For each source folder, copy the `*.xml` files (keep
the folder structure) and the license file(s) into a folder named after the tarball,
then run:

```bash
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='2026-01-01 00:00Z' \
    --format=gnu -cf - <name> | gzip -9n > <name>-rtac.tar.gz
```

## Exports that were not included

These public RTAC exports have no license, so they can't be redistributed. They
were used only to check the parser locally.

- [Fluxara-co/loadshed](https://github.com/Fluxara-co/loadshed) `docs/RTAC GW Export`
  (3530 part number `DeviceMOT`, schema 18, DNP3 server, Network GVLs, POUs with
  `ArchivedContent`)
