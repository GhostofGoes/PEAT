# PEAT in a SCEPTRE (phenix) experiment

Files for the documentation tutorial *Virtual RTUs in a SCEPTRE (phenix) experiment*
(`docs/tutorials/sceptre_phenix.rst`):

- `peat-bennu-topology.yaml`: phenix topology with two bennu DNP3 RTUs, a PyPower
  provider, and a PEAT workstation VM
- `peat-bennu-scenario.yaml`: phenix scenario applying the `sceptre` app to those nodes
- `peat-bennu.yaml`: the PEAT configuration injected into the workstation VM

Copy the directory to `/phenix/topologies/peat-bennu/` on the phenix host; the tutorial
explains the rest. See https://phenix.sceptre.dev/ for phenix itself.
