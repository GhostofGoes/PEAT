"""
Tests for the vendored Schneider Electric MIB modules and their packaging.
"""

import ast
import shutil
from pathlib import Path

import pytest

import peat
from peat.modules.schneider.m340 import m340_snmp
from peat.protocols.snmp import SNMP

MIB_FILE = m340_snmp.SCHNEIDER_MIBS_DIR / "TFPRIVATE-MIB.py"
REPO_ROOT = Path(peat.__file__).resolve().parent.parent
SPEC_FILES = ["peat.spec", "sneakypeat.spec"]


def test_mibs_dir_contents():
    assert m340_snmp.SCHNEIDER_MIBS_DIR.is_dir()
    # Only compiled modules, no MIB source texts, and not a Python package
    assert sorted(p.name for p in m340_snmp.SCHNEIDER_MIBS_DIR.iterdir()) == ["TFPRIVATE-MIB.py"]


def test_mib_file_provenance_and_no_texts():
    text = MIB_FILE.read_text(encoding="utf-8")
    header = text[: text.index("if 'mibBuilder' not in globals()")]
    assert "SchneiderTFE_V03.01.mib" in header
    assert "c1f89c133b9eccb4a0204d2301a039bfbb4ed8fa84405ab53eddf4b9e3f65782" in header
    assert "Produced by pysmi-1.4.3" in header
    assert "WITHOUT MIB texts" in header
    assert "On host" not in header
    # DESCRIPTION texts and other MIB prose must not be included
    for forbidden in ["setDescription(", "setContactInfo(", "setOrganization(", "setReference("]:
        assert forbidden not in text


def test_mib_loads_and_defines_tables():
    snmp = SNMP(ip="192.0.2.10", mib_paths=[m340_snmp.SCHNEIDER_MIBS_DIR])
    assert snmp.load_mibs(m340_snmp.TFE_MIB) == [m340_snmp.TFE_MIB]
    builder = snmp.engine.getMibBuilder()
    expected = {
        "port502IpSecurityTable": "2.7",
        "port502ConnTable": "2.8",
        "ioScanDeviceTable": "3.6",
        "glbDataPubTable": "4.9",
        "glbDataSubTable": "4.10",
        "profileBandwidthDistTable": "7.8",
        "profileLedDisplayTable": "7.9",
        "profileTrapTable": "7.13",
        "emailTable": "9.1.1",
    }
    for name, arc in expected.items():
        (table,) = builder.importSymbols(m340_snmp.TFE_MIB, name)
        assert ".".join(str(x) for x in table.name) == f"{m340_snmp.TFE_ROOT}.{arc}"
    (scalar,) = builder.importSymbols(m340_snmp.TFE_MIB, "tfeMibVersionNumber")
    assert scalar.name == (1, 3, 6, 1, 4, 1, 3833, 1, 255, 1)


def _spec_mib_entries(spec_path: Path) -> list[tuple[Path, str]]:
    """Resolve the Schneider MIB data file entries of a PyInstaller spec file."""
    tree = ast.parse(spec_path.read_text(encoding="utf-8"))
    names = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id.startswith("schneider_mibs_"):
                if isinstance(node.value, ast.Constant):
                    names[target.id] = node.value.value
                else:  # os.path.join('..', 'peat', ...)
                    names[target.id] = [arg.value for arg in node.value.args]

    entries = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Tuple)
            and len(node.elts) == 2
            and isinstance(node.elts[1], ast.Name)
            and node.elts[1].id == "schneider_mibs_dst"
        ):
            join_args = node.elts[0].args
            src = spec_path.parent.joinpath(*names[join_args[0].id], join_args[1].value)
            entries.append((src.resolve(), names["schneider_mibs_dst"]))

    return entries


@pytest.mark.parametrize("spec_name", SPEC_FILES)
def test_pyinstaller_spec_includes_mibs(spec_name):
    spec_path = REPO_ROOT / "distribution" / spec_name
    entries = _spec_mib_entries(spec_path)
    assert entries, f"Schneider MIBs aren't included in {spec_name}"

    # Every compiled MIB module is included, at the path the code loads it from
    expected_dst = m340_snmp.SCHNEIDER_MIBS_DIR.relative_to(REPO_ROOT).as_posix()
    assert {src.name for src, _ in entries} == {
        p.name for p in m340_snmp.SCHNEIDER_MIBS_DIR.glob("*.py")
    }
    for src, dst in entries:
        assert src.is_file()
        assert src.parent == m340_snmp.SCHNEIDER_MIBS_DIR
        assert dst == expected_dst


def test_mib_loads_from_pyinstaller_layout(tmp_path, monkeypatch, fake_snmp_cls, json_data):
    """
    Emulate a PyInstaller bundle, where data files from the spec are extracted
    under sys._MEIPASS and module ``__file__`` paths point into the same tree.
    """
    (_, dst) = _spec_mib_entries(REPO_ROOT / "distribution" / "peat.spec")[0]
    bundle_mibs = tmp_path.joinpath(*dst.split("/"))
    bundle_mibs.mkdir(parents=True)
    shutil.copy2(MIB_FILE, bundle_mibs)

    # SCHNEIDER_MIBS_DIR is computed from the module's __file__, which is at
    # the same path relative to the bundle root in a PyInstaller executable.
    frozen_file = tmp_path / Path(m340_snmp.__file__).resolve().relative_to(REPO_ROOT)
    assert (frozen_file.parent.parent / "mibs").resolve() == bundle_mibs.resolve()

    monkeypatch.setattr(m340_snmp, "SCHNEIDER_MIBS_DIR", bundle_mibs.resolve())
    entries = json_data("m340_snmp_walk.json")["entries"]
    monkeypatch.setattr(
        m340_snmp, "SNMP", lambda *args, **kwargs: fake_snmp_cls(*args, entries=entries, **kwargs)
    )
    data = m340_snmp.pull_snmp("192.0.2.10")
    assert m340_snmp.TFE_MIB in data["mibs_loaded"]
    assert data["tfe"]["port502_messaging"]["port502Status"] == "operationnal"
