from types import SimpleNamespace

import pytest

from peat import DeviceData, config
from peat.modules.schneider.m340.m340 import M340


@pytest.mark.parametrize(
    "proj_name",
    ["/../../../../escape_m340", "../../escape_m340", "..\\..\\escape_m340", ".."],
)
def test_generate_openplc_project_contained(mocker, tmp_path, proj_name):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path / "results" / "devices"})
    dev = DeviceData(ip="10.0.0.1")
    dev._runtime_options["m340"] = {"generate_openplc_project": "dev_out_dir"}
    # The project name is parsed from the (untrusted) project file
    dev.logic.name = proj_name
    dev.logic.formats["tc6"] = "<project/>"
    dev._cache["tc6"] = SimpleNamespace(
        main_pou=SimpleNamespace(find=lambda _: "body"), element_empty=lambda _: False
    )

    proj_path = M340.generate_openplc_project(dev)

    dev_dir = dev.get_out_dir().resolve()
    assert proj_path is not None
    assert proj_path.resolve().parent == dev_dir
    assert proj_path.name.startswith("openplc_project_")
    written = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*.xml"))
    assert len(written) == 2
    assert all(dev_dir in (tmp_path / p).resolve().parents for p in written)
