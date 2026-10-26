import importlib.util
import json
import sys
from pathlib import Path
from unittest import mock

import pytest

from peat import DeviceData, DeviceModule, IPMethod, datastore, module_api

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES_DIR = REPO_ROOT / "examples"
AWESOME_MODULE = EXAMPLES_DIR / "example_peat_module" / "awesome_module.py"
AWESOME_OUTPUT = EXAMPLES_DIR / "example_peat_module" / "awesome_output.json"
SCEPTRE_CONFIG = EXAMPLES_DIR / "devices" / "sceptre" / "ep" / "dnp3-server.xml"


def _load_script():
    # Register before executing, since dataclasses look up their module
    spec = importlib.util.spec_from_file_location(
        "check_module", REPO_ROOT / "scripts" / "check_module.py"
    )
    script = importlib.util.module_from_spec(spec)
    sys.modules["check_module"] = script
    spec.loader.exec_module(script)
    return script


check_module = _load_script()


@pytest.fixture(autouse=True)
def _isolate(mocker, monkeypatch):
    # The script imports modules and parses files like PEAT does,
    # so keep that from changing what other tests see
    mocker.patch.object(module_api, "modules", dict(module_api.modules))
    mocker.patch.object(
        module_api, "module_aliases", {k: set(v) for k, v in module_api.module_aliases.items()}
    )
    mocker.patch.object(module_api, "runtime_imports", set(module_api.runtime_imports))
    mocker.patch.object(module_api, "runtime_paths", set(module_api.runtime_paths))
    mocker.patch.object(datastore, "objects", [])
    # Other tests import copies of the example module with the same name, from
    # directories they add to sys.path. Python would find those instead.
    monkeypatch.setattr(
        sys,
        "path",
        [
            p
            for p in sys.path
            if not Path(p, AWESOME_MODULE.name).is_file()
            or Path(p).resolve() == AWESOME_MODULE.parent
        ],
    )
    prefixes = ("awesome_module", "example_peat_module", "same_name")
    for name in [n for n in sys.modules if n.startswith(prefixes)]:
        monkeypatch.delitem(sys.modules, name)
    yield
    for name in [n for n in sys.modules if n.startswith(prefixes)]:
        del sys.modules[name]


def findings(report, severity=None):
    return {(f.severity, f.check) for f in report.findings if severity in (None, f.severity)}


def messages(report):
    return "\n".join(f.message for f in report.findings)


def check(mod):
    return check_module.check_module(mod, module_api.modules.values())


def _identify(dev: DeviceData) -> bool:
    return bool(dev)


def ip_method(**kwargs) -> IPMethod:
    values = {
        "name": "test http",
        "description": "Test method",
        "identify_function": _identify,
        "reliability": 5,
        "protocol": "http",
        "transport": "tcp",
        "type": "unicast_ip",
        "default_port": 80,
    }
    values.update(kwargs)
    return IPMethod(**values)


class GoodModule(DeviceModule):
    """A module with nothing wrong with it."""

    device_type = "PLC"
    vendor_id = "Good"
    vendor_name = "Good Inc."
    brand = "Goodbrand"
    model = "G1"
    filename_patterns = ["*.good"]
    ip_methods = [ip_method()]

    @classmethod
    def _parse(cls, file, dev=None):  # noqa: ARG003
        return dev

    @classmethod
    def _pull(cls, dev):  # noqa: ARG003
        return True


def test_good_module_has_no_findings():
    assert check(GoodModule).findings == []


bundled = sorted(module_api._get_static_modules().values(), key=lambda m: m.__name__)


@pytest.mark.parametrize("mod", bundled, ids=[m.__name__ for m in bundled])
def test_bundled_modules_have_no_errors(mod):
    report = check(mod)
    assert not report.count("error"), messages(report)


def test_find_bundled_modules():
    found, failures = check_module.find_bundled_modules()
    assert not failures
    # Every module class in peat/modules/ is registered with PEAT
    assert set(found) == {
        m for m in module_api.modules.values() if m.__module__.startswith("peat.modules.")
    }


def test_run_checks_all_bundled_modules():
    found, _ = check_module.find_bundled_modules()
    reports = check_module.run_checks(found)
    assert len(reports) == len(found)
    assert not any(r.count("error") for r in reports)


def test_example_module():
    modules, reports = check_module.resolve_targets([str(AWESOME_MODULE)])
    assert not reports
    assert [m.__name__ for m in modules] == ["AwesomeTool"]
    report = check(modules[0])
    assert findings(report) == findings(report, "info")


def test_example_module_imported_twice():
    # The file and the directory it's in are the same module
    modules, _ = check_module.resolve_targets([str(AWESOME_MODULE), str(AWESOME_MODULE.parent)])
    assert [m.__name__ for m in modules] == ["AwesomeTool"]


def test_example_module_same_file_name(tmp_path):
    # Python imports a module name once, so the second file isn't imported
    for name in ("one", "two"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "same_name.py").write_bytes(AWESOME_MODULE.read_bytes())
    modules, reports = check_module.resolve_targets(
        [str(tmp_path / "one" / "same_name.py"), str(tmp_path / "two" / "same_name.py")]
    )
    assert len(modules) == 1
    assert ("error", "import") in findings(reports[0])
    assert "same name" in messages(reports[0])


def test_parse_example_module_file():
    (mod,), _ = check_module.resolve_targets([str(AWESOME_MODULE)])
    report = check_module.check_module(mod, module_api.modules.values(), AWESOME_OUTPUT)
    # The parsed device is added to the datastore
    assert len(datastore.objects) == 1
    assert not findings(report, "error")
    assert ("warning", "parse-file") not in findings(report)
    assert datastore.objects[0].name == "SomeDevice"


def test_parse_sceptre_config():
    sceptre = module_api.get_module("SCEPTRE")
    report = check_module.check_module(sceptre, module_api.modules.values(), SCEPTRE_CONFIG)
    assert len(datastore.objects) == 1
    assert datastore.objects[0]._module is sceptre
    assert not findings(report, "error")
    assert ("warning", "parse-file") not in findings(report)


def test_parse_wrong_file():
    # A real file, but not one the module can parse
    report = check_module.check_module(
        module_api.get_module("SCEPTRE"), module_api.modules.values(), AWESOME_OUTPUT
    )
    assert ("warning", "parse-file") in findings(report)
    assert ("error", "parse-file") in findings(report)


def test_not_a_module():
    report = check(DeviceData)
    assert findings(report) == {("error", "class")}


def test_attribute_types():
    class Bad(GoodModule):
        """Doc"""

        vendor_id = None
        filename_patterns = "*.txt"
        ip_methods = ["http"]
        annotate_fields = {1: "x"}
        can_parse_dir = "yes"

    report = check(Bad)
    assert ("error", "types") in findings(report)
    text = messages(report)
    for attr in ("vendor_id", "filename_patterns", "ip_methods", "annotate_fields"):
        assert attr in text
    assert "can_parse_dir" in text
    # Checks that need the bad attributes are skipped
    assert ("warning", "filename-patterns") not in findings(report)


def test_metadata():
    class Bad(GoodModule):
        """Doc"""

        device_type = ""
        vendor_id = ""
        brand = " Brand"
        supported_models = ["A", "a", ""]

    report = check(Bad)
    assert findings(report, "warning") == {("warning", "metadata")}
    text = messages(report)
    assert "device_type" in text
    assert "vendor_id" in text
    assert "whitespace" in text
    assert "duplicate" in text


def test_missing_docstring_and_spelling():
    class Bad(GoodModule):
        filename_pattern = ["*.bad"]
        pull_project = None
        identify = None

    Bad.__doc__ = None
    report = check(Bad)
    assert findings(report) == {
        ("warning", "class"),
        ("warning", "spelling"),
        ("warning", "legacy-api"),
    }
    assert "did you mean 'filename_patterns'" in messages(report)


def test_spelling_ignores_helpers():
    class Fine(GoodModule):
        """Doc"""

        models = ["A"]
        _parser = None
        supported_model_list = ["A"]

        @classmethod
        def parse(cls, to_parse, dev=None):
            return super().parse(to_parse, dev)

        @classmethod
        def _parsed(cls):
            return None

    assert check(Fine).findings == []


def test_device_type_case():
    class Bad(GoodModule):
        """Doc"""

        device_type = "plc"

    report = check(Bad)
    assert "differs in case from 'PLC'" in messages(report)


def test_does_nothing():
    class Bad(DeviceModule):
        """Doc"""

        device_type = "PLC"

    report = check(Bad)
    assert ("error", "capabilities") in findings(report)
    assert "can't do anything with it" in messages(report)


def test_parse_without_patterns():
    class Bad(GoodModule):
        """Doc"""

        filename_patterns = []

    report = check(Bad)
    assert ("error", "capabilities") in findings(report)
    assert "'peat parse' skips modules without them" in messages(report)


def test_patterns_without_parse():
    class Bad(DeviceModule):
        """Doc"""

        device_type = "PLC"
        filename_patterns = ["*.bad"]
        serial_methods = []
        ip_methods = [ip_method()]

    report = check(Bad)
    assert findings(report, "error") == {("error", "capabilities")}
    assert "_parse() is not implemented" in messages(report)


def test_pull_without_identify_methods():
    class Bad(GoodModule):
        """Doc"""

        ip_methods = []

    report = check(Bad)
    assert ("error", "capabilities") in findings(report)
    assert "peat pull" in messages(report)


def test_overrides():
    class Bad(GoodModule):
        """Doc"""

        @classmethod
        def parse(cls, to_parse, dev=None):
            return cls._parse(to_parse, dev)

        @classmethod
        def method_implemented(cls, method_name):  # noqa: ARG003
            return True

    report = check(Bad)
    assert ("warning", "overrides") in findings(report)
    text = messages(report)
    assert "overrides DeviceModule.parse() without calling super()" in text
    assert "overrides DeviceModule.method_implemented()" in text


def test_override_with_super():
    class Extended(GoodModule):
        """Doc"""

        @classmethod
        def update_dev(cls, dev):
            super().update_dev(dev)

    assert ("warning", "overrides") not in findings(check(Extended))


def test_method_signatures():
    class NotClassmethod(GoodModule):
        """Doc"""

        def _parse(self, file, dev=None):  # noqa: ARG002
            return dev

    class WrongArgs(GoodModule):
        """Doc"""

        @classmethod
        def _parse(cls, path, dev=None):  # noqa: ARG003
            return dev

        @classmethod
        def _pull(cls):
            return True

    class PlainFunction(GoodModule):
        """Doc"""

        def _pull(dev):
            return bool(dev)

    class NotFunction(GoodModule):
        """Doc"""

        _pull = None

    report = check(NotClassmethod)
    assert ("error", "signatures") in findings(report)
    assert "Is the @classmethod decorator missing?" in messages(report)
    # PEAT can call it, since it takes one argument
    report = check(PlainFunction)
    assert findings(report) == {("warning", "signatures")}
    assert "_pull() should be a @classmethod" in messages(report)
    report = check(NotFunction)
    assert ("error", "signatures") in findings(report)
    assert "_pull must be a method, not NoneType" in messages(report)
    report = check(WrongArgs)
    assert ("error", "signatures") in findings(report)
    assert "_parse(file=..., dev=...)" in messages(report)
    assert "_pull(_)" in messages(report)


def test_identify_methods():
    def no_args():
        return True

    class Bad(GoodModule):
        """Doc"""

        ip_methods = [
            ip_method(identify_function=None),
            ip_method(identify_function=no_args),
            ip_method(name="other", description=" ", reliability=0),
            ip_method(name="bcast", type="broadcast_ip", protocol="unknownproto"),
            ip_method(name="unicast", protocol="myproto"),
        ]
        # Scanning only uses PEAT's default options to find the default port
        default_options = {"myproto": {"port": 1234}}

    report = check(Bad)
    assert ("error", "identify-methods") in findings(report)
    text = messages(report)
    assert "identify_function is not set" in text
    assert "with one argument" in text
    assert "name is used by another method" in text
    assert "description is empty" in text
    assert "TCP can't be broadcast" in text
    assert "'unknownproto' has no options" in text
    assert "default port of protocol 'myproto'" in text


def test_filename_patterns():
    class Bad(GoodModule):
        """Doc"""

        filename_patterns = [
            "*.good",
            "*.GOOD",
            "*config*.txt",
            "*cfg_config*.txt",
            "*.*",
            "*.t?",
            "*.t*",
        ]

    report = check(Bad)
    text = messages(report)
    # Only patterns with no wildcards other than "*" are compared
    assert "'*.t?'" not in text
    assert "'*.GOOD' is the same as '*.good'" in text
    assert "'*cfg_config*.txt' appears to be redundant" in text
    assert "'*.*' matches every file" in text


def test_aliases():
    class Bad(GoodModule):
        """Doc"""

        module_aliases = ["thing", "THING", " ", "selrelay", "good", "bad"]

    report = check(Bad)
    text = messages(report)
    assert "module_aliases has an empty value" in text
    assert "'THING' is a duplicate" in text
    assert "'selrelay' is the name of the module SELRelay" in text
    assert "'good' isn't needed, since PEAT adds it" in text
    assert "'bad' isn't needed, since the module name" in text


def test_annotate_fields():
    class Bad(GoodModule):
        """Doc"""

        annotate_fields = {"os.name": "Linux", "os.nme": "Linux", "os": "Linux"}

    report = check(Bad)
    text = messages(report)
    assert "'os.nme' is not a field" in text
    assert "'os' can't be set" in text
    assert "os.name" not in text


def test_default_options():
    class Bad(GoodModule):
        """Doc"""

        default_options = {
            "ftp": 21,
            "timeout": "5",
            "user": "admin",
            "bad": {"user": "admin"},
        }

    report = check(Bad)
    text = messages(report)
    assert "'ftp' must be a dict" in text
    assert "'timeout' is a str" in text
    assert "{'bad': {'user': ...}}" in text
    # Not included with PEAT, so options don't need to be in peat-config.yaml
    assert "peat-config.yaml" not in text


def test_default_options_compatible_types():
    class Fine(GoodModule):
        """Doc"""

        default_options = {"timeout": 10, "baudrates": (9600,), "good": {"user": ""}}

    assert check(Fine).findings == []


def test_documented_options():
    documented = check_module._documented_options(EXAMPLES_DIR / "peat-config.yaml")
    assert {"sel", "sage", "ftp", "web"} <= documented
    assert "hosts" not in documented


def test_shared_defaults(mocker):
    mocker.patch.object(DeviceModule, "ip_methods", [ip_method()])

    class Bad(DeviceModule):
        """Doc"""

        device_type = "PLC"

    report = check(Bad)
    assert ("error", "shared-default") in findings(report)
    reports = check_module.run_checks([Bad])
    assert any(r.name == "DeviceModule" and r.count("error") for r in reports)


def test_vendors():
    class Same(GoodModule):
        """Doc"""

        vendor_name = "Good, Incorporated"

    reports = {GoodModule: check(GoodModule), Same: check(Same)}
    check_module.check_vendors([GoodModule, Same], reports)
    assert ("warning", "vendors") in findings(reports[GoodModule])
    assert ("warning", "vendors") in findings(reports[Same])


def test_vendors_wrong_type():
    class NoName(GoodModule):
        """Doc"""

        vendor_name = None

    reports = check_module.run_checks([NoName, GoodModule])
    assert not any(("error", "crash") in findings(r) for r in reports)
    assert ("error", "types") in findings(reports[0])


def test_crashed_check(monkeypatch):
    def check_metadata(*_):
        raise ValueError("boom")

    monkeypatch.setattr(check_module, "check_metadata", check_metadata)
    report = check(GoodModule)
    assert findings(report) == {("error", "crash")}
    assert "check_metadata() crashed" in messages(report)
    assert "boom" in messages(report)


def test_parse_empty_pattern():
    class Bad(GoodModule):
        """Doc"""

        filename_patterns = ["", "*.json"]

    report = check_module.check_module(Bad, module_api.modules.values(), AWESOME_OUTPUT)
    assert ("error", "crash") not in findings(report)
    assert "filename_patterns has an empty value" in messages(report)


def test_main(capsys):
    assert check_module.main(["SCEPTRE"]) == 0
    assert "SCEPTRE" in capsys.readouterr().out

    assert check_module.main(["no-such-module"]) == 1
    assert "No module or alias named" in capsys.readouterr().out

    class Warns(GoodModule):
        filename_patterns = ["*.good", "*.GOOD"]

    with mock.patch.object(check_module, "resolve_targets", return_value=([Warns], [])):
        assert check_module.main(["Warns"]) == 0
        assert check_module.main(["Warns", "--strict"]) == 1
    capsys.readouterr()

    assert check_module.main(["SCEPTRE", "--json"]) == 0
    results = json.loads(capsys.readouterr().out)
    assert results[0]["name"] == "SCEPTRE"


def test_main_parse(capsys):
    args = [str(AWESOME_MODULE), "--parse", str(AWESOME_OUTPUT)]
    assert check_module.main(args) == 0
    assert "AwesomeTool" in capsys.readouterr().out
    assert datastore.objects[0].name == "SomeDevice"

    with pytest.raises(SystemExit):
        check_module.main(["sel", "--parse", str(AWESOME_OUTPUT)])
