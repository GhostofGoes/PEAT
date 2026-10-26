import importlib.util
import sys
from pathlib import Path

import pytest

from peat import DeviceData, DeviceModule, IPMethod, module_api

SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "check_module.py"


@pytest.fixture(scope="module")
def check_module():
    spec = importlib.util.spec_from_file_location("check_module", SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["check_module"] = mod
    spec.loader.exec_module(mod)
    yield mod
    sys.modules.pop("check_module", None)


def _ident(dev: DeviceData) -> bool:
    return True


def _ip_method(**kwargs) -> IPMethod:
    values = {
        "name": "Test HTTP",
        "description": "Test method",
        "type": "unicast_ip",
        "identify_function": _ident,
        "reliability": 5,
        "protocol": "http",
        "transport": "tcp",
        "default_port": 80,
    }
    values.update(kwargs)
    return IPMethod(**values)


class GoodModule(DeviceModule):
    """A correctly implemented module."""

    device_type = "PLC"
    vendor_id = "ACMECheck"
    vendor_name = "ACME Check, Inc."
    supported_models = ["X100"]
    filename_patterns = ["*.goodconfig"]
    ip_methods = [_ip_method()]
    annotate_fields = {"os.name": "GoodOS"}
    default_options = {"goodmodule": {"option": True}, "http": {"port": 8080}}

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        return True

    @classmethod
    def _parse(cls, file: Path, dev: DeviceData | None = None) -> DeviceData | None:
        return None


def test_good_module_has_no_errors_or_warnings(check_module):
    report = check_module.check_module(GoodModule)
    assert report.count("error") == 0, report.render()
    assert report.count("warning") == 0, report.render()


def test_example_module_is_clean(check_module, example_module_file):
    modules, failures = check_module.resolve_targets(
        [str(example_module_file("awesome_module.py"))]
    )
    assert not failures
    assert [m.__name__ for m in modules] == ["AwesomeTool"]
    report = check_module.check_module(modules[0])
    assert report.count("error") == 0, report.render()
    assert report.count("warning") == 0, report.render()


def test_builtin_modules_have_no_errors(check_module):
    for cls in module_api.classes:
        report = check_module.check_module(cls)
        assert report.count("error") == 0, report.render()


def test_invalid_class(check_module):
    class NotAModule:
        pass

    report = check_module.check_module(NotAModule)
    assert report.codes == {"invalid-class"}


def test_no_functionality(check_module):
    class EmptyModule(DeviceModule):
        """Does nothing."""

        device_type = "PLC"
        vendor_id = "Empty"
        vendor_name = "Empty"

    report = check_module.check_module(EmptyModule)
    assert "no-functionality" in report.codes


def test_wrapper_override_and_not_classmethod(check_module):
    class LegacyModule(DeviceModule):
        """Legacy style module."""

        filename_patterns = ["*.legacy"]

        @classmethod
        def parse(cls, to_parse, dev=None):
            return None

        def _parse(self, file, dev=None):
            return None

    report = check_module.check_module(LegacyModule)
    assert "wrapper-override" in report.codes
    assert "not-classmethod" in report.codes


def test_bad_signature(check_module):
    class BadSignature(DeviceModule):
        """Bad method signatures."""

        filename_patterns = ["*.bad"]

        @classmethod
        def _parse(cls, path: Path) -> None:
            return None

        @classmethod
        def _push(cls, dev: DeviceData) -> bool:
            return True

    report = check_module.check_module(BadSignature)
    errors = [f for f in report.findings if f.code == "bad-signature"]
    assert len(errors) == 2


def test_parsing_attributes(check_module):
    class PatternsNoParse(DeviceModule):
        """Has patterns but can't parse."""

        filename_patterns = ["*.txt"]
        can_parse_dir = True
        ip_methods = [_ip_method()]

    report = check_module.check_module(PatternsNoParse)
    assert "patterns-without-parse" in report.codes
    assert "parse-dir-without-parse" in report.codes

    class ParseNoPatterns(DeviceModule):
        """Can parse but has no patterns."""

        @classmethod
        def _parse(cls, file: Path, dev: DeviceData | None = None) -> DeviceData | None:
            return None

    report = check_module.check_module(ParseNoPatterns)
    assert "parse-without-patterns" in report.codes


def test_attribute_types(check_module):
    class BadTypes(DeviceModule):
        """Wrong attribute types."""

        vendor_id = None
        module_aliases = "bad"
        filename_patterns = ["*.dup", "*.DUP"]
        ip_methods = [_ip_method(), "not a method"]

        @classmethod
        def _parse(cls, file: Path, dev: DeviceData | None = None) -> DeviceData | None:
            return None

    report = check_module.check_module(BadTypes)
    assert "attr-type" in report.codes
    assert "attr-duplicates" in report.codes
    assert "identify-type" in report.codes


def test_identify_function(check_module):
    class BadIdentify(DeviceModule):
        """Broken identify methods."""

        ip_methods = [
            _ip_method(identify_function=None),
            _ip_method(name="Two args", identify_function=lambda a, b: True),
        ]

    report = check_module.check_module(BadIdentify)
    errors = [f for f in report.findings if f.code == "identify-function"]
    assert len(errors) == 2


def test_annotate_fields_and_options(check_module):
    class BadFields(DeviceModule):
        """Invalid annotate_fields and options."""

        ip_methods = [_ip_method()]
        annotate_fields = {"os.name": "ok", "not.a.real.field": "bad"}
        default_options = {"flat_option": True, "http": 80}

    report = check_module.check_module(BadFields)
    errors = [f for f in report.findings if f.code == "annotate-field"]
    assert len(errors) == 1
    assert "not.a.real.field" in errors[0].message
    assert "options-not-nested" in report.codes
    assert "options-type" in report.codes


def test_aliases_and_name_conflict(check_module):
    class SELRelay(DeviceModule):
        """Conflicts with the builtin SELRelay module."""

        ip_methods = [_ip_method()]
        module_aliases = ["m340", "selrelay"]

    report = check_module.check_module(SELRelay)
    assert "name-conflict" in report.codes
    assert "alias-shadowed" in report.codes
    assert "alias-redundant" in report.codes


def test_base_class_mutated(check_module, mocker):
    mocker.patch.object(DeviceModule, "ip_methods", [_ip_method()])
    report = check_module.check_module(GoodModule)
    assert "base-mutated" in report.codes


def test_load_from_path_errors(check_module, tmp_path):
    broken = tmp_path / "broken_peat_module.py"
    broken.write_text("import this_module_does_not_exist_peat\n")
    empty = tmp_path / "empty_peat_module.py"
    empty.write_text('"""Nothing here."""\n')

    _, failures = check_module.resolve_targets(
        [str(broken), str(empty), str(tmp_path / "missing.py"), "notarealmodule"]
    )
    codes = [f.code for r in failures for f in r.findings]
    assert codes == ["import-failed", "no-modules", "not-found", "not-found"]


def test_main_exit_codes(check_module, example_module_file, tmp_path, capsys):
    assert check_module.main([str(example_module_file("awesome_module.py"))]) == 0
    assert "AwesomeTool" in capsys.readouterr().out
    assert check_module.main(["notarealmodule"]) == 1

    # No vendor information is a warning, which only fails in strict mode
    no_vendor = tmp_path / "novendor_peat_module.py"
    no_vendor.write_text(
        '"""Module without a vendor."""\n'
        "from peat import DeviceModule\n\n\n"
        "class NoVendor(DeviceModule):\n"
        '    """No vendor."""\n\n'
        '    device_type = "PLC"\n'
        '    filename_patterns = ["*.novendor"]\n\n'
        "    @classmethod\n"
        "    def _parse(cls, file, dev=None):\n"
        "        return None\n"
    )
    assert check_module.main([str(no_vendor)]) == 0
    assert check_module.main(["--strict", str(no_vendor)]) == 1
