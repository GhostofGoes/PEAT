from peat import (
    SCEPTRE,
    Baseline,
    BaselineProvenance,
    BaselineRule,
    BaselineSelector,
    ControlLogix,
    DeviceData,
    DeviceModule,
    SELRelay,
    module_api,
)


def test_device_method_implemented():
    assert ControlLogix.method_implemented("_parse") is False
    assert SELRelay.method_implemented("_parse")
    assert SCEPTRE.method_implemented("_parse")


def test_device_base_methods():
    """
    This is mostly for coverage purposes.
    """
    dev = DeviceData()
    assert DeviceModule._pull(dev) is None
    assert DeviceModule._push(dev, "", "config") is None
    assert DeviceModule._parse(None, None) is None


def test_known_defaults_contract_all_modules():
    """Known-default baselines declared by modules follow the contract."""
    assert module_api.modules
    for name, module in module_api.modules.items():
        baselines = module.get_known_defaults()
        assert isinstance(baselines, list), name
        ids = [b.id for b in baselines]
        assert len(ids) == len(set(ids)), name
        for baseline in baselines:
            assert isinstance(baseline, Baseline), name
            assert baseline.id, name
            assert baseline.kind in ("factory_default", "vendor_recommended"), name
            assert baseline.expected is None, name
            assert baseline.provenance.author, name
            assert not baseline.selector.is_default_selector(), name
            rule_ids = [r.id for r in baseline.rules]
            assert all(rule_ids), name
            assert len(rule_ids) == len(set(rule_ids)), (name, baseline.id)
        for user, password in module.factory_default_credentials:
            assert user, name
            # an empty factory password is valid (ControlLogix "Administrator")
            assert isinstance(password, str), name
            assert module.is_factory_default_credential(user.upper(), password), name
            assert module.is_factory_default_credential(user.lower(), password), name
            assert not module.is_factory_default_credential(user, password + "x"), name


class _ParentModule(DeviceModule):
    vendor_id = "ACME"
    device_type = "PLC"
    factory_default_credentials = {("Admin", "Secret1!")}
    known_defaults = [
        Baseline(
            id="acme-plc-vendor-recommended",
            name="ACME PLC hardening",
            kind="vendor_recommended",
            rules=[
                BaselineRule(id="acme.telnet", path="service[protocol=telnet]", operator="absent")
            ],
        ),
        Baseline(
            id="acme-plc-factory-defaults",
            kind="factory_default",
            selector=BaselineSelector(vendor_id="ACME", model="X*"),
            provenance=BaselineProvenance(author="ACME manual"),
        ),
    ]


class _ChildModule(_ParentModule):
    device_type = "RTU"
    known_defaults = [
        Baseline(
            id="acme-plc-vendor-recommended",
            name="ACME RTU hardening",
            kind="vendor_recommended",
        ),
    ]


def test_get_known_defaults():
    parent = _ParentModule.get_known_defaults()
    assert [b.id for b in parent] == ["acme-plc-vendor-recommended", "acme-plc-factory-defaults"]
    assert parent[0].provenance.author == "_ParentModule"
    assert parent[0].selector.vendor_id == "ACME"
    assert parent[0].selector.device_type == "PLC"
    assert parent[1].provenance.author == "ACME manual"  # kept
    assert parent[1].selector.model == "X*"  # explicit selectors are kept
    assert not parent[1].selector.device_type

    # deep copies: callers can't modify the declared baselines
    parent[0].rules.clear()
    assert _ParentModule.known_defaults[0].rules
    assert not _ParentModule.known_defaults[0].provenance.author

    # subclass entries win over parent entries with the same id
    child = _ChildModule.get_known_defaults()
    assert [b.id for b in child] == ["acme-plc-vendor-recommended", "acme-plc-factory-defaults"]
    assert child[0].name == "ACME RTU hardening"
    assert child[0].selector.device_type == "RTU"
    assert child[0].provenance.author == "_ChildModule"

    assert DeviceModule.get_known_defaults() == []


def test_is_factory_default_credential():
    assert _ParentModule.is_factory_default_credential("Admin", "Secret1!")
    assert _ParentModule.is_factory_default_credential("ADMIN", "Secret1!")
    assert _ParentModule.is_factory_default_credential("admin", "Secret1!")
    assert not _ParentModule.is_factory_default_credential("admin", "secret1!")
    assert not _ParentModule.is_factory_default_credential("root", "Secret1!")
    assert not _ParentModule.is_factory_default_credential("", "")
    assert _ChildModule.is_factory_default_credential("admin", "Secret1!")  # inherited
    assert not DeviceModule.is_factory_default_credential("Admin", "Secret1!")
