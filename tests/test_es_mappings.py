"""
Consistency checks between the data models (``peat/data/models.py``), the
Elasticsearch mappings (``peat/es_mappings.py``) and the documents PEAT generates.
"""

import json

import pytest

from peat import config, es_mappings
from peat.data import models
from peat.es_mappings import PEAT_INDICES
from peat.settings import Configuration

from .data.example_devices import ALL_DEVICES, SIPROTEC_HOSTS, T0

# Derived host-document fields that are not DeviceData model fields
HOST_DOC_DERIVED = ("tags", "indicator_states")
# DeviceData fields that are NOT in the host document (own indices or not mapped)
HOST_DOC_EXCLUDED = ("module", "relationships", "baseline_findings")

MODEL_MAPPING_PAIRS = [
    (models.DeviceData, es_mappings.HOST_FIELDS, HOST_DOC_EXCLUDED + HOST_DOC_DERIVED),
    (models.Interface, es_mappings.INTERFACE_FIELDS, ()),
    (models.Service, es_mappings.SERVICE_FIELDS, ()),
    (models.File, es_mappings.FILE_FIELDS, ()),
    (models.Event, es_mappings.HOST_EVENT_FIELDS, ()),
    (models.Related, es_mappings.RELATED_FIELDS, ()),
    (models.Logic, es_mappings.LOGIC_FIELDS, ()),
    (models.Firmware, es_mappings.FIRMWARE_FIELDS, ()),
    (models.SSHKey, es_mappings.SSHKEY_FIELDS, ()),
    (models.User, es_mappings.USER_FIELDS, ()),
    (models.OS, es_mappings.OS_FIELDS, ()),
    (models.Geo, es_mappings.GEO_FIELDS, ()),
    (models.Hardware, es_mappings.HARDWARE_FIELDS, ()),
    (models.Description, es_mappings.DESCRIPTION_FIELDS, ()),
    (models.X509, es_mappings.X509_FIELDS, ()),
    (models.Register, es_mappings.REGISTER_FIELDS, ()),
    (models.Tag, es_mappings.TAG_FIELDS, ()),
    (models.IO, es_mappings.IO_FIELDS, ()),
    (models.Memory, es_mappings.MEMORY_FIELDS, ()),
    (models.UEFIFile, es_mappings.UEFI_FILE_FIELD, ()),
    (models.UEFIHash, es_mappings.UEFI_HASH_FIELD, ()),
    (models.Relationship, es_mappings.RELATIONSHIP_FIELDS, ()),
    (models.RelationshipEndpoint, es_mappings.RELATIONSHIP_ENDPOINT_FIELDS, ()),
    (models.Vlan, es_mappings.VLAN_FIELDS, ()),
    (models.NetworkStatistics, es_mappings.NETWORK_STATISTICS_FIELDS, ()),
    (models.NetworkTraffic, es_mappings.NETWORK_TRAFFIC_FIELDS, ()),
    (models.ConnectionStatistics, es_mappings.CONNECTION_STATISTICS_FIELDS, ()),
    (models.ServiceSecurity, es_mappings.SERVICE_SECURITY_FIELDS, ()),
    (models.Redundancy, es_mappings.REDUNDANCY_FIELDS, ()),
    (models.LogicTask, es_mappings.LOGIC_TASK_FIELDS, ()),
    (models.Route, es_mappings.ROUTE_FIELDS, ()),
    (models.TimeSource, es_mappings.TIME_SOURCE_FIELDS, ()),
    (models.Clock, es_mappings.CLOCK_FIELDS, ()),
    (models.Indicator, es_mappings.INDICATOR_FIELDS, ()),
    (models.HostProcess, es_mappings.HOST_PROCESS_FIELDS, ()),
    (models.Package, es_mappings.PACKAGE_FIELDS, ()),
    (models.Asset, es_mappings.ASSET_FIELDS, ()),
    (models.IEC61850, es_mappings.IEC61850_FIELDS, ()),
    (models.IEC61850Address, es_mappings.IEC61850_ADDRESS_FIELDS, ()),
]


def check_model_mapping(model_cls, mapping: dict, path: str, exceptions=()) -> list[str]:
    """Every model field must be mapped and every mapped key must be a model field."""
    errors = []
    fields = set(model_cls.__fields__)
    mapped = set(mapping)
    for missing in sorted(fields - mapped - set(exceptions)):
        errors.append(f"{path}: model field '{missing}' not mapped")
    for extra in sorted(mapped - fields - set(exceptions)):
        errors.append(f"{path}: mapped key '{extra}' is not a model field")
    for name, field in model_cls.__fields__.items():
        if name in exceptions or name not in mapping:
            continue
        sub = mapping[name]
        typ = field.type_
        if isinstance(typ, type) and hasattr(typ, "__fields__") and "properties" in sub:
            errors += check_model_mapping(typ, sub["properties"], f"{path}.{name}")
    return errors


def check_types(model_cls, mapping: dict, path: str) -> list[str]:
    """``Field(elastic_type=...)`` of a model must agree with the mapping type."""
    errors = []
    for name, field in model_cls.__fields__.items():
        if name not in mapping:
            continue
        spec = mapping[name]
        etype = field.field_info.extra.get("elastic_type")
        if etype is not None:
            if etype == "flattened":
                good = spec.get("type") in ("flattened", "flat_object")
            elif isinstance(etype, dict):
                good = all(spec.get(k) == v for k, v in etype.items())
            else:
                good = spec.get("type") == etype
            if not good:
                errors.append(f"{path}.{name}: elastic_type={etype} mapping={spec}")
        typ = field.type_
        if isinstance(typ, type) and hasattr(typ, "__fields__") and "properties" in spec:
            errors += check_types(typ, spec["properties"], f"{path}.{name}")
    return errors


def leaf_paths(doc, prefix: str = ""):
    if isinstance(doc, dict):
        for key, value in doc.items():
            yield from leaf_paths(value, f"{prefix}{key}.")
    elif isinstance(doc, list):
        for value in doc:
            yield from leaf_paths(value, prefix)
    else:
        yield prefix[:-1]


def unmapped(doc: dict, index: str) -> list[str]:
    """Leaf paths of a generated document that the index mapping lacks."""
    missing = []
    for path in sorted(set(leaf_paths(json.loads(json.dumps(doc, default=str))))):
        props = PEAT_INDICES[index]["properties"]
        parts = path.split(".")
        for i, part in enumerate(parts):
            spec = props.get(part)
            if spec is None:
                missing.append(path)
                break
            if spec.get("type") in ("flattened", "flat_object"):
                break  # any key below a flattened field is fine
            if i < len(parts) - 1:
                if "properties" not in spec:
                    missing.append(path)
                    break
                props = spec["properties"]
    return missing


def count_fields(props: dict) -> int:
    """Count mapped fields like Elasticsearch does (objects + leaves + multi-fields)."""
    total = 0
    for spec in props.values():
        total += 1
        if "properties" in spec:
            total += count_fields(spec["properties"])
        if "fields" in spec:
            total += len(spec["fields"])
    return total


@pytest.fixture
def devices(mocker) -> dict:
    mocker.patch.dict(config["CONFIG"], {"HOSTS": SIPROTEC_HOSTS})
    return {name: builder() for name, builder in ALL_DEVICES.items()}


@pytest.mark.parametrize(
    ("model_cls", "mapping", "exceptions"),
    MODEL_MAPPING_PAIRS,
    ids=[pair[0].__name__ for pair in MODEL_MAPPING_PAIRS],
)
def test_model_mapping_consistency(model_cls, mapping, exceptions):
    assert check_model_mapping(model_cls, mapping, model_cls.__name__, exceptions) == []


@pytest.mark.parametrize(
    ("model_cls", "mapping", "exceptions"),
    MODEL_MAPPING_PAIRS,
    ids=[pair[0].__name__ for pair in MODEL_MAPPING_PAIRS],
)
def test_model_elastic_types_match_mapping(model_cls, mapping, exceptions):  # noqa: ARG001
    assert check_types(model_cls, mapping, model_cls.__name__) == []


def test_free_text_mapping():
    assert es_mappings.FREE_TEXT["type"] == "keyword"
    assert es_mappings.FREE_TEXT["ignore_above"] == 1024
    assert es_mappings.FREE_TEXT["fields"] == {"text": {"type": "text"}}
    # new free-text fields use FREE_TEXT
    assert es_mappings.EVENT_FIELDS["reason"] is es_mappings.FREE_TEXT
    assert es_mappings.RELATIONSHIP_FIELDS["description"] is es_mappings.FREE_TEXT
    # existing mapping bug fix: the model declares keyword + text
    assert es_mappings.EVENT_FIELDS["action"] == es_mappings.KEYWORD_AND_TEXT


def test_event_mappings():
    assert es_mappings.EVENT_FIELDS["severity"] == es_mappings.LONG
    assert "log_level" not in es_mappings.EVENT_FIELDS  # root "log.level" instead
    assert es_mappings.HOST_EVENT_FIELDS["log_level"] == es_mappings.KEYWORD
    assert "start" not in es_mappings.HOST_EVENT_FIELDS
    events = PEAT_INDICES["ot-device-events"]["properties"]
    assert events["log"] == {"properties": {"level": es_mappings.KEYWORD}}
    hosts = PEAT_INDICES["ot-device-hosts-timeseries"]["properties"]
    assert hosts["event"]["properties"]["kind"] == es_mappings.KEYWORD
    assert hosts["host"]["properties"]["event"]["properties"] is es_mappings.HOST_EVENT_FIELDS


def test_host_document_excludes_own_index_lists():
    host = PEAT_INDICES["ot-device-hosts-timeseries"]["properties"]["host"]["properties"]
    for key in ("relationships", "baseline_findings"):
        assert key not in host
        assert key not in host["module"]["properties"]
    for key in ("files", "successful_pulls", "asset", "tags", "indicator_states"):
        assert key in host


def test_no_pgid_and_no_log_original():
    for name, index in PEAT_INDICES.items():
        paths = set(leaf_paths_of_mapping(index["properties"]))
        assert not any("pgid" in p for p in paths), name
    assert "original" not in PEAT_INDICES["peat-logs"]["properties"]["log"]["properties"]


def leaf_paths_of_mapping(props: dict, prefix: str = ""):
    for name, spec in props.items():
        if "properties" in spec:
            yield from leaf_paths_of_mapping(spec["properties"], f"{prefix}{name}.")
        else:
            yield f"{prefix}{name}"


@pytest.mark.parametrize("index", sorted(PEAT_INDICES))
def test_field_count_below_limit(index):
    # PEAT creates indices with "index.mapping.total_fields.limit" of 20000
    assert count_fields(PEAT_INDICES[index]["properties"]) < 20000


def test_elastic_index_settings_wired():
    """Every ELASTIC_*_INDEX setting must map to a PEAT index mapping."""
    conf = Configuration("configuration", env_prefix="TEST_CONF_", init_env=False)
    index_settings = [
        key
        for key in conf.json_dict(include_none_vals=True)
        if key.startswith("ELASTIC_") and key.endswith("_INDEX")
    ]
    assert "ELASTIC_RELATIONSHIPS_INDEX" in index_settings
    assert "ELASTIC_BASELINE_FINDINGS_INDEX" in index_settings
    for key in ("ELASTIC_RELATIONSHIPS_INDEX", "ELASTIC_BASELINE_FINDINGS_INDEX"):
        assert getattr(conf, key) in PEAT_INDICES
    assert "ot-device-relationships" in PEAT_INDICES
    assert "ot-device-baseline-findings" in PEAT_INDICES
    assert models.Relationship()._es_index_varname == "ELASTIC_RELATIONSHIPS_INDEX"
    assert models.BaselineFinding()._es_index_varname == "ELASTIC_BASELINE_FINDINGS_INDEX"


def test_generated_documents_are_mapped(devices):
    """Every leaf of every generated document is mapped in its index."""
    problems = {}
    for device in devices.values():
        device.export()
        for index, docs in (
            ("ot-device-hosts-timeseries", [device.gen_elastic_content()]),
            (
                "ot-device-relationships",
                [rel.gen_elastic_content(device) for rel in device.relationships],
            ),
            ("ot-device-events", [ev.gen_elastic_content(device) for ev in device.event]),
            ("ot-device-files", [f.gen_elastic_content(device) for f in device.files]),
        ):
            for doc in docs:
                missing = unmapped(doc, index)
                if missing:
                    problems.setdefault(index, set()).update(missing)

    findings = [
        models.BaselineFinding(
            baseline_id="b",
            baseline_name="B",
            baseline_kind=kind,
            baseline_version="1",
            rule_id="r",
            rule_name="R",
            path="service[protocol=telnet].enabled",
            category="ports_services",
            result=result,
            difference="mismatch" if result == "fail" else "",
            operator="equals",
            expected=False,
            actual=True,
            severity="high" if result == "fail" else "",
            alert=result == "fail",
            reason="Telnet is enabled",
            reference="https://example.com",
            standards={"NERC CIP-007-6 R1.1"},
            timestamp=T0,
        )
        for kind, result in (("vendor_recommended", "fail"), ("factory_default", "pass"))
    ]
    for finding in findings:
        doc = finding.gen_elastic_content(devices["siprotec"])
        missing = unmapped(doc, "ot-device-baseline-findings")
        if missing:
            problems.setdefault("ot-device-baseline-findings", set()).update(missing)

    goose = models.Relationship(
        type="publishes_to",
        protocol="goose",
        direction="egress",
        reference="PROT1PRO/LLN0$GO$gcbTrip",
        remote=models.RelationshipEndpoint(mac="01:0C:CD:01:00:10", protocol_address="0x1000"),
        vlan=models.Vlan(id="100", priority=4),
        statistics=models.NetworkStatistics(
            timestamp=T0,
            ingress=models.NetworkTraffic(bytes=1, packets=1),
            egress=models.NetworkTraffic(bytes=2, packets=2),
        ),
    )
    goose_dev = models.DeviceData(name="PROT1", mac="00:30:A7:00:00:01")
    missing = unmapped(goose.gen_elastic_content(goose_dev), "ot-device-relationships")
    if missing:
        problems.setdefault("ot-device-relationships", set()).update(missing)

    assert problems == {}


def test_host_document_contents(devices):
    sip = devices["siprotec"]
    doc = sip.gen_elastic_content()
    assert doc["event"] == {"kind": "asset", "category": ["host"], "type": ["info"]}
    assert doc["host"]["tags"] == ["feeder", "protection"]
    assert unmapped(doc, "ot-device-hosts-timeseries") == []
