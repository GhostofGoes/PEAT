import pytest
from pydantic import ValidationError

from peat import Elastic
from peat.data.models import Event
from peat.data.validators import ECS_EVENT_VALUES, PROTOCOL_ALIASES, clean_protocol, validate_ecs


def test_ecs_version():
    assert Elastic.ECS_VERSION == "9.5.0"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("type", "device"),  # Added in ECS 9.2.0
        ("type", "indicator"),
        ("kind", "asset"),  # GA in ECS 9.0.0
        ("category", "vulnerability"),
        ("category", "library"),
        ("outcome", "unknown"),
    ],
)
def test_ecs_event_values_accepted(field, value):
    assert value in ECS_EVENT_VALUES[field]
    if field == "outcome":
        # outcome is a plain string on the Event model, not validated
        evt = Event(outcome=value)
        assert evt.outcome == value
    else:
        evt = Event(**{field: {value}})
        assert value in getattr(evt, field)


def test_ecs_event_value_normalized():
    evt = Event(type={"Device"}, category={"intrusion-detection"})
    assert evt.type == {"device"}
    assert evt.category == {"intrusion_detection"}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("type", "not_a_type"),
        ("kind", "dataset"),
        ("category", "device"),  # "device" is a type, not a category
    ],
)
def test_ecs_event_values_rejected(field, value):
    with pytest.raises(ValidationError):
        Event(**{field: {value}})


def test_ecs_signal_kind_rejected():
    # "signal" is reserved by ECS for Kibana alerting: data sources must not set it
    assert "signal" not in ECS_EVENT_VALUES["kind"]
    with pytest.raises(ValidationError):
        Event(kind={"signal"})


def test_validate_ecs_field_name_with_underscores(monkeypatch):
    """Only leading underscores are stripped from the (reused) validator's field name."""

    class FakeField:
        name = "_event_category"

    monkeypatch.setitem(ECS_EVENT_VALUES, "event_category", {"some_value"})
    assert validate_ecs("Some-Value", FakeField()) == "some_value"
    with pytest.raises(ValueError, match="event_category"):
        validate_ecs("other", FakeField())


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("c37.118", "c37_118"),
        ("C37.118", "c37_118"),
        ("iec-104", "iec104"),
        ("iec_104", "iec104"),
        ("iec60870-5-104", "iec104"),
        ("modbus-tcp", "modbus_tcp"),
        ("dnp3", "dnp3"),
        ("SEL-Fast-Message", "SEL_Fast_Message"),  # case is handled by the model fields
    ],
)
def test_clean_protocol_aliases(raw, expected):
    assert clean_protocol(raw) == expected
    assert PROTOCOL_ALIASES.get(expected.lower(), expected) == expected


def test_protocol_aliases_on_models():
    from peat.data.models import NetworkStatistics, Relationship, Service

    assert Service(protocol="C37.118").protocol == "c37_118"
    assert Relationship(protocol="IEC-104").protocol == "iec104"
    assert NetworkStatistics(protocol="c37.118").protocol == "c37_118"
