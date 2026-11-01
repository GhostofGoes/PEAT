import pytest
from pydantic import ValidationError

from peat import Elastic
from peat.data.models import Event
from peat.data.validators import ECS_EVENT_VALUES


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
