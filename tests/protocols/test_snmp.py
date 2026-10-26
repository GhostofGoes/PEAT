import pytest

from peat import config
from peat.protocols import snmp as snmp_module
from peat.protocols.snmp import SNMP


def test_snmp_get_fails(mocker):
    mocker.patch.dict(config["CONFIG"], {"DEBUG": True})

    with pytest.raises(ValueError):
        SNMP(ip="127.0.0.1", snmp_version=20)

    with pytest.raises(ValueError):
        SNMP(ip="127.0.0.1").get(())

    assert not SNMP(ip="127.0.0.1", timeout=0.01).get("1.3.6.1.2.1.1.1.0")


def _endless_agent(mocker):
    """Patch nextCmd with an agent that always returns another value."""
    from pysnmp.hlapi import ObjectIdentity

    calls = {"count": 0}
    # Skipped by SNMP.get(), so no real values are needed
    skipped_value = mocker.MagicMock(spec=ObjectIdentity)

    def _responses(*args, **kwargs):  # noqa: ARG001
        while True:
            calls["count"] += 1
            if calls["count"] > 20_000:  # a runaway walk
                return
            # (error_indication, error_status, error_index, var_binds)
            yield None, 0, 0, [(None, skipped_value)]

    mocker.patch("peat.protocols.snmp.nextCmd", side_effect=_responses)
    return calls


def test_snmp_walk_default_limit(mocker):
    calls = _endless_agent(mocker)
    snmp = SNMP(ip="127.0.0.1", timeout=0.01)
    snmp.get("1.3.6.1.2.1.1", single_query=False)
    assert calls["count"] == 10_000
    assert snmp_module.DEFAULT_QUERY_LIMIT == 10_000


def test_snmp_walk_explicit_limits(mocker):
    calls = _endless_agent(mocker)
    SNMP(ip="127.0.0.1", timeout=0.01).get("1.3.6.1.2.1.1", single_query=False, query_limit=5)
    assert calls["count"] == 5

    calls = _endless_agent(mocker)
    SNMP(ip="127.0.0.1", timeout=0.01).get("1.3.6.1.2.1.1", single_query=False, query_limit=0)
    assert calls["count"] == 20_001  # 0 is no limit: until the agent stops
