import time

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


def test_snmp_walk_deadline(mocker):
    """10,000 queries just under the timeout each could take many hours."""
    calls = _endless_agent(mocker)
    real_next = snmp_module.nextCmd.side_effect

    def _slow(*args, **kwargs):
        for response in real_next(*args, **kwargs):
            time.sleep(0.01)
            yield response

    mocker.patch("peat.protocols.snmp.nextCmd", side_effect=_slow)
    # A generous deadline: a loaded Windows CI runner can take a while for one reply
    snmp = SNMP(ip="127.0.0.1", timeout=0.01, walk_deadline=1.0)
    start = time.monotonic()
    snmp.get("1.3.6.1.2.1.1", single_query=False, query_limit=0)
    assert time.monotonic() - start < 10.0  # 20,000 replies would take 200 seconds
    assert 2 <= calls["count"] < 500

    assert SNMP(ip="127.0.0.1").walk_deadline == snmp_module.DEFAULT_WALK_DEADLINE


def test_snmp_repr_no_community(log_messages):
    snmp = SNMP(ip="127.0.0.1", community="Comm-UNIQUE-123")
    assert "Comm-UNIQUE-123" not in repr(snmp)
    assert "127.0.0.1" in repr(snmp)
    assert not any("Comm-UNIQUE-123" in m for m in log_messages)
