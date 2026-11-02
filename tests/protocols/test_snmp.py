import pytest

from peat import config
from peat.protocols.snmp import SNMP


def test_snmp_get_fails(mocker):
    mocker.patch.dict(config["CONFIG"], {"DEBUG": True})

    with pytest.raises(ValueError):
        SNMP(ip="127.0.0.1", snmp_version=20)

    with pytest.raises(ValueError):
        SNMP(ip="127.0.0.1").get(())

    assert not SNMP(ip="127.0.0.1", timeout=0.01).get("1.3.6.1.2.1.1.1.0")


def test_snmp_repr_hides_community():
    snmp = SNMP(ip="127.0.0.1", community="s1te-secret")
    assert "s1te-secret" not in repr(snmp)
    assert "s1te-secret" not in str(snmp)
    assert "127.0.0.1" in repr(snmp)
