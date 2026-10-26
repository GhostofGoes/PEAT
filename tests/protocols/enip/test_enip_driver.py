from types import SimpleNamespace

from peat.protocols.enip import EnipDriver, EnipSocket


def test_enip_driver_class():
    e_sock = EnipSocket("127.0.0.1", 44818, 1.0)
    assert "127.0.0.1" in str(EnipDriver(e_sock))
    d1 = EnipDriver(e_sock)
    d2 = EnipDriver(e_sock)
    assert d1.sequence != d2.sequence
    assert str(d1) == str(d2)
    assert d1.enip_socket == d2.enip_socket


def test_enip_driver_non_utf8_names(mocker):
    driver = EnipDriver(EnipSocket("127.0.0.1", 44818, 1.0))
    items = [SimpleNamespace(serviceName=b"Comm\xffs\x00\x00", itemData=b"eth\xfe0\x00")]
    mocker.patch.object(driver, "_get_services", return_value=SimpleNamespace(listItems=items))
    mocker.patch.object(driver, "_get_interfaces", return_value=SimpleNamespace(listItems=items))

    assert driver.list_services() == ["Comm�s"]
    assert driver.list_interfaces() == ["eth�0"]
