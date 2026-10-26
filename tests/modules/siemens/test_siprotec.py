import pytest

from peat.modules.siemens.mlfb import decode_mlfb
from peat.modules.siemens.siprotec import Siprotec


@pytest.mark.parametrize("data", ["", "x", "7SJ8", "7SJ8\n", "7SJ62255EB923FC1\nBF123\nV04.70.01"])
def test_parse_mlfb_txt_malformed(data):
    # Previously, IndexError or ValueError
    parsed = Siprotec._parse_mlfb_txt(data)
    assert "mlfb" not in parsed


def test_parse_mlfb_txt():
    parsed = Siprotec._parse_mlfb_txt("7SJ62255EB92-3FC1\nBF1234567890\nFW V04.70.01")
    assert parsed["model"] == "7SJ622"
    assert parsed["bf_number"] == "BF1234567890"
    assert parsed["firmware_version"] == "V04.70.01"
    assert parsed["mlfb"] == "55EB92"
    assert parsed["nominal_current"] == "Iph=5A, Ignd=5A/Sensitive"


def test_decode_mlfb_too_long():
    # Previously, IndexError for more characters than known fields
    decoded = decode_mlfb("5" * 20)
    assert decoded["mlfb"] == "5" * 20
    assert len(decoded) == 11
