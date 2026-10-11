"""
Fuzz tests for code that handles untrusted data from devices.

These use Hypothesis to generate random and malformed inputs, and check
that PEAT handles them without crashing or hanging. They run as part of the
normal test suite. Increase the number of generated examples by setting the
``HYPOTHESIS_PROFILE`` environment variable to ``fuzz``, e.g.:

.. code-block:: bash

   HYPOTHESIS_PROFILE=fuzz pdm run pytest tests/test_fuzz.py
"""

import os
from unittest import mock

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from peat import DeviceData, config
from peat.modules.rockwell import ab_scan
from peat.parsing import command_parsers
from peat.protocols.enip.enip_packets import ENIP, ENIPListIdentityResponse

settings.register_profile(
    "default",
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.register_profile(
    "fuzz",
    max_examples=5000,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))

# All concrete parsers for command output and files pulled from devices
NIX_PARSERS = [
    cls
    for cls in vars(command_parsers).values()
    if isinstance(cls, type)
    and issubclass(cls, command_parsers.NixParserBase)
    and cls is not command_parsers.NixParserBase
]

# Text that looks a bit like command output, plus arbitrary unicode
nix_text = st.one_of(
    st.text(),
    st.lists(
        st.text(alphabet=st.characters(blacklist_categories=["Cs"]), max_size=80),
        max_size=30,
    ).map("\n".join),
    st.lists(
        st.sampled_from(
            ["eth0", "lo", ":", "=", " ", "\t", "inet", "kB", "0", "1", "/", "-", "root"]
        ),
        max_size=60,
    ).map("".join),
)


@pytest.fixture(scope="module")
def fuzz_dev_dir(tmp_path_factory):
    return tmp_path_factory.mktemp("fuzz_devices")


@pytest.mark.parametrize("parser", NIX_PARSERS, ids=lambda p: p.__name__)
def test_fuzz_nix_parsers(parser, fuzz_dev_dir):
    """
    parse_and_process() must return a bool for any input, never raise.
    """

    @given(data=nix_text)
    def _fuzz(data: str):
        with mock.patch.dict(config["CONFIG"], {"DEVICE_DIR": fuzz_dev_dir}):
            dev = DeviceData(id=f"fuzz_{parser.__name__}")
            assert parser.parse_and_process(data, dev) in (True, False)

    _fuzz()


class _FakeSocket:
    """Stands in for a UDP socket that receives one packet from a "device"."""

    def __init__(self, data: bytes):
        self.data = data

    def recvfrom(self, _bufsize: int) -> tuple[bytes, tuple[str, int]]:
        return self.data, ("192.0.2.1", 44818)


# Mostly well-formed ListIdentity replies with random contents, plus raw bytes
enip_reply = st.one_of(
    st.binary(max_size=512),
    st.binary(max_size=256).map(lambda b: bytes(ENIP(commandCode="ListIdentity", data=b))),
    st.binary(max_size=128).map(
        lambda b: bytes(
            ENIP(
                commandCode="ListIdentity",
                data=bytes(ENIPListIdentityResponse(productNameLength=len(b), productName=b)),
            )
        )
    ),
)


@given(data=enip_reply)
def test_fuzz_enip_fingerprint_device(data: bytes):
    """
    A device's reply to a CIP ListIdentity scan must never crash the scan.
    """
    with mock.patch.object(ab_scan, "enumerate_device_modules", return_value={}):
        result = ab_scan.fingerprint_device(_FakeSocket(data))
    assert result is None or isinstance(result, dict)


@given(
    product_name=st.binary(max_size=64),
    product_code=st.integers(min_value=0, max_value=0xFFFF),
)
def test_fuzz_enip_product_name(product_name: bytes, product_code: int):
    """
    Device-supplied product names may not be valid UTF-8.
    """
    identity = ENIPListIdentityResponse(
        productCode=product_code,
        productNameLength=len(product_name),
        productName=product_name,
    )
    info = ab_scan.extract_info_response(ENIPListIdentityResponse(bytes(identity)))
    if product_name:
        assert isinstance(info["product_name"], str)
