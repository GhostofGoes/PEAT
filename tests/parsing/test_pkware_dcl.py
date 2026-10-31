import os

import pytest

from peat.parsing.pkware_dcl import DCLError, explode
from tests.modules.rockwell.rss_fixtures import implode_literals


def test_explode_blast_test_vector():
    # Test vector from the blast.c source (zlib contrib/blast)
    assert explode(bytes.fromhex("00048224258f807f")) == b"AIAIAIAIAIAIA"


@pytest.mark.parametrize("data", [b"", b"x", b"hello world" * 50, bytes(range(256)) * 4])
def test_explode_literal_round_trip(data):
    assert explode(implode_literals(data)) == data


def test_explode_random_round_trip():
    data = os.urandom(5000)
    assert explode(implode_literals(data)) == data


@pytest.mark.parametrize(
    "header",
    [
        b"\x02\x06",  # Invalid literal coding flag
        b"\x00\x07",  # Invalid dictionary size
        b"\x00\x03",  # Invalid dictionary size
    ],
)
def test_explode_invalid_header(header):
    with pytest.raises(DCLError, match="invalid"):
        explode(header + b"\x00" * 8)


@pytest.mark.parametrize("data", [b"", b"\x00", b"\x00\x06\x00"])
def test_explode_truncated(data):
    with pytest.raises(DCLError, match="unexpected end"):
        explode(data)


def test_explode_truncated_before_end_code():
    stream = implode_literals(b"abcdef")
    with pytest.raises(DCLError):
        explode(stream[:-2])


def test_explode_max_out():
    stream = implode_literals(b"a" * 100)
    assert explode(stream, max_out=100) == b"a" * 100
    with pytest.raises(DCLError, match="exceeds the limit"):
        explode(stream, max_out=99)


def test_explode_max_out_on_copy():
    # The test vector expands a short input with a copy
    with pytest.raises(DCLError, match="exceeds the limit"):
        explode(bytes.fromhex("00048224258f807f"), max_out=5)


def test_explode_distance_too_far():
    # Binary literals, 1K dictionary, then a length/distance pair with no
    # output yet: the first bit is 1 (a pair), then codes that decode to a
    # distance past the start of the output.
    with pytest.raises(DCLError, match="too far back"):
        explode(b"\x00\x04\x01\x00\x00\x00")
