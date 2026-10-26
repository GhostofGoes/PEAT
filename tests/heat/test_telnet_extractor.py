from datetime import UTC, datetime

import pytest

from peat import config
from peat.heat.heat_classes import TelnetHeatArtifact
from peat.heat.telnet_extractor import TelnetExtractor

START = datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)


def _escape(value: int) -> bytes:
    # SEL's ASCII protocol sends 0xff as 0xffff
    return b"\xff\xff" if value == 0xFF else bytes([value])


def _block(extractor: TelnetExtractor, block_id: int, data: bytes) -> bytes:
    data = data.ljust(128, b"\x00")
    crc = extractor.ymodem_crc(data)
    return (
        b"\x01"
        + _escape(block_id)
        + _escape(255 - block_id)
        + data
        + _escape(crc >> 8)
        + _escape(crc & 0xFF)
    )


def _download_stream(extractor: TelnetExtractor, file_name: bytes, content: bytes) -> bytearray:
    command = b"File Read SET_1.TXT\r\n"
    ready = b"#000 Ready to send file\r\n" + b"\x00"  # skipped by the parser
    blocks = _block(extractor, 0, file_name + b"\x00") + _block(extractor, 1, content)
    return bytearray(command + ready + blocks + b"\x04")


@pytest.fixture
def extractor():
    ext = TelnetExtractor(None)
    packet = {
        "@timestamp": START.isoformat(),
        "source": {"ip": "192.0.2.1"},
        "destination": {"ip": "192.0.2.2"},
    }
    ext.elastic_data = [[packet]]
    ext.start_times = {0: START}
    ext.end_times = {0: START}
    return ext


def test_parse_stream_reconstructs_file(extractor):
    stream = _download_stream(extractor, b"SET_1.TXT", b'[1]\r\nRID,"FEEDER 1"\r\n')
    extractor.bytestreams = {0: stream}

    # Previously, ValueError (iterating the dict's keys) for every completed transfer
    extractor.parseStream(stream, 0)
    assert len(extractor.artifacts) == 1
    artifact = extractor.artifacts[0]
    assert artifact.artifact_file_name == "SET_1.TXT"
    assert artifact.reconstructed_artifact == '[1]\r\nRID,"FEEDER 1"\r\n'
    assert artifact.direction == "DOWNLOAD"


@pytest.mark.parametrize("cut", [1, 30, 60, 160, 200, 290])
def test_parse_stream_truncated(extractor, cut):
    full = _download_stream(extractor, b"SET_1.TXT", b"settings")
    stream = full[: len(full) - cut]
    extractor.bytestreams = {0: stream}

    # Previously, IndexError on a truncated capture
    extractor.parseStream(stream, 0)
    assert extractor.artifacts == []


def _artifact(name: str) -> TelnetHeatArtifact:
    return TelnetHeatArtifact(
        source_ip="192.0.2.1",
        dest_ip="192.0.2.2",
        direction="DOWNLOAD",
        start_time=START,
        end_time=START,
        start=10,
        stop=500,
        reconstructed_artifact="settings",
        artifact_file_name=name,
    )


@pytest.mark.parametrize(
    "name",
    ["../../../../../heat_escape.txt", "/tmp/heat_abs_escape.txt", "..\\..\\heat_win.txt"],
)
def test_export_artifacts_contained(extractor, mocker, tmp_path, name):
    artifacts_dir = tmp_path / "results" / "heat_artifacts"
    mocker.patch.dict(config["CONFIG"], {"HEAT_ARTIFACTS_DIR": artifacts_dir})
    extractor.artifacts = [_artifact(name)]

    extractor.assemble_artifacts()
    extractor.export_artifacts()

    written = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert len(written) == 1
    assert written[0].parent == artifacts_dir
    assert written[0].name.startswith("192.0.2.1_192.0.2.2_DOWNLOAD_heat_")
    assert written[0].name.endswith("_[10_500].txt")
    assert written[0].read_text(encoding="utf-8") == "settings"


def test_assemble_artifacts_no_extension(extractor):
    # Previously, ValueError from .index('.')
    extractor.artifacts = [_artifact("NODOT")]
    extractor.assemble_artifacts()
    assert extractor.artifacts[0].file_name.endswith("_[10_500]")
    assert "NODOT" in extractor.artifacts[0].file_name
