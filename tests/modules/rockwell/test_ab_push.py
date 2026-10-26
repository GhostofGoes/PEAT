import io
import zipfile

import pytest

from peat.modules.rockwell import ab_push

NVS = (
    "[Update1]\nDataFileName={}\n[Update2]\nDataFileName=bin1.bin\n"
    "[Update3]\nDataFileName=sig2.bin\n[Update4]\nDataFileName=bin2.bin\n"
)


def _firmware(files: dict[str, bytes]) -> bytes:
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return data.getvalue()


def _files(sig1_name: str = "sig1.bin") -> dict[str, bytes]:
    return {
        "PN-123.nvs": NVS.format(sig1_name).encode(),
        "sig1.bin": b"s1",
        "bin1.bin": b"b1",
        "sig2.bin": b"s2",
        "bin2.bin": b"b2",
    }


def test_open_firmware():
    assert ab_push._open_firmware(_firmware(_files())) == (b"s1", b"b1", b"s2", b"b2")


def test_open_firmware_refuses_oversize(mocker):
    mocker.patch.object(ab_push, "MAX_FIRMWARE_EXTRACTED_SIZE", 1024 * 1024)
    files = _files()
    files["padding.bin"] = b"\0" * (4 * 1024 * 1024)  # compresses to a few KB
    firmware = _firmware(files)
    assert len(firmware) < 64 * 1024

    extract = mocker.spy(zipfile.ZipFile, "extractall")
    with pytest.raises(ValueError, match="too large"):
        ab_push._open_firmware(firmware)
    assert not extract.called


@pytest.mark.parametrize("relative", [False, True])
def test_open_firmware_data_file_outside_archive(tmp_path, relative):
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"not from the archive")
    name = "../" * 30 + outside.as_posix().lstrip("/") if relative else outside.as_posix()

    # Previously, the file outside the archive was read (and pushed to the device)
    with pytest.raises(FileNotFoundError):
        ab_push._open_firmware(_firmware(_files(sig1_name=name)))
