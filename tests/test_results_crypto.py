import io
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import pyzipper

from peat import results_crypto

RESULTS_ARCHIVE_MEMBER = getattr(results_crypto, "RESULTS_ARCHIVE_MEMBER", "peat-results.tar")


def test_mock_peat_results_exists(mock_peat_results):
    assert mock_peat_results.is_dir()


def test_zip_encrypt_missing_dir(tmp_path):
    missing_dir = tmp_path / "does_not_exist"

    result = results_crypto.zip_encrypt_results(missing_dir)
    assert result is False


def test_zip_encrypt_wrong_target(tmp_path):
    wrong_file = tmp_path / "wrong.txt"
    wrong_file.write_text("hello there")

    result = results_crypto.zip_encrypt_results(wrong_file)
    assert result is False


def test_zip_encrypt_success(mock_peat_results, tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    result = results_crypto.zip_encrypt_results(mock_peat_results, out_dir, "secret")
    assert result is True

    zip_path = out_dir / "encrypted_mock_peat_results.zip"
    with pyzipper.AESZipFile(zip_path) as zf:
        zf.setpassword(b"secret")
        with tarfile.open(fileobj=io.BytesIO(zf.read(RESULTS_ARCHIVE_MEMBER))) as tar:
            assert sorted(tar.getnames()) == ["file1.txt", "file2.txt"]


def test_zip_encrypt_pwd_prompt(monkeypatch, mock_peat_results, tmp_path):
    prompts = []
    monkeypatch.setattr(
        results_crypto.getpass, "getpass", lambda prompt: prompts.append(prompt) or "typed_pw"
    )

    result = results_crypto.zip_encrypt_results(mock_peat_results, tmp_path, None)
    assert result is True
    assert len(prompts) == 2  # the password is confirmed

    out = tmp_path / "decrypted"
    assert results_crypto.unzip_decrypt_results(
        tmp_path / "encrypted_mock_peat_results.zip", out, "typed_pw"
    )


def test_zip_encrypt_pwd_prompt_mismatch(monkeypatch, mock_peat_results, tmp_path):
    answers = iter(["typed_pw", "typo_pw"])
    monkeypatch.setattr(results_crypto.getpass, "getpass", lambda _prompt: next(answers))

    assert results_crypto.zip_encrypt_results(mock_peat_results, tmp_path, None) is False
    assert not (tmp_path / "encrypted_mock_peat_results.zip").exists()


def test_unzip_decrypt_success(monkeypatch, tmp_path):
    encrypted_file = tmp_path / "encrypted_peat_results.zip"
    encrypted_file.write_text("fake zip content")

    mock_zip_class = MagicMock()
    # need to return the mock zip in context manager to check for password
    mock_zip = mock_zip_class.return_value.__enter__.return_value

    # patch check for zipfile
    monkeypatch.setattr(results_crypto.pyzipper, "is_zipfile", lambda _is_dir: True)
    # patch the pyzipper AESZipFile function and return a mock zip class
    monkeypatch.setattr(results_crypto.pyzipper, "AESZipFile", mock_zip_class)

    result = results_crypto.unzip_decrypt_results(
        encrypted_dir_path=encrypted_file,
        write_path=tmp_path,
        user_password="secret",
    )

    assert result is True
    mock_zip.setpassword.assert_called_once_with(b"secret")
    mock_zip.extractall.assert_called_once()


def test_unzip_decrypt_requires_pwd(monkeypatch, tmp_path):
    encrypted_file = tmp_path / "encrypted_peat_results.zip"
    encrypted_file.write_text("fake zip content")

    mock_zip_class = MagicMock()
    # need to return the mock zip in context manager to check for password
    mock_zip = mock_zip_class.return_value.__enter__.return_value

    monkeypatch.setattr(results_crypto.pyzipper, "is_zipfile", lambda _is_dir: True)
    # patch the pyzipper AESZipFile function and return a mock zip class
    monkeypatch.setattr(results_crypto.pyzipper, "AESZipFile", mock_zip_class)

    # patch getpass to simulate a prompt
    monkeypatch.setattr(results_crypto.getpass, "getpass", lambda _prompt: "typed_pw")

    result = results_crypto.unzip_decrypt_results(encrypted_file, tmp_path, None)
    assert result is True
    mock_zip.setpassword.assert_called_once_with(b"typed_pw")


def test_encrypted_zip_cannot_be_opened_wrong_pwd(mock_encrypted_peat_results, tmp_path):
    result = results_crypto.unzip_decrypt_results(
        encrypted_dir_path=mock_encrypted_peat_results,
        write_path=tmp_path,
        user_password="wrongpass",
    )

    assert result is False


def test_encrypted_zip_cannot_be_opened_with_zip(mock_encrypted_peat_results):
    with zipfile.ZipFile(mock_encrypted_peat_results, "r") as zf:
        # archive is readable, but file contents are encrypted
        assert zf.namelist() == [RESULTS_ARCHIVE_MEMBER]

        with pytest.raises(RuntimeError, match="encrypted, password required for extraction"):
            zf.read(RESULTS_ARCHIVE_MEMBER)


def _results_dir(tmp_path: Path) -> Path:
    results = tmp_path / "peat_results"
    device_dir = results / "pull_run_1" / "devices" / "192.0.2.10"
    device_dir.mkdir(parents=True)
    (device_dir / "SET_ALL.TXT").write_text("relay settings", encoding="utf-8")
    (device_dir / "device-data-full.json").write_text('{"ip": "192.0.2.10"}', encoding="utf-8")
    (results / "pull_run_1" / "peat_metadata").mkdir()
    (results / "pull_run_1" / "peat_metadata" / "peat-config.yaml").write_text(
        "debug: 1", encoding="utf-8"
    )
    return results


def test_encrypted_zip_hides_file_names(tmp_path):
    results = _results_dir(tmp_path)
    assert results_crypto.zip_encrypt_results(results, tmp_path, "pw-1234")

    zip_path = tmp_path / "encrypted_peat_results.zip"
    # Without the password, only the names and sizes in the ZIP directory are visible
    with zipfile.ZipFile(zip_path) as zf:
        listing = [(info.filename, info.file_size) for info in zf.infolist()]
    assert [name for name, _ in listing] == [RESULTS_ARCHIVE_MEMBER]
    raw = zip_path.read_bytes()
    for secret in [b"192.0.2.10", b"SET_ALL", b"device-data-full", b"pull_run_1"]:
        assert secret not in raw


def test_encrypted_results_round_trip(tmp_path):
    results = _results_dir(tmp_path)
    assert results_crypto.zip_encrypt_results(results, tmp_path, "pw-1234")

    out = tmp_path / "out"
    assert results_crypto.unzip_decrypt_results(
        tmp_path / "encrypted_peat_results.zip", out, "pw-1234"
    )
    extracted = out / "peat_results"
    original = sorted(p.relative_to(results) for p in results.rglob("*") if p.is_file())
    assert sorted(p.relative_to(extracted) for p in extracted.rglob("*") if p.is_file()) == (
        original
    )
    for rel in original:
        assert (extracted / rel).read_bytes() == (results / rel).read_bytes()


def _legacy_archive(path: Path, files: dict[str, bytes], password: bytes) -> Path:
    """Archive in the layout created by older versions of PEAT (one member per file)."""
    with pyzipper.AESZipFile(
        path, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
    ) as zf:
        zf.setpassword(password)
        for name, data in files.items():
            zf.writestr(name, data)
    return path


def test_decrypt_legacy_archive(tmp_path):
    zip_path = _legacy_archive(
        tmp_path / "encrypted_old_results.zip",
        {"devices/192.0.2.10/SET_ALL.TXT": b"settings", "peat.log": b"log"},
        b"old-pw",
    )
    assert results_crypto.unzip_decrypt_results(zip_path, tmp_path / "out", "old-pw")
    out = tmp_path / "out" / "old_results"
    assert (out / "devices" / "192.0.2.10" / "SET_ALL.TXT").read_bytes() == b"settings"
    assert (out / "peat.log").read_bytes() == b"log"


def test_decrypt_refuses_oversize_archive(tmp_path):
    # Highly compressible, so the archive is small but its contents aren't
    zip_path = _legacy_archive(
        tmp_path / "encrypted_bomb.zip", {"a.bin": b"\0" * (4 * 1024 * 1024)}, b"pw"
    )
    assert zip_path.stat().st_size < 64 * 1024

    out = tmp_path / "out"
    assert results_crypto.unzip_decrypt_results(zip_path, out, "pw", max_size=1024 * 1024) is False
    assert not (out / "bomb" / "a.bin").exists()


def test_decrypt_skips_unsafe_tar_members(tmp_path):
    tar_data = io.BytesIO()
    with tarfile.open(fileobj=tar_data, mode="w") as tar:
        for name, kind in [("ok.txt", tarfile.REGTYPE), ("../escape.txt", tarfile.REGTYPE)]:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.size = 2
            tar.addfile(info, io.BytesIO(b"hi"))
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tar.addfile(link)

    zip_path = _legacy_archive(
        tmp_path / "encrypted_crafted.zip", {RESULTS_ARCHIVE_MEMBER: tar_data.getvalue()}, b"pw"
    )
    out = tmp_path / "out"
    assert results_crypto.unzip_decrypt_results(zip_path, out, "pw")
    assert (out / "crafted" / "ok.txt").read_bytes() == b"hi"
    assert not (out / "escape.txt").exists()
    assert not (out / "crafted" / "link").exists()


def test_decrypt_legacy_example_archive(examples_dir, tmp_path):
    # The example archive was created by an older version of PEAT
    zip_path = examples_dir / "encryption" / "encrypted_example_peat_results.zip"
    assert results_crypto.unzip_decrypt_results(zip_path, tmp_path, "example-password")
    out = tmp_path / "example_peat_results"
    assert (out / "devices" / "192.0.2.10" / "device-data-summary.json").is_file()
    assert (out / "README.md").read_text(encoding="utf-8").startswith("This directory")
