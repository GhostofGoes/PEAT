import base64
import shutil
from pathlib import Path

import pytest
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from peat import config_crypto


def test_wrong_password(tmp_path, examples_dir):
    """
    Test to make sure giving decrypt an incorrect password will result in None returned
    """
    filepath = examples_dir / "encryption/example_config.yaml"
    tmp_filepath = tmp_path / "test"
    tmp_filepath.mkdir()
    shutil.copy(src=filepath.as_posix(), dst=f"{tmp_filepath.as_posix()}/example_config.yaml")
    config_crypto.encrypt_config(
        file_path=tmp_filepath / "example_config.yaml", user_password="passw"
    )
    assert (
        config_crypto.decrypt_config(
            filepath=tmp_filepath / "encrypted_example_config.yaml",
            user_password="wrongpassw",
        )
        is None
    )


def test_gen_header(examples_dir):
    file = Path(examples_dir / "encryption" / "encrypted_config.yaml")
    file_data = file.read_text(encoding="utf-8")
    assert config_crypto.check_header(file_data)


def _encrypt(tmp_path: Path, text: str, password: str, name: str = "cfg.yaml") -> Path:
    src = tmp_path / name
    src.write_text(text, encoding="utf-8")
    assert config_crypto.encrypt_config(file_path=src, user_password=password)
    return tmp_path / f"encrypted_{name}"


def _legacy_key(password: str) -> Fernet:
    # The key derivation used by older versions of PEAT: static salt b"9001"
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b"9001", iterations=1_200_000)
    return Fernet(base64.urlsafe_b64encode(kdf.derive(password.encode())))


def test_encrypt_decrypt_round_trip(tmp_path):
    text = "debug: 1\nhosts:\n  - identifiers: {ip: 192.0.2.1}\n"
    enc = _encrypt(tmp_path, text, "round-trip-pw")
    assert "round-trip-pw" not in enc.read_text(encoding="utf-8")
    assert config_crypto.decrypt_config(filepath=enc, user_password="round-trip-pw") == text
    assert config_crypto.decrypt_config(filepath=enc, user_password="wrong-pw") is None


def test_encrypt_uses_random_salt_per_file(tmp_path):
    """The same plaintext and password must not produce the same key for every file."""
    text = "debug: 0\n"
    first = _encrypt(tmp_path, text, "same-password", name="a.yaml").read_text(encoding="utf-8")
    second = _encrypt(tmp_path, text, "same-password", name="b.yaml").read_text(encoding="utf-8")

    header = b"PEAT_CRYPT2".hex()
    assert first.startswith(header)
    assert second.startswith(header)
    salt_len = config_crypto.SALT_LENGTH * 2
    first_salt = bytes.fromhex(first[len(header) : len(header) + salt_len])
    second_salt = bytes.fromhex(second[len(header) : len(header) + salt_len])
    assert len(first_salt) == len(second_salt) == 16
    assert first_salt != second_salt
    assert config_crypto.LEGACY_SALT not in (first_salt, second_salt)

    # Neither file can be decrypted with the old static-salt key
    with pytest.raises(InvalidToken):
        _legacy_key("same-password").decrypt(first[len(header) + salt_len :])


def test_decrypt_legacy_static_salt_file(tmp_path):
    """Files encrypted by older versions of PEAT (static salt) can still be decrypted."""
    text = "debug: 2\n"
    legacy = tmp_path / "encrypted_legacy.yaml"
    token = _legacy_key("legacy-pw").encrypt(text.encode()).decode()
    legacy.write_text(b"PEAT_CRYPT".hex() + token, encoding="utf-8")

    assert config_crypto.check_header(legacy.read_text(encoding="utf-8"))
    assert config_crypto.decrypt_config(filepath=legacy, user_password="legacy-pw") == text
    assert config_crypto.decrypt_config(filepath=legacy, user_password="nope-pw") is None


def test_decrypt_empty_or_invalid_file(tmp_path):
    empty = tmp_path / "empty.yaml"
    empty.write_text("", encoding="utf-8")
    assert config_crypto.decrypt_config(filepath=empty, user_password="pw-pw") is None

    bad_salt = tmp_path / "bad_salt.yaml"
    bad_salt.write_text(b"PEAT_CRYPT2".hex() + "zz" * 16 + "gAAAA", encoding="utf-8")
    assert config_crypto.decrypt_config(filepath=bad_salt, user_password="pw-pw") is None

    plain = tmp_path / "plain.yaml"
    plain.write_text("debug: 1\n", encoding="utf-8")
    assert not config_crypto.check_header("debug: 1\n")
    assert config_crypto.decrypt_config(filepath=plain, user_password="pw-pw") is None
