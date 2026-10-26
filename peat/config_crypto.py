"""
Functionality for encrypting/decrypting config files
"""

import base64
import getpass
import os
from pathlib import Path
from typing import Final

import yaml
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from peat import log, utils

#: Header of encrypted PEAT config files, hex-encoded "PEAT_CRYPT2"
#: (``504541545f435259505432``). It's followed by the hex-encoded random
#: salt (:data:`SALT_LENGTH` bytes) and then the Fernet token.
_encrypted_header: Final[str] = b"PEAT_CRYPT2".hex()

#: Header of encrypted config files created by older versions of PEAT,
#: hex-encoded "PEAT_CRYPT" (``504541545f4352595054``). These files used
#: :data:`LEGACY_SALT` and are followed directly by the Fernet token.
_legacy_encrypted_header: Final[str] = b"PEAT_CRYPT".hex()

#: Length in bytes of the random salt generated for each encrypted file
SALT_LENGTH: Final[int] = 16

#: Static salt used by older versions of PEAT. Only used to decrypt old files.
LEGACY_SALT: Final[bytes] = b"9001"


def encrypt_config(file_path: Path, user_password: str) -> bool:
    """
    Encrypt a config file at a given location

    Args:
        file_path: the path to the config file
        user_password: Password specified by CLI, if None user will
        be prompted to input a password

    Returns:
        true if successful encrypted a config and wrote to disk
    """
    if not user_password:
        user_password = getpass.getpass(prompt="Enter a password: ")

    if not file_path.is_file():
        log.info(f"Error attempting to read file at {file_path}")
        return False

    # A new random salt for every file, so the key derived from a password
    # is different for every file (no precomputed tables)
    salt = os.urandom(SALT_LENGTH)
    fernet_key = generate_key(user_password.encode(), salt)

    cfg_data = file_path.read_text(encoding="utf-8")
    encrypted_cfg = (
        _encrypted_header.encode() + salt.hex().encode() + fernet_key.encrypt(cfg_data.encode())
    )

    return write_encrypted_file(encrypted_cfg, file_path)


def write_encrypted_file(data: str, filepath: Path) -> bool:
    """
    Write an encrypted file to disk
    By default the file will be written to /peat/examples/
    An "encrypted" tag will be added to the filename

    Args:
        data: encrypted string to be written to file
        filepath: The path to the originally encrypted file

    Returns:
        Return true if file was written successfully
    """
    if os.sep in str(filepath.resolve()):
        filename = "encrypted_" + filepath.name  # give the encrypted config a new new name
        new_filepath = filepath.with_name(filename)
        new_filepath = new_filepath.resolve()
        log.info(f"Saving encrypted config to {new_filepath}")
        # TODO allow for custmo output path
        return utils.write_file(data, new_filepath)
    else:
        log.error("The argument given to peat encrypt is not a valid path")
        return False


def decrypt_config(filepath: Path, user_password: str | None = None) -> str | None:
    """
    Decrypt a given config file and return as string in memory.
    This does not write the unencrypted file to disk

    Args:
        filepath: the path to the encrypted file
        user_password: Password specified by CLI, if None user will
        be prompted to input a password
    Return:
        String of decrypted data, or :obj:`None` if decryption failed
    """
    encrypted_cfg = filepath.read_text(encoding="utf-8")
    if not encrypted_cfg:
        log.error(f"PEAT decrypt encountered an error attempting to read the file: {filepath}")
        return None

    if encrypted_cfg.startswith(_encrypted_header):
        # Current format: header, hex-encoded random salt, Fernet token
        salt_end = len(_encrypted_header) + SALT_LENGTH * 2
        try:
            salt = bytes.fromhex(encrypted_cfg[len(_encrypted_header) : salt_end])
        except ValueError:
            salt = b""
        if len(salt) != SALT_LENGTH:
            log.error("Invalid salt in encrypted config file")
            return None
        token = encrypted_cfg[salt_end:]
    elif encrypted_cfg.startswith(_legacy_encrypted_header):
        # Files encrypted by older versions of PEAT, with a static salt
        log.warning(
            f"{filepath.name} was encrypted by an older version of PEAT. "
            f"Re-encrypt it with 'peat encrypt-config' to use a unique salt."
        )
        salt = LEGACY_SALT
        token = encrypted_cfg[len(_legacy_encrypted_header) :]
    else:
        log.error("Invalid header")
        return None

    if not user_password:
        user_password = getpass.getpass(prompt="Enter a password: ")

    fernet_key = generate_key(user_password.encode(), salt)
    try:
        decrypted_msg = fernet_key.decrypt(token)
    except InvalidToken:
        return None

    return decrypted_msg.decode()


def check_header(file_data: str) -> bool:
    """
    Check if the file data is a config that has been previously
    encrypted by PEAT (should contain valid header)

    Args:
        file_data: the encrypted file in memory
    Returns:
        true: encrypted file has valid PEAT header
        false: no header was found
    """
    # NOTE: the legacy header is a prefix of the current header
    return file_data.startswith((_encrypted_header, _legacy_encrypted_header))


def convert_to_dict(decrypted_data: str) -> dict:
    try:
        return yaml.safe_load(decrypted_data)
    except yaml.YAMLError as err:
        log.error(f"PEAT encountered an error while parsing config file, exiting...: {err}")


def generate_key(password: bytes, salt: bytes) -> Fernet:
    """
    Function to generate a new fernet key

    Args:
        password: the password used to create the key, provided by user input
        salt: random salt stored in the encrypted file
            (:data:`LEGACY_SALT` for files created by older versions of PEAT)

    Returns:
        the fernet key used to decrypt/encrypt a file
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1_200_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return Fernet(key)
