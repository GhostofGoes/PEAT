"""
Functionality for encrypting/decrypting the results directory
"""

import getpass
import os
import shutil
import tarfile
from pathlib import Path
from typing import Final

import pyzipper

from peat import log, utils

#: Name of the single member of an encrypted results archive. The results
#: directory is stored as a tar archive in this member, so the names and sizes
#: of the files (which include device IPs, module names, etc.) are encrypted,
#: instead of being readable in the ZIP directory without the password.
RESULTS_ARCHIVE_MEMBER: Final[str] = "peat-results.tar"

#: Maximum total (uncompressed) size of the files in an encrypted results
#: archive that will be extracted, so a small crafted archive can't fill the disk.
MAX_RESULTS_ARCHIVE_SIZE: Final[int] = 32 * 1024**3  # 32 GiB

#: Maximum number of links that weren't extracted listed in the warning about them
MAX_LISTED_LINKS: Final[int] = 20


def zip_encrypt_results(
    results_dir_path: Path, write_path: Path = Path("./"), user_password: str | None = None
) -> bool:
    """
    zip and encrypted the target 'peat_results' directory

    The directory is stored as a single tar archive inside the AES-encrypted
    ZIP file, so the file names and sizes are encrypted as well as the contents.
    Symbolic links are stored as links (their targets aren't included), and
    :func:`unzip_decrypt_results` doesn't extract them, so a warning is
    logged for each one.

    Args:
        results_dir_path:    target peat results directory
        write_path:          where to write archive
        user_password:       password to encrypt the zip

    Returns:
        bool
    """

    if not results_dir_path.is_dir():
        log.error(f"directory path {results_dir_path} does not exist")
        return False

    results_dir_path = results_dir_path.resolve()
    write_path = write_path.resolve()

    zip_name = write_path / f"encrypted_{results_dir_path.name}.zip"

    try:
        # pyzipper needs a password
        if user_password is None:
            user_password = getpass.getpass(
                "WARNING: PEAT will not save the encrypted archive's password for you,"
                "it is up to you to remember it\n"
                "Please provide a password for the archive: "
            )
            if getpass.getpass("Please confirm the password: ") != user_password:
                log.error("The passwords don't match")
                return False

        log.info("Zippping and Encrypting Results...")
        with pyzipper.AESZipFile(
            zip_name,
            "w",
            compression=pyzipper.ZIP_DEFLATED,
            encryption=pyzipper.WZ_AES,
        ) as zf:
            zf.setpassword(user_password.encode("utf-8"))

            with (
                zf.open(RESULTS_ARCHIVE_MEMBER, "w", force_zip64=True) as member,
                tarfile.open(fileobj=member, mode="w|", format=tarfile.PAX_FORMAT) as tar,
            ):
                for dirpath, dirnames, filenames in os.walk(results_dir_path):
                    dirpath = Path(dirpath)
                    # os.walk() lists links to directories in dirnames (and doesn't follow them)
                    links = [d for d in dirnames if (dirpath / d).is_symlink()]
                    for filename in sorted(filenames + links):
                        full_path = dirpath / filename
                        arcname = full_path.relative_to(results_dir_path).as_posix()
                        if full_path.is_symlink():
                            log.warning(
                                f"'{arcname}' is a symbolic link (to "
                                f"'{os.readlink(full_path)}'). Only the link is stored "
                                f"in the archive, not the file it points to, and "
                                f"links aren't extracted when decrypting results."
                            )
                        tar.add(full_path, arcname=arcname, recursive=False)
        log.info(f"encrypted results written: {zip_name}")
        return True

    except Exception as e:
        log.error(f"Issue zipping and encrypting results: {e}")
        return False


def unzip_decrypt_results(
    encrypted_dir_path: Path,
    write_path: Path = Path("./"),
    user_password: str | None = None,
    max_size: int = MAX_RESULTS_ARCHIVE_SIZE,
) -> bool:
    """
    Decrypt target archive with provided password and write to target path

    Both archives with a single tar member (created by current versions of PEAT)
    and archives with the result files stored directly in the ZIP (created by
    older versions of PEAT) are supported. Only regular files and directories
    with safe names are extracted from the tar archive.

    Args:
        encrypted_dir_path:  target encrypted archive
        write_path:          where to write extracted dir
        user_password:       password to decrypt the zip
        max_size:            maximum total uncompressed size of the archive, in bytes.
            Larger archives, or archives larger than the free disk space, aren't extracted.

    Returns:
        bool
    """

    if not pyzipper.is_zipfile(encrypted_dir_path):
        log.error(f"archive path {encrypted_dir_path} does not exist")
        return False

    write_path = write_path.resolve()
    encrypted_dir_path = encrypted_dir_path.resolve()

    extract_dir = write_path / encrypted_dir_path.stem.replace("encrypted_", "", 1)

    try:
        if user_password is None:
            user_password = getpass.getpass("Please provide a password for the archive: ")

        log.info("Unzipping and Decrypting Results...")
        with pyzipper.AESZipFile(encrypted_dir_path, "r") as zf:
            zf.setpassword(user_password.encode("utf-8"))

            # NOTE: the sizes in the ZIP directory are enforced when extracting,
            # and the contents of a tar member can't be larger than the tar itself.
            total_size = sum(info.file_size for info in zf.infolist())
            free_space = shutil.disk_usage(_existing_parent(write_path)).free
            if total_size > max_size or total_size > free_space:
                log.error(
                    f"Not extracting {encrypted_dir_path.name}: its contents are "
                    f"{total_size} bytes, more than the limit of {max_size} bytes "
                    f"or the free disk space ({free_space} bytes)"
                )
                return False

            if zf.namelist() == [RESULTS_ARCHIVE_MEMBER]:
                _extract_results_tar(zf, extract_dir)
            else:  # Archive created by an older version of PEAT
                zf.extractall(path=extract_dir)

        log.info(f"decrypted results written: {write_path}")
        return True

    except Exception as e:
        log.error(f"Issue unzipping and decrypting results: {e}")
        return False


def _existing_parent(path: Path) -> Path:
    while not path.exists() and path != path.parent:
        path = path.parent
    return path


def _extract_results_tar(zf: pyzipper.AESZipFile, extract_dir: Path) -> None:
    extract_dir.mkdir(parents=True, exist_ok=True)

    links: list[str] = []
    with (
        zf.open(RESULTS_ARCHIVE_MEMBER) as member,
        tarfile.open(fileobj=member, mode="r|") as tar,
    ):
        for unchecked in tar:
            if unchecked.issym() or unchecked.islnk():
                links.append(f"'{unchecked.name}' -> '{unchecked.linkname}'")
                continue

            checked = utils.check_tar_member(unchecked, extract_dir, allow_dirs=True)
            if checked is None:
                continue

            if hasattr(tarfile, "data_filter"):
                tar.extract(unchecked, path=extract_dir, filter="data")
            else:  # Python < 3.11.4, the member was already checked
                tar.extract(checked, path=extract_dir)

    if links:
        shown = ", ".join(links[:MAX_LISTED_LINKS])
        more = (
            f" (and {len(links) - MAX_LISTED_LINKS} more)" if len(links) > MAX_LISTED_LINKS else ""
        )
        log.warning(
            f"{len(links)} symbolic or hard link(s) in the archive weren't extracted, "
            f"since links aren't extracted from encrypted results (the files they point "
            f"to aren't in the archive, and a link could point outside of the results): "
            f"{shown}{more}"
        )
