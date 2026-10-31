import ftplib
import posixpath
import re
import traceback
from collections.abc import Callable
from io import BufferedReader, BytesIO, TextIOWrapper
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Literal, Optional

import peat  # Avoid circular imports
from peat import CommError, config, log, utils

from .cache import NS_FTP_FILE, NS_FTP_WELCOME, CacheKey, data_cache

# Placeholder for the (unknown) home directory of the logged-in user.
# NUL can't appear in FTP paths, so this can't collide with a real path.
_HOME = "/\x00home"

# FTP commands that change the user or working directory of a session (RFC 959)
_STATE_VERBS = frozenset({"CWD", "XCWD", "CDUP", "XCUP", "USER", "PASS", "ACCT", "REIN", "SMNT"})

# FTP commands that may change files on the server
_MODIFY_VERBS = frozenset(
    {"STOR", "STOU", "APPE", "DELE", "RNFR", "RNTO", "MKD", "XMKD", "RMD", "XRMD", "SITE"}
)


class _TrackingFTP(ftplib.FTP):
    """
    :class:`ftplib.FTP` that notices commands which change the user or
    working directory of the session, or which may change files.

    All commands sent by :mod:`ftplib` go through ``sendcmd()`` or
    ``voidcmd()``, including the ones sent by ``login()``, ``cwd()``,
    ``storbinary()``, ``delete()`` and ``rename()``.
    """

    peat_state_changed: bool = False
    """If the user or directory changed in a way :class:`FTP` didn't track."""

    peat_tracking_paused: bool = False

    def _peat_note(self, cmd: str) -> None:
        verb = cmd.split(" ", 1)[0].strip().upper()
        if verb in _STATE_VERBS and not self.peat_tracking_paused:
            self.peat_state_changed = True
        if verb in _MODIFY_VERBS:
            # Cached files from this server may be out of date now
            data_cache.invalidate(namespace=NS_FTP_FILE, host=self.host, port=self.port)

    def sendcmd(self, cmd: str) -> str:
        self._peat_note(cmd)
        try:
            return super().sendcmd(cmd)
        finally:
            self._peat_note(cmd)

    def voidcmd(self, cmd: str) -> str:
        self._peat_note(cmd)
        try:
            return super().voidcmd(cmd)
        finally:
            self._peat_note(cmd)


def _join_remote(cwd: str | None, path: str) -> str | None:
    """
    Resolve a path on the FTP server relative to the working directory.

    Returns:
        The absolute path, or :obj:`None` if it can't be resolved
    """
    if path.startswith("/"):
        return posixpath.normpath(path)
    if cwd is None:
        return None
    joined = posixpath.normpath(posixpath.join(cwd, path or "."))
    if cwd.startswith(_HOME) and not (joined == _HOME or joined.startswith(_HOME + "/")):
        return None  # went above the home directory, which is unknown
    return joined


class FTP:
    """
    Generic wrapper for File Transfer Protocol (FTP) functionality.
    """

    def __init__(self, ip: str, port: int = 21, timeout: float = 5.0) -> None:
        self.ip: str = ip
        self.port: int = port
        self.timeout: float = timeout

        self.log = log.bind(
            classname=self.__class__.__name__,
            target=f"{self.ip}:{self.port}",
        )
        self.all_output: list[tuple | str] = []
        self._ftp: ftplib.FTP | None = None

        # Login and working directory tracked for caching of downloaded files
        self._login_fp: str | None = None
        self._cwd: str | None = None

        self.log.trace2(f"Initialized {repr(self)}")

    @property
    def ftp(self) -> ftplib.FTP:
        """
        :class:`ftplib.FTP` instance used for interacting with the server.
        """
        if not self._ftp:
            try:
                # Since "connect" shouldn't be reused on instances,
                # we create a new instance for every new connection.
                self.log.debug(
                    f"Attempting connection to {self.ip}:{self.port} (timeout: {self.timeout})"
                )
                self._login_fp = None
                self._cwd = None
                self._ftp = _TrackingFTP()
                self._ftp.connect(self.ip, self.port, self.timeout)
            except Exception as ex:
                self._ftp = None
                raise CommError(f"({self.ip}:{self.port}) {ex}") from ex

            welcome = getattr(self._ftp, "welcome", None)
            if welcome:
                data_cache.put(self.welcome_key(self.ip, self.port), welcome)

            # TODO: figure out a way to log FTP protocol debugging messages
            #  to a file (like we're doing for peat.protocols.Telnet)
            if config.DEBUG == 2:
                # Moderate amount of output, generally a single line per request
                # NOTE: this output goes directly to stdout!
                self._ftp.set_debuglevel(1)
            elif config.DEBUG >= 3:
                # Maximum output, each line sent/received on the control connection
                self._ftp.set_debuglevel(2)

            self.log.info(f"Connected to {self.ip}:{self.port}")

        return self._ftp

    def __enter__(self) -> "FTP":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.disconnect()
        if exc_type:
            self.log.debug(f"Unhandled exception while exiting - {exc_type.__name__}: {exc_val}")
            self.log.trace(
                f"Exception traceback\n"
                f"{''.join(traceback.format_tb(exc_tb))}"
                f"{exc_type.__name__}: {exc_val}"
            )

    def __str__(self) -> str:
        return self.ip

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.ip}, {self.port}, {self.timeout})"

    @ftp.setter
    def ftp(self, obj: ftplib.FTP) -> None:
        self._ftp = obj
        self._login_fp = None
        self._cwd = None

    @staticmethod
    def welcome_key(ip: str, port: int = 21) -> CacheKey:
        """Cache key of the welcome message of a FTP server."""
        return CacheKey(NS_FTP_WELCOME, ip, port, "welcome")

    @classmethod
    def cached_welcome(cls, ip: str, port: int = 21) -> str | None:
        """
        Get the welcome message of a FTP server, if it was received recently
        by any :class:`FTP` instance, without connecting to the server.

        Returns:
            The welcome message, or :obj:`None` if there is no
            fresh welcome message in the cache
        """
        return data_cache.get(cls.welcome_key(ip, port))

    def _file_key(self, filename: str, mode: Literal["binary", "text"]) -> CacheKey | None:
        """
        Cache key for a file download.

        The key includes the user that's logged in and the absolute path
        of the file. If either isn't known reliably (e.g. the directory was
        changed without using :meth:`cd`), the file is not cached.
        """
        ftp = self._ftp
        if (
            not isinstance(ftp, _TrackingFTP)
            or ftp.peat_state_changed
            or self._login_fp is None
            or not filename
        ):
            return None

        path = _join_remote(self._cwd, filename)
        if path is None:
            return None

        resource = f"{mode}:{path.replace(_HOME, '~', 1)}"
        return CacheKey(NS_FTP_FILE, self.ip, self.port, resource, self._login_fp)

    def _cached_download(
        self,
        filename: str,
        mode: Literal["binary", "text"],
        fetch: Callable[[], bytes | str],
        use_cache: bool,
    ) -> bytes | str:
        """Download a file using ``fetch``, or get it from the cache."""
        key = self._file_key(filename, mode) if use_cache else None
        if key is None:
            return fetch()

        result = data_cache.get_or_fetch(
            key,
            fetch,
            store_if=bool,  # don't cache empty files
            size_of=len,
            wait_timeout=max(30.0, 3 * float(self.timeout or 0)),
        )
        if result.from_cache:
            self.log.debug(
                f"Using cached copy of '{filename}' ({len(result.value)} bytes, "
                f"fetched {result.age:.1f}s ago)"
            )
        return result.value

    @property
    def address(self) -> str:
        """
        Alias for ``ip`` to make code cleaner for some PEAT modules.
        """
        return self.ip

    def disconnect(self) -> None:
        """
        Attempt to cleanly disconnect from the device.
        """
        if self._ftp is not None:
            try:
                # Try to do it cleanly
                self._ftp.quit()
            except Exception as exquit:
                self.log.trace2(f"Unclean quit(): {exquit}")
                try:
                    # If that can't be done, close it normally
                    self._ftp.close()
                except Exception as exclose:
                    self.log.trace2(f"Unclean close(): {exclose}")

            self._ftp = None
            self.log.debug(f"Disconnected from {self.ip}:{self.port}")

            if self.all_output:
                # Save the raw output to disk as an artifact
                try:
                    dev = peat.data.datastore.get(self.ip)
                    dev.write_file(self.all_output, "raw-ftp-output.json", merge_existing=True)
                except Exception as ex:
                    self.log.warning(f"Failed to write raw output to file: {ex}")

    def login(self, user: str = "", passwd: str = "") -> bool:
        """
        Login to the FTP server.

        .. note::
           This function should be called only once for each instance,
           per the documentation for :mod:`ftplib`.

        Args:
            user: Username to login with (default: ``anonymous``)
            passwd: Password to login with (default: ``anonymous@``)

        Returns:
            If the login was successful
        """
        self.log.debug(f"Attempting login as user '{user}'")

        ftp = self.ftp
        tracking = isinstance(ftp, _TrackingFTP)
        self._login_fp = None
        try:
            if tracking:
                ftp.peat_tracking_paused = True
            ftp.login(user, passwd)
        except ftplib.all_errors as ex:
            err_str = str(ex)
            if "530" in err_str:
                err_str = "access was denied or server does not allow anonymous login"
            self.log.debug(f"Login failed as user '{user}': {err_str}")
            return False
        finally:
            if tracking:
                ftp.peat_tracking_paused = False

        self._login_fp = data_cache.fingerprint(user or "anonymous", passwd)
        self._cwd = _HOME
        self.log.info(f"Successfully logged in as user '{user}'")
        return True

    def download_binary(
        self,
        filename: str,
        save_path: Path | None = None,
        save_to_file: bool = True,
        use_cache: bool = True,
    ) -> bytes:
        """
        Download a binary file from the FTP server.

        If the same file was downloaded recently by the same user (by this
        or another :class:`FTP` instance), the cached data is used instead of
        downloading it again (:mod:`peat.protocols.cache`). The file is still
        saved, if ``save_to_file`` is :obj:`True`.

        Args:
            filename: Name or path of the file to download.
                This path must be valid on the server.
                Relative paths generally work best.
            save_path: Path on the local system to save the file to.
                If not specified then it's saved to the device's standard
                output directory and filename.
            save_to_file: If the data should be automatically written to a file
                as defined by ``save_path``
            use_cache: If cached data should be used, and the file cached

        Returns:
            The binary file data as :class:`bytes`
        """
        cmd = f"RETR {filename}"
        self.log.trace2(f"download_binary command string: '{cmd}'")

        # TODO: workaround for odd behavior seen in some SEL relays
        # from _ssl import _SSLSocket
        # def retrbinary(obj: ftplib.FTP, command, callback, blocksize=8192, rest=None):
        #     obj.voidcmd('TYPE I')
        #     resp = obj.voidresp()
        #     with obj.transfercmd(command, rest) as conn:
        #         while 1:
        #             data = conn.recv(blocksize)
        #             if not data:
        #                 break
        #             callback(data)
        #         # shutdown ssl layer
        #         if _SSLSocket is not None and isinstance(conn, _SSLSocket):
        #             conn.unwrap()
        #     return resp
        # _old_retr = self.ftp.retrbinary
        # self.ftp.retrbinary = retrbinary
        # self.ftp.retrbinary(self.ftp, cmd, file_obj.write)
        # self.ftp.retrbinary = _old_retr

        def _fetch() -> bytes:
            file_obj = BytesIO()
            self.ftp.retrbinary(cmd, file_obj.write)
            return file_obj.getvalue()

        data = self._cached_download(filename, "binary", _fetch, use_cache)

        if not data:
            self.log.warning(f"No data for binary file '{filename}' on {self.ip} (command: {cmd})")
        elif not isinstance(data, bytes):
            self.log.error(
                f"download_binary: data has type '{data.__class__.__name__}', not 'bytes'"
            )
        # Save the raw file to disk as an artifact
        elif data and save_to_file:
            if save_path:
                utils.write_file(data, save_path)
            else:
                dev = peat.data.datastore.get(self.ip)

                if filename.startswith("/"):
                    filename = filename[1:]  # Prevent files being saved in "/"

                dev.write_file(data=data, filename=filename, out_dir=dev.get_sub_dir("ftp_files"))
                dev.related.files.add(filename)

        return data

    def download_text(
        self,
        filename: str,
        save_path: Path | None = None,
        save_to_file: bool = True,
        use_cache: bool = True,
    ) -> str:
        """
        Download a text file from the FTP server.

        If the same file was downloaded recently by the same user (by this
        or another :class:`FTP` instance), the cached data is used instead of
        downloading it again (:mod:`peat.protocols.cache`). The file is still
        saved, if ``save_to_file`` is :obj:`True`.

        Args:
            filename: Name or path of the file to download.
                This path must be valid on the server.
                Relative paths generally work best.
            save_path: Path on the local system to save the file to.
                If not specified then it's saved to the device's standard
                output directory and filename.
            save_to_file: If the data should be automatically written to a file
                as defined by ``save_path``
            use_cache: If cached data should be used, and the file cached

        Returns:
            Text file data as a :class:`str`
        """
        cmd = f"RETR {filename}"
        self.log.trace2(f"download_text command string: '{cmd}'")

        def _fetch() -> str:
            lines = []
            self.ftp.retrlines(cmd, lines.append)
            return "\n".join(lines)

        text = self._cached_download(filename, "text", _fetch, use_cache)

        if text:
            if save_to_file:
                # Save the raw file to disk as an artifact
                if save_path:
                    utils.write_file(text, save_path)
                else:
                    dev = peat.data.datastore.get(self.ip)

                    if filename.startswith("/"):
                        filename = filename[1:]  # Prevent files being saved in "/"

                    dev.write_file(
                        data=text,
                        filename=filename,
                        out_dir=dev.get_sub_dir("ftp_files"),
                    )
                    dev.related.files.add(filename)
        else:
            self.log.warning(f"No data for text file '{filename}' on {self.ip} (command: {cmd})")

        return text

    def find_file(self, check_for: str, ext: str, directory: str | None = None) -> str | None:
        for filename in self.nlst_files(directory):
            if check_for in filename and filename.endswith(ext):
                return filename
        self.log.debug(
            f"Could not find file {check_for} ending with {ext} "
            f"in the output of the 'NLST' command"
        )
        return None

    def upload_text(self, filename: str, content: str | bytes | TextIOWrapper | BinaryIO) -> None:
        # We make a new variable to avoid over-writing the argument reference
        if isinstance(content, str):
            file_obj = BytesIO(content.encode("utf-8"))  # str to bytes
        elif isinstance(content, bytes):
            file_obj = BytesIO(content)
        else:
            file_obj = content

        self.ftp.storlines(f"STOR {filename}", file_obj)

    def upload_binary(self, filename: str, content: bytes | BufferedReader) -> None:
        # We make a new variable to avoid over-writing the argument reference
        if isinstance(content, bytes):
            file_obj = BytesIO(content)
        else:
            file_obj = content

        self.ftp.storbinary(f"STOR {filename}", file_obj)

    def cmd(self, command: str) -> str | None:
        """Execute a raw FTP command."""
        if isinstance(command, bytes):
            command = command.decode("utf-8")

        try:
            resp = self.ftp.sendcmd(command)
            self.all_output.append((command, resp))
            return resp
        except ftplib.all_errors as ex:
            self.log.debug(f"Command '{command}' failed: {ex}")
            return None

    def cd(self, directory: str) -> bool:
        """Change directory on the server (``cwd``)."""
        self.log.debug(f"Changing directory to '{directory}'")

        ftp = self.ftp
        tracking = isinstance(ftp, _TrackingFTP)
        try:
            if tracking:
                ftp.peat_tracking_paused = True
            success = self._do("cwd", directory) is not None
        finally:
            if tracking:
                ftp.peat_tracking_paused = False

        # A rejected CWD leaves the working directory unchanged
        if success:
            self._cwd = _join_remote(self._cwd, directory)
        return success

    def cwd(self, directory: str) -> bool:
        return self.cd(directory)

    def pwd(self) -> str | None:
        """Get the current working directory on the server."""
        return self._do("pwd")

    def mkdir(self, directory: str) -> bool:
        """Create a directory on the server."""
        return True if self._do("mkd", directory) is not None else False

    def rmdir(self, directory: str) -> bool:
        """Remove a directory on the server."""
        return True if self._do("rmd", directory) is not None else False

    def file_size(self, filename: str) -> int | None:
        """Get the size of a file on the server."""
        return self._do("size", filename)

    def file_delete(self, filename: str) -> int | None:
        """Remove a file from the server."""
        return self._do("delete", filename)

    def file_rename(self, filename: str, new_name: str) -> int | None:
        """Rename a file on the server."""
        return self._do("rename", filename, new_name)

    def dir(self, directory: str | None = None) -> tuple[list[str], list[dict]] | None:
        """
        List files on the FTP server, including file metadata (``dir`` command).

        This returns two objects:

        - List of filenames
        - List of dicts with detailed information about each file,
            including type of file, modification time, and size.

        Returns:
            :class:`tuple` with list of filenames and list of dicts with
            file metadata, or :obj:`None` if the command failed.
        """
        file_names = []
        file_metadata = []

        # Approximate header structure:
        #   TYPE PERMS ? USER GROUP SIZE DATE-MODIFIED FILENAME
        #
        # Examples:
        # '-rwxrwxrwx   1 0      0          437824 JAN 21  2011 FILE.SYS'
        # '----------   0 0      0               0 JAN 01  1970 null'
        # 'drwxrwxrwx   5 0      0            8192 JAN 01  1970 OS'

        def _append_func(line: str) -> None:
            """
            Python's ftplib takes a function when calling LIST,
            and will call the function with the result of
            each line of data returned from LIST.
            """
            self.all_output.append(line)

            parts = [x.strip() for x in line.strip().split(" ") if x.strip()]
            name = " ".join(parts[8:])

            # skip "." and ".." since they're not files
            if name in [".", ".."]:
                return

            file_names.append(name)

            if directory:
                path = str(PurePosixPath(directory, name))
                parent = directory
                if not parent.endswith("/"):
                    parent += "/"
            else:  # Relative to current directory (directory arg is None)
                path = str(PurePosixPath(name))
                # NOTE: it's impossible to know parent without running
                # "pwd" if directory is None (a relative dir command).
                parent = ""

            metadata = {
                "type": "dir" if parts[0][0] == "d" else "file",
                "permissions": parts[0][1:],
                "size": int(parts[4]),
                "modified": utils.parse_date(" ".join(parts[5:8])),
                "name": name,
                "path": path,
                "parent": parent,
            }
            file_metadata.append(metadata)

        try:
            if directory is None:
                self.ftp.dir(_append_func)
            else:
                self.ftp.dir(directory, _append_func)
        except ftplib.all_errors as ex:
            self.log.warning(f"'dir' failed for {directory}: {ex}")
            return None

        return file_names, file_metadata

    def rdir(
        self,
        directory: str | None = None,
        _paths_done: set | None = None,
    ) -> tuple[list[str], list[dict]] | None:
        """
        Recursively lists files on the server and parses metadata
        about those files (the ``dir`` command).

        This calls recursively calls :func:`~peat.protocols.FTP.dir`
        on any directories, and returns the consolidated output of
        the calls. Refer to that method's docstring for further
        details about the returned data.

        Returns:
            Tuple with list of filenames and list of dicts with file metadata,
            or :obj:`None` if the command failed.
        """
        dir_result = self.dir(directory)
        if not dir_result:
            return None

        # this is all filenames and directories, without path
        filenames = dir_result[0]
        metadata = dir_result[1]

        if _paths_done is None:
            _paths_done = set()

        for file_dict in metadata:
            if file_dict["type"] == "dir":
                # Don't do the same directory twice
                if file_dict["path"] in _paths_done:
                    continue
                _paths_done.add(file_dict["path"])

                sub_result = self.rdir(file_dict["path"], _paths_done)

                if not sub_result:
                    continue

                # Sanity checks for duplicates
                for filename in sub_result[0]:
                    if filename not in filenames:
                        filenames.append(filename)

                # The _paths_done checks should prevent this from ever happening,
                # but better to be safe than sorry like in the past...
                for meta in sub_result[1]:
                    if meta not in metadata:
                        metadata.append(meta)
                    else:
                        self.log.warning(f"Duplicate metadata: {meta}")

        return filenames, metadata

    def download_files(self, local_dir: Path, files: list[dict]):
        """
        Download files from a device to a directory on the local system.

        The file structure of the local files will match that on the device, if possible.

        .. warning::
           On Windows, there are restrictions on characters allowed in paths,
           so the paths may vary on that platform.

        Args:
            local_dir: Path to local directory to save downloaded files to.
            files: Listing of files to download, as returned from
                :func:`~peat.protocols.FTP.dir` or :func:`~peat.protocols.FTP.rdir`.
        """
        to_download = [f for f in files if f["type"] == "file"]

        self.log.info(f"Downloading {len(to_download)} files to '{local_dir}'")

        if not local_dir.exists():
            local_dir.mkdir(parents=True, exist_ok=True)

        good = 0
        failed = 0

        for entry in to_download:
            save_path = Path(local_dir, entry["path"].lstrip("/"))
            if save_path.exists():
                self.log.warning(f"{save_path} already exists, new file: {entry}")
            try:
                self.log.debug(f"Downloading {entry['path']}")
                self.download_binary(entry["path"], save_path)
                good += 1
            except Exception as ex:
                self.log.warning(f"Failed to download '{entry['path']}': {ex}")
                failed += 1

        self.log.info(
            f"Finished downloading {len(to_download)} files to '{local_dir}'. "
            f"{good} downloads were successful, {failed} downloads failed."
        )

    def nlst(self, directory: str | None = None) -> list[str] | None:
        """``nlst`` command to list files on the server."""
        if directory is None:
            return self._do("nlst")
        else:
            return self._do("nlst", directory)

    def nlst_files(self, directory: str | None = None) -> list[str]:
        """
        List files in a directory on the device using NLST.

        This is a wrapper around :func:`~peat.protocols.FTP.nlst`.

        Args:
            directory: Case-insensitive name of directory to list the contents of.
                If :obj:`None` or empty string, the current directory is listed.

        Returns:
            List of names of files in the directory.
        """
        files = self.nlst(directory)
        if files is None:
            return []
        return files

    def list_command(self, directory: str) -> list[str]:
        """
        Get list of files with file type, permission, and timestamp information.

        This uses the LIST FTP command directly, instead of ``nlst`` or ``dir``.

        Args:
            directory: Case-insensitive name of directory to list the contents of.

        Returns:
            List of names of files in the directory,
            or empty list if the command failed.
        """
        listings = []
        self._do("retrlines", f"LIST {directory}", listings.append)
        return listings

    def getwelcome(self) -> str | None:
        """Return the welcome message sent by the server."""
        return self._do("getwelcome")

    def process_vxworks_ftp_welcome(
        self, welcome: str, dev: Optional["peat.data.models.DeviceData"] = None
    ) -> str | None:
        """
        Extract the VxWorks version from the FTP welcome message.

        Args:
            welcome: FTP welcome message string to parse
            dev: DeviceData object to annotate with extracted information
                If :obj:`None`, no information will be annotated, the
                version will be returned and nothing else will happen.

        Returns:
            The version number as a string, or :obj:`None`
            if the parse failed.
        """
        if dev:
            dev.extra["ftp_welcome"] = welcome

        lower_welcome = welcome.strip().lower()
        if "vxworks" in lower_welcome:
            result = re.search(r"\(vxworks\s+(?:vxworks|)([\d\.]+)\)", lower_welcome)
        elif "wind river" in lower_welcome:
            result = re.search(r"wind river ftp server ([\d\.]+)\s+", lower_welcome)
        else:
            self.log.warning(f"Unknown format for FTP welcome '{welcome}'")
            return None

        if result:
            version = result.groups()[0]
            if dev:
                if not dev.os.version:
                    dev.os.version = version
                else:
                    dev.extra["vxworks_version_from_ftp"] = version

                if not dev.os.name:
                    dev.os.name = "VxWorks"

                if not dev.os.vendor.name:
                    dev.os.vendor.name = "Wind River Systems"

                if not dev.os.vendor.id:
                    dev.os.vendor.id = "WindRiver"
            return version
        else:
            self.log.warning(f"Failed to parse FTP welcome '{welcome}' from {dev.ip}")
            return None

    def _do(self, func: str, *args) -> list | str | None:
        try:
            resp = getattr(self.ftp, func)(*args)
            self.all_output.append((func, resp))
            return resp
        except ftplib.all_errors as ex:
            self.log.debug(f"Action '{func}' failed: {ex}")
            return None


__all__ = ["FTP"]
