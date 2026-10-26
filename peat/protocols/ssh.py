"""
This module handles SSH connections for PEAT modules.

This module provides connection handling, command writing/reading, and all parsing and logging.
This module should be inherited by all additional modules that use SSH connections.

Authors

- Kevin Cox
"""

import base64
import hashlib
import os
import tempfile
import threading
import traceback
from copy import deepcopy
from pathlib import Path
from time import sleep
from typing import Any, Final

import paramiko

import peat
from peat import CommError, config, consts, log, utils

#: Serializes reads and updates of the PEAT known_hosts file between threads
_known_hosts_lock: Final = threading.Lock()

#: Host keys trusted during this run, so they're still checked by later
#: connections if the known_hosts file can't be saved (or saving is disabled)
_session_host_keys: Final = paramiko.HostKeys()

#: known_hosts files that a warning about failing to load or save was logged for
_known_hosts_warned: Final[set[str]] = set()

#: Errors from reading or writing a known_hosts file (ValueError includes
#: UnicodeDecodeError from a file that isn't text)
_KNOWN_HOSTS_ERRORS: Final = (OSError, ValueError, paramiko.SSHException)


def host_key_fingerprint(key: paramiko.PKey) -> str:
    """
    OpenSSH-style SHA256 fingerprint of a SSH host key, e.g. ``SHA256:nThbg6kX...``.
    This is the same format as ``ssh-keygen -lf <key>`` outputs.
    """
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def fingerprint_matches(key: paramiko.PKey, fingerprint: str) -> bool:
    """
    Check if a SSH host key matches a fingerprint, either in OpenSSH SHA256 format
    (``SHA256:<base64>``) or MD5 hex format (``MD5:aa:bb:...`` or ``aabb...``).
    """
    fingerprint = fingerprint.strip()
    if fingerprint.upper().startswith("SHA256:"):
        return host_key_fingerprint(key)[7:] == fingerprint[7:].rstrip("=")

    if fingerprint.upper().startswith("MD5:"):
        fingerprint = fingerprint[4:]
    return key.get_fingerprint().hex() == fingerprint.replace(":", "").lower()


def known_hosts_path() -> Path | None:
    """
    Path to PEAT's SSH known_hosts file, from
    :attr:`SSH_KNOWN_HOSTS <peat.settings.Configuration.SSH_KNOWN_HOSTS>`
    (with ``~`` expanded), or :obj:`None` if saving host keys is disabled.
    """
    if not config.SSH_KNOWN_HOSTS:
        return None
    return Path(config.SSH_KNOWN_HOSTS).expanduser()


def _remove_host(host_keys: paramiko.HostKeys, hostname: str) -> None:
    # "del host_keys[hostname]" only removes the first entry for the host
    while True:
        try:
            del host_keys[hostname]
        except KeyError:
            break


def load_host_keys(path: Path, host_keys: paramiko.HostKeys) -> None:
    """
    Load the keys in a known_hosts file into ``host_keys``, if the file exists.

    The file is read under the same lock used for saving it, so a partially
    written file is never read by another thread.
    """
    with _known_hosts_lock:
        if path.is_file():
            host_keys.load(str(path))


def save_host_key(path: Path, hostname: str, key: paramiko.PKey, replace: bool = False) -> None:
    """
    Add a host key to a known_hosts file, creating the file if needed.

    The file is replaced atomically, so it's never seen partially written,
    even by another process.

    Args:
        path: known_hosts file to update
        hostname: Host name as used by paramiko (``host`` or ``[host]:port``)
        key: The host key to save
        replace: If existing keys for the host should be removed first
    """
    with _known_hosts_lock:
        host_keys = paramiko.HostKeys()
        if path.is_file():
            host_keys.load(str(path))
        elif not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        if replace:
            _remove_host(host_keys, hostname)

        host_keys.add(hostname, key.get_name(), key)

        # Write a temporary file in the same directory and rename it over the
        # file (or a symbolic link's target). mkstemp() creates it with mode 0600.
        real_path = Path(os.path.realpath(path))
        fd, tmp_name = tempfile.mkstemp(
            dir=real_path.parent, prefix=f".{real_path.name}.", suffix=".tmp"
        )
        os.close(fd)
        try:
            host_keys.save(tmp_name)
            os.replace(tmp_name, real_path)
        except BaseException:
            Path(tmp_name).unlink(missing_ok=True)
            raise


def _warn_known_hosts_error(path: Path, action: str, ex: Exception, logger: Any) -> None:
    # Warn once per file, since this would otherwise be logged for every connection
    msg = f"Failed to {action} SSH known_hosts file '{path}': {ex}"
    if str(path) in _known_hosts_warned:
        logger.debug(msg)
        return
    _known_hosts_warned.add(str(path))
    unchecked = "Keys saved in it can't be checked, and h" if action == "load" else "H"
    logger.warning(
        f"{msg}. {unchecked}ost keys trusted in this run are only kept in memory "
        f"(a key that changes during the run is still refused). To not use a PEAT "
        f"known_hosts file, set ssh_known_hosts to an empty string in the config "
        f'(ssh_known_hosts: "").'
    )


class TrustOnFirstUsePolicy(paramiko.MissingHostKeyPolicy):
    """
    Accept and save host keys for hosts that don't have a known key
    (trust on first use, or TOFU), logging a warning with the fingerprint.

    A key that doesn't match a known key is rejected by paramiko
    (:class:`paramiko.BadHostKeyException`) before this policy is used.
    """

    def __init__(self, known_hosts: Path | None, logger: Any, replace: bool = False) -> None:
        self.known_hosts = known_hosts
        self.log = logger
        self.replace = replace

    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey):
        key_str = f"{key.get_name()} {host_key_fingerprint(key)}"
        saved = f", saving it to '{self.known_hosts}'" if self.known_hosts else ""

        if self.replace:
            self.log.warning(
                f"Trusting the SSH host key presented by {hostname} ({key_str}) without "
                f"checking it against known keys, since 'trust_new_host_key' is set{saved}"
            )
        else:
            self.log.warning(
                f"New SSH host key for {hostname}: {key_str}. Trusting it on first use"
                f"{saved}. If possible, check this fingerprint matches the device's key."
            )

        client.get_host_keys().add(hostname, key.get_name(), key)
        with _known_hosts_lock:
            if self.replace:
                _remove_host(_session_host_keys, hostname)
            _session_host_keys.add(hostname, key.get_name(), key)

        if self.known_hosts:
            try:
                save_host_key(self.known_hosts, hostname, key, replace=self.replace)
            except _KNOWN_HOSTS_ERRORS as ex:
                _warn_known_hosts_error(self.known_hosts, "save", ex, self.log)


class PinnedHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """
    Only accept a host key that matches a pinned fingerprint.
    """

    def __init__(self, fingerprint: str) -> None:
        self.fingerprint = fingerprint

    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey):
        if not fingerprint_matches(key, self.fingerprint):
            raise paramiko.SSHException(
                f"SSH host key for {hostname} ({key.get_name()} {host_key_fingerprint(key)}) "
                f"does not match the pinned 'host_key_fingerprint' ({self.fingerprint}). "
                f"The connection was refused and no credentials were sent."
            )
        client.get_host_keys().add(hostname, key.get_name(), key)


class SSH:
    """
    General SSH functionality.

    This is a wrapper around Python's :mod:`paramiko` module.

    Note:
        The SSH class attributes can be overridden by the deriving class, but isn't
        always necessary.

    Args:
        ip (str): Which IP address to use.
        port (int, optional): Which port number to use - default is 22.
        timeout (float, optional): Seconds to wait for command before timing out.
        kwargs (dict[str, any], optional): Additional kwargs for Paramiko.
        ENCODING (str, optional): Encoding to use for parsing.
        POST_WRITE_SLEEP (float, optional): How long to sleep after writing out.
        LINE_TERMINATOR (str, optional): Which line terminator to use for input commands.
        MAX_BYTES (int, optional): Max number of bytes to use when reading from device.
        READ_DELAY (float, optional): How long to sleep before reading output.

    Attributes:
        ENCODING (str, optional): Encoding to use for parsing.
        POST_WRITE_SLEEP (float, optional): How long to sleep after writing out.
        LINE_TERMINATOR (str, optional): Which line terminator to use for input commands.
        MAX_BYTES (int, optional): Max number of bytes to use when reading from device.
        READ_DELAY (float, optional): How long to sleep before reading output.

    Added features:
    - Logging messages
    - Records all commands and responses and saves to a file
    - Simpler function calls
    """

    ENCODING: str = "utf-8"
    POST_WRITE_SLEEP: float = 5.0
    READ_DELAY: float = 0.0
    LINE_TERMINATOR: str = "\n"
    MAX_BYTES: int = 60000

    def __init__(
        self,
        ip: str,
        port: int = 22,
        timeout: float = 5.0,
        username: str | None = None,
        password: str | None = None,
        kwargs: dict[str, Any] | None = None,  # Additional Paramiko input
        host_key_fingerprint: str | None = None,
        trust_new_host_key: bool | None = None,
    ) -> None:
        """
        Args:
            host_key_fingerprint: Only accept a host key with this fingerprint
                (``SHA256:...`` or MD5 hex). If :obj:`None`, the
                ``ssh.host_key_fingerprint`` option of the device is used, if any.
            trust_new_host_key: Accept (and save) the host key the server presents,
                even if it doesn't match the known key. If :obj:`None`, the
                ``ssh.trust_new_host_key`` option of the device is used, if any.
        """
        self.ip: str = ip
        self.port: int = port
        self.timeout: float = timeout
        self.connected: bool = False
        self.raw_output: list[bytes] = []
        self.info: dict[str, Any] = {}
        self.successful_creds: tuple[str, str] | None = None
        self.log = log.bind(
            classname=self.__class__.__name__,
            target=f"{self.ip}:{self.port}",
        )
        self.all_output: list[str] = []
        self.username: str | None = username
        self.password: str | None = password
        if password:
            # Imported here to avoid a circular import
            from peat.log_utils import register_secret

            # The password may not be in the config (e.g. a module's default
            # credentials), so ensure it's redacted from log messages.
            register_secret(password)

        if kwargs is None:
            kwargs = {}

        # Host key verification options. These may be in kwargs (e.g. from
        # device options) and must not be passed to paramiko.
        dev_options: dict = {}
        dev = peat.data.datastore.search(ip, "ip")
        if dev is not None:
            dev_options = dev.options.get("ssh", {})

        kw_fingerprint = kwargs.pop("host_key_fingerprint", None)
        kw_trust_new = kwargs.pop("trust_new_host_key", None)
        if host_key_fingerprint is None:
            host_key_fingerprint = kw_fingerprint or dev_options.get("host_key_fingerprint", "")
        if trust_new_host_key is None:
            if kw_trust_new is not None:
                trust_new_host_key = kw_trust_new
            else:
                trust_new_host_key = dev_options.get("trust_new_host_key", False)

        self.host_key_fingerprint: str = host_key_fingerprint or ""
        self.trust_new_host_key: bool = bool(trust_new_host_key)

        self.kwargs = kwargs  # type: dict[str, Any]

        self._comm: paramiko.SSHClient = paramiko.SSHClient()
        self._channel: paramiko.Channel | None = None
        self.sftp_conn: paramiko.SFTPClient | None = None
        self.log.trace2(f"Initialized {repr(self)}")

    def __enter__(self) -> "SSH":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.disconnect()
        if exc_type:
            self.log.debug(f"Unhandled exception while exiting - {exc_type.__name__}: {exc_val}")
            self.log.trace(
                f"Exception traceback\n"
                f"{''.join(traceback.format_tb(exc_tb))}"
                f"{exc_type.__name__}: {exc_val}",
                self.log,
            )

    @property
    def channel(self) -> paramiko.Channel:
        """
        SSH channel (paramiko.Channel).
        """
        if not self._channel:
            self._channel = self.comm.invoke_shell()

        return self._channel

    @channel.setter
    def channel(self, obj: paramiko.Channel) -> None:
        self._channel = obj

    @property
    def comm(self) -> paramiko.SSHClient:
        """
        Initialize SSH communication.

        Python SSH instance used for interacting with the device.

        Returns:
            paramiko.SSHClient: SSH client used for maintaining connection state.
        """
        if not self.connected:
            try:
                # TODO: this is specific to the Sage,
                # move sage-specific logic into SageSSH.
                kwargs = deepcopy(self.kwargs)
                pkey = kwargs.pop("key_filename", None)
                if not pkey:
                    pkey = kwargs.pop("pkey", None)
                if pkey is not None:
                    pkey = paramiko.RSAKey.from_private_key_file(
                        filename=pkey,
                        password=self.password,
                    )
                # Commenting out overriding paramiko ciphers.
                # Leaving as comment in case unintended results occur
                # paramiko.Transport._preferred_ciphers = ("aes256-cbc", 'ssh-rsa', 'aes256-ctr')

                self._configure_host_key_checking()

                self.log.debug(f"Attempting SSH login with user '{self.username}'")
                self._comm.connect(
                    hostname=self.ip,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    pkey=pkey,
                    timeout=self.timeout,
                    **kwargs,
                )

                self.connected = True
                self.log.info(f"SSH connected to {self.ip}:{self.port}")
            except paramiko.BadHostKeyException as ex:
                self._close()
                kh = known_hosts_path()
                raise CommError(
                    f"SSH host key for {self.ip}:{self.port} has CHANGED! Expected "
                    f"{ex.expected_key.get_name()} {host_key_fingerprint(ex.expected_key)}, "
                    f"got {ex.key.get_name()} {host_key_fingerprint(ex.key)}. Someone may be "
                    f"intercepting the connection (man-in-the-middle), or the device's key "
                    f"was changed (e.g. a firmware update or a replaced device). The "
                    f"connection was refused and no credentials were sent. If the change "
                    f"is expected, remove the old key for the host from "
                    f"{f'{kh} or ' if kh else ''}~/.ssh/known_hosts, pin the new key with "
                    f"the 'ssh.host_key_fingerprint' option, or set the "
                    f"'ssh.trust_new_host_key' option to true for the host."
                ) from None
            except paramiko.AuthenticationException as ex:
                self._close()
                raise paramiko.AuthenticationException(
                    f"Failed to authenticate to {self.ip}:{self.port} "
                    f"with user '{self.username}': {ex}"
                ) from None
            except Exception as ex:
                self._close()
                raise CommError(f"Failed to SSH connect to {self.ip}:{self.port}: {ex}") from ex

        return self._comm

    @comm.setter
    def comm(self, obj: paramiko.SSHClient) -> None:
        self._comm = obj

    def _configure_host_key_checking(self) -> None:
        """
        Configure how the server's host key is checked before authenticating.

        - If a fingerprint is pinned, only a key matching it is accepted.
        - If ``trust_new_host_key`` is set, any key is accepted and saved,
          replacing any known key for the host.
        - Otherwise, keys are checked against the system known_hosts file
          (``~/.ssh/known_hosts``) and PEAT's known_hosts file. A changed key
          is rejected, and a key for a new host is trusted on first use
          and saved to PEAT's known_hosts file.
        """
        if self.host_key_fingerprint:
            # Known keys aren't loaded, so the policy is always used to check the pin
            self._comm.set_missing_host_key_policy(PinnedHostKeyPolicy(self.host_key_fingerprint))
            return

        known_hosts = known_hosts_path()

        if not self.trust_new_host_key:
            try:
                self._comm.load_system_host_keys()
            except _KNOWN_HOSTS_ERRORS as ex:
                self.log.warning(f"Failed to load the system SSH known_hosts file: {ex}")

            host_keys = self._comm.get_host_keys()
            if known_hosts:
                try:
                    # NOTE: not SSHClient.load_host_keys(), so paramiko doesn't save the file
                    load_host_keys(known_hosts, host_keys)
                except _KNOWN_HOSTS_ERRORS as ex:
                    _warn_known_hosts_error(known_hosts, "load", ex, self.log)

            # Keys trusted earlier in this run, which may not have been saved
            with _known_hosts_lock:
                for hostname, keys in _session_host_keys.items():
                    for key_type, key in keys.items():
                        host_keys.add(hostname, key_type, key)

        self._comm.set_missing_host_key_policy(
            TrustOnFirstUsePolicy(known_hosts, self.log, replace=self.trust_new_host_key)
        )

    def open_sftp(self) -> None:
        if self.connected:
            self.sftp_conn = self._comm.open_sftp()

    def sftp_recursive_file_walk(self, directory: str, _paths_done: set | None = None) -> dict:
        if not self.sftp_conn:
            self.log.warning("No sftp connection established in order to walk file structure")
            return {}

        file_info = {directory: []}
        self.log.debug(f"Identifying files in following directory: {directory}")
        metadata = self.sftp_conn.listdir_attr(directory)

        if _paths_done is None:
            _paths_done = set()

        for meta_fl in metadata:
            fl_path = f"{directory}/{meta_fl.filename}"
            fl_permissions = meta_fl.longname.split()[0]

            if "d" in fl_permissions:
                if fl_path in _paths_done:
                    continue
                _paths_done.add(fl_path)
                sub_results = self.sftp_recursive_file_walk(fl_path, _paths_done)
                file_info.update(sub_results)
            else:
                file_info[directory].append(meta_fl)

        return file_info

    def sftp_download_files(self, local_dir: Path, files: list[dict]):
        if not self.sftp_conn:
            self.log.warning("No sftp connection established in order to download files.")
            return False

        self.log.info(f"Downloading {len(files)} files to '{local_dir}'")

        if not local_dir.exists():
            local_dir.mkdir(parents=True, exist_ok=True)

        good = 0
        failed = 0

        for entry in files:
            try:
                # The path comes from the device's file listing,
                # ensure it can't be used to write outside of local_dir.
                save_path = utils.safe_join(local_dir, consts.sanitize_filepath(entry["path"]))
            except ValueError as ex:
                self.log.warning(f"Skipping download of '{entry['path']}': {ex}")
                failed += 1
                continue

            if save_path.exists():
                self.log.debug(f"{save_path} already exists, new file: {entry}")

            try:
                save_path.parent.mkdir(parents=True, exist_ok=True)
                self.log.debug(f"Downloading {entry['path']}")
                self.sftp_conn.get(entry["path"], save_path)
                good += 1
            except Exception as ex:
                self.log.warning(f"Failed to download '{entry['path']}': {ex}")
                failed += 1

        self.log.info(
            f"Finished downloading {len(files)} files to '{local_dir}'. "
            f"{good} downloads were successful, {failed} downloads failed."
        )

        if failed >= 1:
            return False

        return True

    def _close(self) -> None:
        self._comm.close()
        self.connected = False
        self._channel = None

    def test_connection(self) -> bool:
        """
        Test connection to the device.

        Determine if the SSH connection has been established. This is done by simply checking
        the comm variable is initialized.

        Returns:
            Whether the connection has been established or not
        """
        try:
            return self.comm and self.channel.active
        except CommError as ex:
            self.log.error(f"SSH connection test failed: {ex}")
            return False

    def disconnect(self) -> None:
        """
        Disconnect from the device.

        Cleanly disconnect from the device. This function will close the paramiko connection and
        save all read commands.
        """
        if self.connected and self._comm:
            self._close()
            self.log.info(f"SSH disconnected from {self.ip}")

            if self.all_output:
                # Save the raw output to disk as an artifact
                try:
                    dev = peat.data.datastore.get(self.ip)
                    dev.write_file(self.all_output, "ssh-output.json", merge_existing=True)
                except Exception as ex:
                    self.log.warning(f"Failed to write raw SSH output to file: {ex}")

    def write_read(self, command: bytes | str | int) -> str:
        """
        Send a command, then perform a read and return the response.

        Basically, ``self.write(command)`` followed by ``self.read()``.
        """
        self.write(command)
        return self.read()

    def write(
        self,
        command: bytes | str | int,
        flush: bool = False,  # noqa: ARG002
        sensitive: bool = False,
    ) -> None:
        """
        Send the given command to the SSH device.

        Send a SSH command to the device. The input command will be encoded based off of the
        ENCODING attribute.

        Args:
            command: Command to send (this will be automatically encoded)
            flush: If the responses to the command should be dropped
            sensitive: If the command is a secret (e.g. a password), which
                will not be logged and is redacted from all log messages
        """
        if sensitive:
            # Imported here to avoid a circular import
            from peat.log_utils import register_secret

            register_secret(command)
            self.log.debug("Writing SSH command: <redacted>")
        else:
            self.log.debug(f"Writing SSH command: {command}")

        # If it's an int, first convert to a string, which will then be encoded
        if isinstance(command, int):
            command = str(command)

        # If it's a string, encode to bytes with the device's encoding
        if isinstance(command, str):
            command = command.encode(self.ENCODING)

        # Append the line terminator (encode here to ensure proper encoding)
        command += self.LINE_TERMINATOR.encode(self.ENCODING)

        self.channel.sendall(command)
        sleep(self.POST_WRITE_SLEEP)

    def read(
        self,
        delay: float | None = None,
        strip_whitespace: bool = True,
        wait_until_ready: bool = True,
        sleep_between_recvs: bool = True,
    ) -> str:
        """
        Read all data currently in the SSH response buffer.

        This is a stateful operation, so calling this method again will
        not result in the same information. The results are saved in the
        ``all_output`` class attribute for future access.

        Args:
            delay: Seconds to sleep before querying for data
            strip_whitespace: Call ``str.strip()`` on the results
            wait_until_read: Wait until there's data before attempting read
            sleep_between_recvs: Add a sleep between multiple calls to recv

        Returns:
            Decoded data read from the SSH receive stream
        """
        if delay is None:
            delay = self.READ_DELAY

        sleep(delay)

        # Wait until there's data available
        if wait_until_ready:
            while not self.channel.recv_ready():
                sleep(0.1)

        # Pull data while there's still data to get
        output = b""
        while self.channel.recv_ready():
            output += self.channel.recv(self.MAX_BYTES)
            if sleep_between_recvs:
                sleep(0.1)

        return self._add_data(output, strip_whitespace)

    def read_until(
        self,
        until: bytes | str,
        delay: float = 0.15,
        timeout: float | None = None,
        strip_whitespace: bool = True,
    ) -> str:
        """
        Read the SSH response buffer until the specified string is reached.

        This is a stateful operation, so calling this method again will
        not result in the same information. The results are saved in the
        all_output class attribute for future access.

        Note:
            This function is largely a wrapper for read since Paramiko doesn't include
            a read_until method.

        Args:
            until: String to read all data up to.
            delay: Seconds to sleep before querying for data.
            timeout: Seconds to wait for the string before timing out
                (if None, this defaults to the class's timeout configuration).
            strip_whitespace: If ``strip()`` should be called on the results.

        Returns:
            str: Decoded data read from the SSH receive stream
        """
        if isinstance(until, str):
            until = until.encode(self.ENCODING)

        # how long to wait for the expected string to appear
        if timeout is None:
            timeout = self.timeout
        self.channel.settimeout(timeout)

        sleep(delay)

        output = bytearray()
        while True:
            try:
                part = self.channel.recv(self.MAX_BYTES)
                output += part
                if until in output:
                    break
            except TimeoutError:
                break

        return self._add_data(output, strip_whitespace)

    def _add_data(self, raw_data: bytes, strip_whitespace: bool = True) -> str:
        """
        Add the given data to the stored data.

        Decodes and saves responses from device. The input raw_data is decoded based off of the
        ENCODING attribute.

        Args:
            raw_data: Bytes to add to raw data. This is encoded and saved as well.
            strip_whitespace: Whether to strip whitespace or not.
        """
        self.raw_output.append(raw_data)
        data = raw_data.decode(self.ENCODING)

        self.all_output.append(data)
        if strip_whitespace:
            data = data.strip()

        return data

    def login(self, user: str, passwd: str) -> dict | None:
        """
        Login to the device via ssh.

        Login to the ssh device. This function is deferred to the deriving class.

        Args:
            user: Username to login to device
            passwd: Password to login to device

        Returns:
            Connection dict containing successful user and passwd
        """
        pass

    def __str__(self) -> str:
        return self.ip

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.ip}, {self.port}, {self.timeout})"


__all__ = ["SSH"]
