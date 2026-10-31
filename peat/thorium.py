"""
Client for uploading files to `Thorium <https://github.com/cisagov/thorium>`__,
CISA's file analysis and data generation platform.

Used by ``peat import`` to upload files collected from devices (e.g.
configuration files, logic/project files and firmware images) to Thorium,
tagged with information about the device and the PEAT run they came from.

Only the small subset of the Thorium REST API that PEAT needs is implemented
(based on the Thorium Rust client, ``api/src/client/`` in the Thorium repository):

- ``GET /api/users/whoami``: check the connection and credentials
- ``POST /api/users/auth``: exchange a username and password for a token
- ``POST /api/files/``: upload a file (``multipart/form-data``)

Files are always uploaded, since Thorium's file existence check
(``POST /api/files/exists``) reports that a file exists if its hash is visible
to the user in *any* group, regardless of the groups, name and description of
the submission. Thorium stores the contents of a file only once. If the same
user already submitted the file with the same name, description and groups
(e.g. when importing a run again), Thorium adds the tags to the file and
responds with ``409 Conflict``, which is treated as "already submitted".

Authentication uses a Thorium API token, read from the ``PEAT_THORIUM_TOKEN``
environment variable (the token is never written to PEAT's configuration
dumps or logs). Alternatively, a username and password can be included in the
URL (``https://user:password@thorium.example.com/``), which are exchanged for a
token when connecting.
"""

from __future__ import annotations

import base64
import io
import os
import re
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, unquote, urlsplit

import requests

from peat import consts, log

#: Environment variable with the Thorium API token
TOKEN_ENV_VAR = "PEAT_THORIUM_TOKEN"

#: Maximum length of tag keys and values (longer values are truncated)
MAX_TAG_LENGTH = 256

#: Maximum length of a file description (longer descriptions are truncated)
MAX_DESCRIPTION_LENGTH = 1024

#: Timeouts (connect, read) for API requests, in seconds
API_TIMEOUT = (30.0, 60.0)

#: Timeouts (connect, read) for file uploads, in seconds
UPLOAD_TIMEOUT = (30.0, 900.0)

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

_GROUP_SEPARATORS_RE = re.compile(r"[,\s]+")


def clean_text(value: Any, max_length: int = MAX_TAG_LENGTH) -> str:
    """
    Convert a value to a single-line string without control characters,
    truncated to ``max_length`` characters.

    Values from device data are untrusted, and are used in tags,
    descriptions and multipart form headers.
    """
    text = _CONTROL_CHARS_RE.sub(" ", str(value)).strip()
    return text[:max_length]


def parse_groups(groups: str | list[str] | None) -> list[str]:
    """
    Normalize Thorium group names: a list of names and/or a string
    of names separated by commas or whitespace. Duplicates are removed.

    >>> parse_groups("ot-team, ics")
    ['ot-team', 'ics']
    >>> parse_groups(["ot-team,ics", "ics", "lab"])
    ['ot-team', 'ics', 'lab']
    >>> parse_groups(None)
    []
    """
    if not groups:
        return []
    items = [groups] if isinstance(groups, str) else groups
    names: list[str] = []
    for item in items:
        for name in _GROUP_SEPARATORS_RE.split(clean_text(item)):
            if name and name not in names:
                names.append(name)
    return names


def _split_url(url: str) -> tuple[SplitResult, int | None]:
    """
    Split and validate a Thorium URL.

    Error messages don't include the URL, since it may contain a password.

    Raises:
        PeatError: the URL is invalid
    """
    try:
        parts = urlsplit(url)
        port = parts.port  # Raises ValueError if invalid
    except ValueError as ex:
        raise consts.PeatError(f"Invalid Thorium URL: {clean_text(ex, 200)}") from None
    if parts.scheme not in ("http", "https"):
        raise consts.PeatError(
            f"Invalid Thorium URL scheme '{clean_text(parts.scheme, 20)}' "
            f"(must be http:// or https://)"
        )
    if not parts.hostname:
        raise consts.PeatError("Invalid Thorium URL: no hostname")
    return parts, port


class MultipartFileBody:
    """
    A ``multipart/form-data`` request body with text fields and a single
    file, that streams the file from disk instead of reading it into memory
    (``requests`` reads the entire file into memory when using ``files=``).

    The total size is known in advance (``len()``), so ``requests`` sends
    a ``Content-Length`` header instead of using chunked transfer encoding.

    .. note::
       This intentionally doesn't implement ``tell()``/``seek()`` or subclass
       :class:`io.IOBase`, which would make ``requests`` ignore ``len()``.
    """

    def __init__(
        self,
        fields: list[tuple[str, str]],
        file_field: str,
        filename: str,
        path: Path,
    ) -> None:
        self.boundary = uuid.uuid4().hex
        head = b"".join(self._text_part(name, value) for name, value in fields)
        safe_name = clean_text(filename, 255).replace('"', "_").replace("\\", "_")
        head += (
            f"--{self.boundary}\r\n"
            f'Content-Disposition: form-data; name="{file_field}"; filename="{safe_name}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        tail = f"\r\n--{self.boundary}--\r\n".encode()

        self._file = Path(path).open("rb")
        file_size = os.fstat(self._file.fileno()).st_size
        self._size = len(head) + file_size + len(tail)
        self._parts: list[Any] = [io.BytesIO(head), self._file, io.BytesIO(tail)]
        self._index = 0

    def _text_part(self, name: str, value: str) -> bytes:
        name = clean_text(name, MAX_TAG_LENGTH + 10).replace('"', "_").replace("\\", "_")
        return (
            f"--{self.boundary}\r\n"
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
            f"{value}\r\n"
        ).encode()

    @property
    def content_type(self) -> str:
        """Value for the ``Content-Type`` request header."""
        return f"multipart/form-data; boundary={self.boundary}"

    def __len__(self) -> int:
        return self._size

    def read(self, size: int | None = -1) -> bytes:
        if size is None or size < 0:
            size = self._size
        chunks = []
        while size > 0 and self._index < len(self._parts):
            data = self._parts[self._index].read(size)
            if not data:
                self._index += 1
                continue
            chunks.append(data)
            size -= len(data)
        return b"".join(chunks)

    def close(self) -> None:
        self._file.close()


class Thorium:
    """
    Minimal client for the Thorium REST API.

    Args:
        url: URL of the Thorium server (the API is at ``<url>/api/``),
            optionally with a username and password, e.g.
            ``https://user:password@thorium.example.com/``.
        groups: Thorium groups to upload files to (at least one is required
            to upload files), a list and/or a string of names separated by
            commas or whitespace (see :func:`parse_groups`)
        token: Thorium API token. If unset, the ``PEAT_THORIUM_TOKEN``
            environment variable is used, or the username and password
            in ``url`` are exchanged for a token.
        verify_tls: If the server's TLS certificate should be verified
    """

    def __init__(
        self,
        url: str,
        groups: str | list[str] | None = None,
        token: str | None = None,
        verify_tls: bool = True,
    ) -> None:
        if "://" not in url:
            url = f"https://{url}"
        parts, port = _split_url(url)

        self._username = unquote(parts.username) if parts.username else None
        self._password = unquote(parts.password) if parts.password else None
        self._token = token or os.environ.get(TOKEN_ENV_VAR) or None

        host = parts.hostname or ""  # Checked by _split_url()
        if ":" in host:  # IPv6 address
            host = f"[{host}]"
        if port:
            host = f"{host}:{port}"
        path = parts.path.rstrip("/")
        if path.endswith("/api"):
            path = path[: -len("/api")]

        #: Server URL without credentials, e.g. ``https://thorium.example.com``
        self.safe_url = f"{parts.scheme}://{host}{path}"
        self.api_url = f"{self.safe_url}/api"
        self.host = host
        self.groups: list[str] = parse_groups(groups)

        #: If the server's TLS certificate is verified. Passed with every request,
        #: since ``Session.verify`` is overridden by ``REQUESTS_CA_BUNDLE``.
        self.verify_tls = verify_tls
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "PEAT"
        self.log = log.bind(target=self.host)
        self.user: dict[str, Any] = {}

    def __str__(self) -> str:
        return self.host

    def __repr__(self) -> str:  # Never include credentials
        return f'Thorium("{self.safe_url}")'

    def _request(
        self,
        method: str,
        path: str,
        auth: bool = True,
        allow_status: tuple[int, ...] = (),
        **kwargs: Any,
    ) -> requests.Response:
        """
        Send a request to the API and check the response status.

        Args:
            method: HTTP method
            path: Path of the API endpoint, relative to :attr:`api_url`
            auth: If the ``Authorization`` header should be added
            allow_status: Status codes, in addition to 2XX, that aren't errors
            kwargs: Passed to :meth:`requests.Session.request`

        Raises:
            PeatError: request failed or the response status isn't 2XX
                (or in ``allow_status``)
        """
        headers = kwargs.pop("headers", {})
        if auth:
            headers["Authorization"] = self._auth_header()
        kwargs.setdefault("timeout", API_TIMEOUT)
        kwargs["verify"] = self.verify_tls
        url = f"{self.api_url}/{path.lstrip('/')}"
        try:
            resp = self.session.request(method, url, headers=headers, **kwargs)
        except requests.RequestException as ex:
            raise consts.PeatError(
                f"Thorium request {method} {path} to {self.safe_url} failed: {ex}"
            ) from None

        if not resp.ok and resp.status_code not in allow_status:
            detail = clean_text(resp.text, 300) if resp.text else ""
            raise consts.PeatError(
                f"Thorium request {method} {path} failed with HTTP "
                f"{resp.status_code} {resp.reason}: {detail}"
            )
        return resp

    def _json(self, resp: requests.Response) -> Any:
        try:
            return resp.json()
        except ValueError:
            raise consts.PeatError(
                f"Invalid JSON response from Thorium for {resp.request.method} {resp.url}"
            ) from None

    def _auth_header(self) -> str:
        if not self._token:
            if self._username and self._password:
                self._token = self.authenticate()
            else:
                raise consts.PeatError(
                    f"No Thorium API token. Set the {TOKEN_ENV_VAR} environment "
                    f"variable, or include a username and password in the Thorium URL."
                )
        encoded = base64.b64encode(self._token.encode()).decode()
        return f"token {encoded}"

    def authenticate(self) -> str:
        """
        Exchange the username and password from the URL for an API token.

        Returns:
            The token

        Raises:
            PeatError: authentication failed
        """
        creds = base64.b64encode(f"{self._username}:{self._password}".encode()).decode()
        resp = self._request(
            "POST", "users/auth", auth=False, headers={"Authorization": f"basic {creds}"}
        )
        data = self._json(resp)
        # Current Thorium versions: {"Authed": {"token": ..., "expires": ...}}
        if isinstance(data, dict) and isinstance(data.get("Authed"), dict):
            data = data["Authed"]
        if isinstance(data, dict) and isinstance(data.get("token"), str) and data["token"]:
            self.log.debug(f"Authenticated to Thorium as '{clean_text(self._username)}'")
            return data["token"]
        if isinstance(data, dict) and "VerifyEmail" in data:
            raise consts.PeatError("Thorium requires the user's email address to be verified")
        raise consts.PeatError("Unexpected response from Thorium when authenticating")

    def connect(self) -> dict[str, Any]:
        """
        Check the connection and credentials, and that the user is a member
        of the configured :attr:`groups`.

        Returns:
            Information about the authenticated user (``username``, ``groups``, etc.)

        Raises:
            PeatError: the server can't be reached, the credentials are
                invalid, or no groups are configured
        """
        if not self.groups:
            raise consts.PeatError(
                "No Thorium groups configured to upload files to "
                "(THORIUM_GROUPS or --thorium-groups)"
            )
        data = self._json(self._request("GET", "users/whoami"))
        if not isinstance(data, dict):
            raise consts.PeatError("Unexpected response from Thorium for users/whoami")
        self.user = data

        username = clean_text(data.get("username", ""))
        user_groups = data.get("groups")
        self.log.info(f"Connected to Thorium server {self.safe_url} as user '{username}'")
        if isinstance(user_groups, list):
            missing = [g for g in self.groups if g not in user_groups]
            if missing:
                self.log.warning(
                    f"Thorium user '{username}' isn't a member of the group(s) "
                    f"{missing}, uploads will probably fail"
                )
        return data

    def upload_file(
        self,
        path: Path,
        tags: dict[str, list[str] | str] | None = None,
        description: str = "",
        name: str | None = None,
    ) -> dict[str, Any] | None:
        """
        Upload a file to Thorium, to :attr:`groups`.

        The file is streamed from disk (it isn't read into memory).
        Thorium stores the contents only once, and adds a submission
        (with its own name, description and groups) for each upload.

        Args:
            path: The file to upload
            tags: Tags to add to the file, keyed by tag name.
                Values can be a string or a list of strings.
                Empty values are skipped.
            description: Description of the file
            name: File name to use, defaults to the name of ``path``

        Returns:
            The submission information (``sha256``, ``sha1``, ``md5``, ``id``),
            or :obj:`None` if this user already submitted the file with the same
            name, description and groups (``409 Conflict``). Thorium adds the
            tags to the file in that case as well.

        Raises:
            PeatError: the upload failed
        """
        if not self.groups:
            raise consts.PeatError("No Thorium groups configured to upload files to")

        fields: list[tuple[str, str]] = []
        if description:
            fields.append(("description", clean_text(description, MAX_DESCRIPTION_LENGTH)))
        for group in self.groups:
            fields.append(("groups", clean_text(group)))
        for key, values in (tags or {}).items():
            key = clean_text(key)
            for value in [values] if isinstance(values, str) else values:
                value = clean_text(value)
                if key and value:
                    fields.append((f"tags[{key}]", value))
        fields.append(("trigger_depth", "0"))

        body = MultipartFileBody(fields, "data", name or Path(path).name, Path(path))
        try:
            resp = self._request(
                "POST",
                "files/",
                data=body,
                headers={"Content-Type": body.content_type},
                timeout=UPLOAD_TIMEOUT,
                allow_status=(409,),
            )
        finally:
            body.close()

        if resp.status_code == 409:
            return None
        data = self._json(resp)
        if not isinstance(data, dict):
            raise consts.PeatError("Unexpected response from Thorium for a file upload")
        return data


__all__ = ["MultipartFileBody", "Thorium", "parse_groups"]
