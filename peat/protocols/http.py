from __future__ import annotations

import re
import socket
import ssl
import tempfile
import threading
import urllib.parse
from collections import OrderedDict
from pathlib import Path, PurePosixPath
from typing import Final, Literal

import urllib3
from bs4 import BeautifulSoup
from requests import PreparedRequest, Response, Session
from requests.exceptions import SSLError
from requests.structures import CaseInsensitiveDict

import peat  # Avoid circular imports
from peat import config, consts, log, utils

#: Added to errors about failed TLS certificate verification
TLS_VERIFY_HINT: Final[str] = (
    "If the server uses a self-signed or otherwise untrusted certificate (common "
    "with older OT devices), either add its CA certificate to a bundle set with "
    "'tls_ca_bundle', disable verification for that host with "
    "'options: {https: {verify: false}}' in the 'hosts' section of the config file "
    "(or for all devices in 'device_options'), or disable it everywhere with "
    "'tls_verify: false' in the config file or the environment variable "
    "PEAT_TLS_VERIFY=false."
)

#: Maximum size (in bytes) of the body of a HTTP response. Larger responses are
#: refused, so a device can't exhaust memory by sending an endless response.
#: This is generous, since some devices serve firmware or configuration files
#: over HTTP. It can be changed for a request with the ``max_body_size``
#: argument of :meth:`HTTP.get` and :meth:`HTTP.post`.
MAX_HTTP_BODY: Final[int] = 64 * 1024 * 1024

#: Maximum number of redirects followed for a request. Only redirects to
#: the same host are followed. This allows for login pages that redirect
#: several times, but stops a device from redirecting endlessly.
MAX_HTTP_REDIRECTS: Final[int] = 10

#: Maximum number of responses kept in :attr:`HTTP.page_cache`
MAX_PAGE_CACHE_ENTRIES: Final[int] = 256

#: Maximum total size (in bytes) of the response bodies kept in :attr:`HTTP.page_cache`
MAX_PAGE_CACHE_BYTES: Final[int] = 256 * 1024 * 1024

_tls_warned_hosts: Final[set[str]] = set()
_tls_warn_lock: Final = threading.Lock()

#: Hosts that TLS_VERIFY_HINT was logged for, so it's only logged once per host
_tls_hint_hosts: Final[set[str]] = set()

#: CA bundles that an error was logged for, since they don't exist
_tls_bad_ca_bundles: Final[set[str]] = set()


def _ca_bundle_path() -> str:
    # Check the bundle exists, since otherwise every request fails with a
    # generic error ("Could not find a suitable TLS CA certificate bundle")
    bundle = Path(config.TLS_CA_BUNDLE).expanduser()
    if not bundle.is_file():
        with _tls_warn_lock:
            first = str(bundle) not in _tls_bad_ca_bundles
            _tls_bad_ca_bundles.add(str(bundle))
        if first:
            log.error(
                f"The CA certificate bundle set with 'tls_ca_bundle' ('{bundle}') "
                f"doesn't exist or isn't a file, so HTTPS connections will fail. Fix "
                f"the path, or set 'tls_ca_bundle' to an empty string to use the "
                f"default CA certificates."
            )
    return str(bundle)


def resolve_tls_verify(
    host: str = "", device_verify: bool = True, warn: bool = True
) -> bool | str:
    """
    Determine if TLS certificates should be verified for a connection to a host.

    Verification is enabled unless it's been disabled globally with
    :attr:`TLS_VERIFY <peat.settings.Configuration.TLS_VERIFY>` or for the
    device with the ``https.verify`` device option. If verification is disabled,
    a warning is logged (once per host) and urllib3's ``InsecureRequestWarning``
    is silenced, since the user has explicitly chosen to disable it.

    Args:
        host: Host (and optionally port) the connection is for, used for logging
        device_verify: Value of the ``https.verify`` option for the device, if any
        warn: If a warning should be logged when verification is disabled

    Returns:
        Value for the ``verify`` argument of :mod:`requests`: :obj:`False` if
        verification is disabled, the path to the CA bundle set with
        :attr:`TLS_CA_BUNDLE <peat.settings.Configuration.TLS_CA_BUNDLE>`,
        or :obj:`True` to use the default CA certificates.
    """
    if config.TLS_VERIFY and device_verify:
        if config.TLS_CA_BUNDLE:
            return _ca_bundle_path()
        return True

    if warn:
        with _tls_warn_lock:
            first_warning = not _tls_warned_hosts
            already_warned = host in _tls_warned_hosts
            _tls_warned_hosts.add(host)

        if first_warning:
            # The user turned verification off, don't spam warnings for every request
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        if not already_warned:
            if not config.TLS_VERIFY:
                how = "'tls_verify' is false. To enable it, set 'tls_verify: true'"
            else:
                how = (
                    "the device option 'https.verify' is false. To enable it, remove "
                    "the option or set it to true"
                )
            log.warning(
                f"TLS certificate verification is DISABLED for {host or 'all servers'}, "
                f"since {how}. The connection can be intercepted, and any credentials "
                f"sent over it can be captured."
            )

    return False


#: Backslashes, whitespace and control characters, which aren't allowed in
#: redirect targets or links that are followed. URL parsers disagree about
#: them (e.g. :mod:`urllib.parse` and urllib3 on ``http://a\@b/``), so they
#: can make a URL look like it's for one host when the request goes to another.
_UNSAFE_URL_RE: Final[re.Pattern[str]] = re.compile(r"[\\\s\x00-\x1f\x7f-\x9f]")


def is_safe_url(url: str) -> bool:
    """
    If a URL (e.g. a ``Location`` header or a link from a device) has no
    backslashes, whitespace or control characters, which URL parsers disagree about.
    """
    return not _UNSAFE_URL_RE.search(url)


def _normalize_host(host: str) -> str:
    return host.lower().strip("[]").rstrip(".")


def url_hostname(url: str) -> str:
    """
    Host name that :mod:`requests` (urllib3) connects to for a URL (lowercase,
    without the port, IPv6 brackets or a trailing dot), or an empty string
    if the URL doesn't have one or can't be parsed.

    This is computed the same way :mod:`requests` does when sending a request,
    since :mod:`urllib.parse` disagrees with it for some URLs.
    """
    try:
        prepared = PreparedRequest()
        prepared.prepare_url(url, None)
        host = urllib3.util.parse_url(prepared.url).host or ""
    except Exception:
        return ""
    return _normalize_host(host)


def _urllib_hostname(url: str) -> str:
    try:
        host = urllib.parse.urlsplit(url).hostname or ""
        # Same IDNA encoding as requests, so internationalized names compare equal
        return _normalize_host(host.encode("idna").decode("ascii"))
    except (ValueError, UnicodeError):
        return ""


def is_same_host(url: str, other: str) -> bool:
    """
    If two URLs are for the same host. The scheme and port can differ,
    e.g. a redirect from ``http://host/`` to ``https://host/`` is the same host.

    URLs with backslashes, whitespace or control characters are never the
    same host (refer to :func:`is_safe_url`), and both :mod:`requests` and
    :mod:`urllib.parse` must agree on the host of each URL, so a URL crafted
    to be parsed differently by them can't pass the check.
    """
    if not is_safe_url(url) or not is_safe_url(other):
        return False

    host = url_hostname(url)
    if not host or host != url_hostname(other):
        return False

    return _urllib_hostname(url) == host and _urllib_hostname(other) == host


class SameHostSession(Session):
    """
    :class:`requests.Session` that only follows redirects to the same host
    as the request, and at most :data:`~peat.protocols.http.MAX_HTTP_REDIRECTS`
    of them. A redirect to another host isn't followed, and the redirect
    response is returned instead.

    This prevents a device from redirecting PEAT (with the cookies and
    credentials of the session) to other hosts reachable from the system
    running PEAT, and from having the response saved and parsed as if it
    came from the device.
    """

    def __init__(self) -> None:
        super().__init__()
        self.max_redirects = MAX_HTTP_REDIRECTS

    def get_redirect_target(self, resp: Response) -> str | None:
        target = super().get_redirect_target(resp)
        if target is None or resp.request is None or not resp.request.url:
            return target

        if not is_safe_url(target) or not is_same_host(
            urllib.parse.urljoin(resp.request.url, target), resp.request.url
        ):
            return None

        return target


class PageCache:
    """
    Thread-safe cache of HTTP responses, keyed by URL. The least recently
    used responses are removed when there are more than ``max_entries``
    responses, or their bodies total more than ``max_bytes``.
    """

    def __init__(
        self,
        max_entries: int = MAX_PAGE_CACHE_ENTRIES,
        max_bytes: int = MAX_PAGE_CACHE_BYTES,
    ) -> None:
        self.max_entries: int = max_entries
        self.max_bytes: int = max_bytes
        self.total_bytes: int = 0
        self._data: OrderedDict[str, Response] = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def _size(response: Response) -> int:
        content = getattr(response, "_content", None)
        return len(content) if isinstance(content, bytes) else 0

    def get(self, url: str, default: Response | None = None) -> Response | None:
        with self._lock:
            response = self._data.get(url)
            if response is None:
                return default
            self._data.move_to_end(url)
            return response

    def __getitem__(self, url: str) -> Response:
        response = self.get(url)
        if response is None:
            raise KeyError(url)
        return response

    def __setitem__(self, url: str, response: Response) -> None:
        size = self._size(response)
        with self._lock:
            if url in self._data:
                self.total_bytes -= self._size(self._data.pop(url))
            if size > self.max_bytes:
                return  # Too large to cache

            self._data[url] = response
            self.total_bytes += size

            while len(self._data) > self.max_entries or self.total_bytes > self.max_bytes:
                _, removed = self._data.popitem(last=False)
                self.total_bytes -= self._size(removed)

    def __contains__(self, url: object) -> bool:
        with self._lock:
            return url in self._data

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()
            self.total_bytes = 0


class HTTP:
    """
    Basic set of reusable HTTP functionality.
    """

    # Global cache of page data, keyed by URL (bounded in size)
    page_cache: PageCache = PageCache()
    DEFAULT_HEADERS: dict = {}

    def __init__(
        self,
        ip: str,
        port: int = 80,
        timeout: float = 5.0,
        dev: peat.data.models.DeviceData | None = None,
        protocol: Literal["http", "https", ""] = "",
    ) -> None:
        """
        Args:
            ip: IP address of HTTP host
            port: TCP port to use
            timeout: Default timeout for requests
            dev: Default :class:`~peat.data.models.DeviceData` instance to
                use for various things like saving files
        """
        self.ip: str = ip
        self.port: int = port
        self.timeout: float = timeout

        self.protocol: Literal["http", "https", ""] = protocol
        if not self.protocol and self.port == 80:
            self.protocol = "http"
        elif not self.protocol and self.port == 443:
            self.protocol = "https"

        # Instance-level logger
        self.log = log.bind(
            classname=self.__class__.__name__,
            target=f"{self.protocol}://{self.ip}:{self.port}",
        )

        self._session: Session | None = None

        # default device object to use
        self.dev: peat.data.models.DeviceData | None = dev

        # WARNING: do NOT uncomment the code below UNLESS Elasticsearch
        # export is disabled, otherwise all Elasticsearch traffic will
        # be emitted to STDOUT (including logging!).
        #
        # if config.DEBUG >= 3:
        #     # Enable request/response debugging output (print statements)
        #     # can we monkeypatch this so it goes to logging instead of just stdout?
        #     from http.client import HTTPConnection
        #     HTTPConnection.debuglevel = 1

        self.log.trace(f"Initialized {repr(self)}")

    @property
    def url(self) -> str:
        return f"{self.protocol}://{self.ip}:{self.port}"

    @property
    def tls_verify(self) -> bool | str:
        """
        If TLS certificates should be verified for this host, as determined by
        :func:`~peat.protocols.http.resolve_tls_verify` using the global
        configuration and the device's ``https.verify`` option.
        """
        dev = self.dev
        if dev is None:
            dev = peat.data.datastore.search(self.ip, "ip")

        device_verify = True
        if dev is not None:
            device_verify = bool(dev.options.get("https", {}).get("verify", True))

        return resolve_tls_verify(
            host=f"{self.ip}:{self.port}",
            device_verify=device_verify,
            warn=self.protocol != "http",
        )

    def ssl_context(self) -> ssl.SSLContext:
        """
        SSL context for raw TLS sockets that honors the TLS verification settings
        (refer to :attr:`~peat.protocols.http.HTTP.tls_verify`).
        """
        verify = self.tls_verify
        if verify is False:
            context = ssl._create_unverified_context()
        else:
            context = ssl.create_default_context(
                cafile=verify if isinstance(verify, str) else None
            )
        # Python 3.10+ already defaults to this; set it explicitly so the
        # minimum is not left to the interpreter's build-time defaults.
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context

    @property
    def session(self) -> Session:
        if self._session is None:
            self._session = self.gen_session(verify=self.tls_verify)
            if self.DEFAULT_HEADERS:
                self._session.headers.update(self.DEFAULT_HEADERS)
        return self._session

    @session.setter
    def session(self, sess: Session) -> None:
        if self._session is not None:
            self._session.close()
        self._session = sess

    @property
    def connected(self) -> bool:
        return bool(self._session)

    def disconnect(self) -> None:
        if self._session is not None:
            self._session.close()

    def __enter__(self) -> HTTP:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.disconnect()
        if exc_type:
            self.log.debug(f"{exc_type.__name__}: {exc_val}")

    def __str__(self) -> str:
        return self.ip

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.ip}, {self.port}, {self.timeout})"

    def _request(
        self,
        method: str,
        url: str,
        timeout: float,
        max_body_size: int | None = None,
        **kwargs,
    ) -> Response:
        """
        Send a request, following redirects only to the same host (at most
        :data:`~peat.protocols.http.MAX_HTTP_REDIRECTS` of them), and read
        the body of the response, up to ``max_body_size`` bytes.

        A redirect that isn't followed (to another host, or after too many
        redirects) is logged, and the redirect response is returned, the same
        as :class:`~peat.protocols.http.SameHostSession` does.

        Raises:
            CommError: The response body was larger than ``max_body_size``
        """
        if max_body_size is None:
            max_body_size = MAX_HTTP_BODY

        # The response is always streamed, so the size of the body can be limited
        kwargs.pop("stream", None)
        follow_redirects = kwargs.pop("allow_redirects", True)

        response: Response = self.session.request(
            method, url, timeout=timeout, allow_redirects=False, stream=True, **kwargs
        )

        history: list[Response] = []
        while follow_redirects and response.is_redirect:
            code = response.status_code
            location = Session.get_redirect_target(self.session, response) or ""
            target = urllib.parse.urljoin(response.url, location)

            if not is_safe_url(location) or not is_same_host(target, url):
                self.log.warning(
                    f"Not following redirect ({code}) from '{response.url}' "
                    f"to a different host: {location!r}"
                )
                break

            if len(history) >= MAX_HTTP_REDIRECTS:
                self.log.warning(
                    f"Not following redirect ({code}) from '{response.url}': "
                    f"too many redirects (more than {MAX_HTTP_REDIRECTS})"
                )
                break

            # Don't read the body of redirect responses that are followed
            response.close()

            # Change the method the same way requests and browsers do
            if method != "HEAD" and (code in (302, 303) or (code == 301 and method == "POST")):
                method = "GET"
                for key in ("data", "json", "files"):
                    kwargs.pop(key, None)

            # The query parameters are in the redirect target, if any
            kwargs.pop("params", None)

            # Don't send credentials if the scheme or port changes (except
            # http to https on the default ports), the same as requests does
            # when it follows redirects, e.g. for a redirect to plain HTTP.
            if self.session.should_strip_auth(response.url, target):
                kwargs.pop("auth", None)
                headers = CaseInsensitiveDict(kwargs.get("headers") or {})
                headers["Authorization"] = None  # Removes the session's header too
                kwargs["headers"] = headers

            self.log.debug(f"Following redirect ({code}) from '{response.url}' to '{target}'")
            history.append(response)
            response = self.session.request(
                method, target, timeout=timeout, allow_redirects=False, stream=True, **kwargs
            )

        response.history = history
        self._read_body(response, max_body_size)

        return response

    @staticmethod
    def _read_body(response: Response, max_size: int) -> None:
        """
        Read the body of a streamed response, refusing it if it's larger than
        ``max_size`` bytes. Afterwards, it's available as usual with
        ``response.content``, ``response.text``, etc.
        """
        try:
            declared = int(response.headers.get("content-length", ""))
        except ValueError:
            declared = -1

        if declared > max_size:
            response.close()
            raise consts.CommError(
                f"response body is too large ({declared} bytes, limit is {max_size} bytes)"
            )

        body = bytearray()
        for chunk in response.iter_content(chunk_size=64 * 1024):
            body += chunk
            if len(body) > max_size:
                response.close()
                raise consts.CommError(
                    f"response body is too large (more than {max_size} bytes, the limit)"
                )

        response._content = bytes(body)
        response._content_consumed = True

    def _save_response_to_file(
        self,
        response: Response,
        page: str,
        url: str,
        dev: peat.data.models.DeviceData | None,
    ) -> Path | None:
        """
        Save raw text data from response to disk, even if bad status code.
        """
        try:
            if response.text:
                f_name = ""

                cd = response.headers.get("content-disposition", "")
                if cd and "filename" in cd:
                    fn_match = re.findall(r"filename=(.+)", cd)
                    if fn_match:
                        # Only use the final component of the name the server
                        # suggests, per RFC 6266, so it can't select the directory.
                        f_name = fn_match[0].split(";")[0].strip().strip("\"'")
                        f_name = PurePosixPath(f_name.replace("\\", "/")).name

                if not f_name:
                    if not page and url:
                        parts = urllib.parse.urlparse(url)
                        page = parts.path.strip("/")
                        # handle paths with args, e.g. ?0x0D00 vs ?0X0000 are different
                        if parts.query:
                            page = f"{page}{parts.query}.html"

                    if not page or page == "/":
                        f_name = "index.html"
                    elif page.endswith(".html") or page.endswith(".htm"):
                        f_name = page
                    else:
                        f_name = f"{page}.html"

                if not dev:
                    dev = peat.data.datastore.get(self.ip)

                # Sanitize characters that are invalid filenames on Windows
                # This avoids a warning in utils.write_file()
                for char in ["?", ":", '"']:
                    if char in f_name:
                        f_name = f_name.replace(char, "_")

                path = dev.write_file(
                    response.text,
                    filename=f_name,
                    out_dir=dev.get_sub_dir("http_files"),
                )

                dev.related.files.add(f_name)

                self.log.trace2(f"Saved response from {url} to {path.as_posix()}")

                return path
        except Exception:
            self.log.exception(f"Failed to write page '{page}' to file")

    def get(
        self,
        page: str = "",
        protocol: Literal["http", "https", ""] = "",
        url: str = "",
        use_cache: bool = True,
        params: dict | None = None,
        auth=None,
        allow_errors: bool = False,
        dev: peat.data.models.DeviceData | None = None,
        timeout: float | None = None,
        max_body_size: int | None = None,
        **kwargs,
    ) -> Response | None:
        """
        Perform a HTTP ``GET`` request and return the response.

        Redirects are only followed to the same host, and at most
        :data:`~peat.protocols.http.MAX_HTTP_REDIRECTS` of them. If a redirect
        isn't followed, the redirect response is returned if ``allow_errors``
        is set, otherwise the request fails.

        .. warning::
           Results of queries for an identical URL are cached by default for
           a single run of PEAT. If your tool is querying the status or looking
           for changes within a single run of PEAT, then set ``use_cache``
           to :obj:`False`.

        .. note::
           The response object will have three additional attributes:
           ``request_timestamp``, ``response_timestamp``, ``file_path``.

        Args:
            page: URL path of the page to get
            protocol: Name of the protocol to use
                If empty string (default), the HTTP instance's "protocol" will be used, if set.
                Otherwise, it will default to "http".
            url: URL to use instead of the auto-constructed one
            use_cache: If the internal page cache should be used.
            params: Additional HTTP parameters to include in the request
            auth: Authentication to use for the request (refer to Requests docs)
            dev: DeviceData object to save files to
            timeout: Timeout for the query. If :obj:`None`, the default
                timeout for this class instance is used instead.
            max_body_size: Maximum size of the response body, in bytes.
                If :obj:`None`, :data:`~peat.protocols.http.MAX_HTTP_BODY` is used.
            kwargs: Additional keyword arguments that will be passed
                directly to ``Requests.get()``

        Returns:
            The response object, or :obj:`None` if the request failed.
            The response object will have three additional attributes:
            ``request_timestamp``, ``response_timestamp``, ``file_path``.
        """
        if not protocol and self.protocol:
            protocol = self.protocol
        elif not protocol:
            protocol = "http"

        if not url:
            if protocol == "https" and self.port == 80:  # TODO: hack
                self.log.debug(
                    f"Protocol is https and port is 80, hardcoding "
                    f"to port 443 for request for page {page}"
                )
                port = 443
            else:
                port = self.port

            # trim leading slash for ergonomics
            if page.startswith("/"):
                page = page[1:]

            # TODO: use urllib.parse.urljoin()
            url = f"{protocol}://{self.ip}:{port}/{page}"

        # TODO: add a lifetime to the cache
        if use_cache and self.page_cache.get(url):
            self.log.info(f"GET -> {url} (using cached response)")
            return self.page_cache[url]

        self.log.info(f"GET -> {url}")

        if not dev and self.dev:
            dev = self.dev

        if timeout is None:
            timeout = self.timeout

        try:
            req_ts = utils.utc_now()  # rough timestamp of send time

            response = self._request(
                "GET",
                url,
                timeout=timeout,
                max_body_size=max_body_size,
                params=params,
                auth=auth,
                **kwargs,
            )

            file_path = self._save_response_to_file(response, page, url, dev)

            if not allow_errors and response.status_code != 200:
                err = f"status code {response.status_code}"
            else:
                # Record rough timestamps of request and response
                response.request_timestamp = req_ts
                response.response_timestamp = req_ts + response.elapsed
                # Record where the file was saved as a Path object
                response.file_path = file_path
                self.page_cache[url] = response
                return response
        except SSLError as ex:
            self._log_tls_failure("GET", url, ex)
            return None
        except Exception as ex:
            err = str(ex)

        self.log.warning(f"Failed to GET '{url}': {err}")
        return None

    def post(
        self,
        url: str,
        timeout: float | None = None,
        dev: peat.data.models.DeviceData | None = None,
        use_cache: bool = False,
        max_body_size: int | None = None,
        **kwargs,
    ) -> Response | None:
        """
        Perform a HTTP ``POST`` request and return the response.

        Redirects are only followed to the same host, and at most
        :data:`~peat.protocols.http.MAX_HTTP_REDIRECTS` of them. If a redirect
        isn't followed, the request fails.

        .. note::
           The response object will have three additional attributes:
           ``request_timestamp``, ``response_timestamp``, ``file_path``.

        Args:
            url: URL to use for the request
            timeout: Timeout for the query. If :obj:`None`, the default
                timeout for this class instance is used instead.
            dev: DeviceData object to save files to
            use_cache: If the internal page cache should be used
            max_body_size: Maximum size of the response body, in bytes.
                If :obj:`None`, :data:`~peat.protocols.http.MAX_HTTP_BODY` is used.
            kwargs: Additional keyword arguments that will be passed
                directly to ``Requests.post()``

        Returns:
            The response object, or :obj:`None` if the request failed.
            The response object will have three additional attributes:
            ``request_timestamp``, ``response_timestamp``, ``file_path``.
        """

        # TODO: add a lifetime to the cache
        if use_cache and self.page_cache.get(url):
            self.log.info(f"POST -> {url} (using cached response)")
            return self.page_cache[url]

        self.log.info(f"POST -> {url}")

        if not dev and self.dev:
            dev = self.dev

        if timeout is None:
            timeout = self.timeout

        try:
            req_ts = utils.utc_now()  # rough timestamp of send time

            response = self._request(
                "POST", url, timeout=timeout, max_body_size=max_body_size, **kwargs
            )

            # Save the raw response text body to disk as an artifact
            parts = urllib.parse.urlparse(url)
            page = parts.path.strip("/")
            # handle paths with args, e.g. ?0x0D00 vs ?0X0000 are different
            if parts.query:
                page = f"{page}{parts.query}.html"

            file_path = self._save_response_to_file(response, page, url, dev)

            if response.status_code != 200:
                err = f"status code {response.status_code}"
            else:
                # Record rough timestamps of request and response
                response.request_timestamp = req_ts
                response.response_timestamp = req_ts + response.elapsed
                # Record where the file was saved as a Path object
                response.file_path = file_path
                self.page_cache[url] = response

                return response
        except SSLError as ex:
            self._log_tls_failure("POST", url, ex)
            return None
        except Exception as ex:
            err = str(ex)

        self.log.warning(f"Failed to POST '{url}': {err}")
        return None

    def _log_tls_failure(self, method: str, url: str, ex: Exception) -> None:
        """
        Log a failed TLS certificate verification, with :data:`TLS_VERIFY_HINT`
        the first time for a host, and at DEBUG level after that, since
        scanning a network with self-signed devices would otherwise be very noisy.
        """
        host = urllib.parse.urlsplit(url).netloc
        with _tls_warn_lock:
            first = host not in _tls_hint_hosts
            _tls_hint_hosts.add(host)

        msg = f"Failed to {method} '{url}': TLS certificate verification failed: {ex}"
        if first:
            self.log.warning(f"{msg}. {TLS_VERIFY_HINT}")
        else:
            self.log.debug(msg)

    def get_ssl_certificate(self) -> peat.data.models.X509 | None:
        """
        Retrieve and parse the server's SSL certificate.

        Returns:
            SSL certificate data in Elastic Common Schema (:term:`ECS`)-compliant format
        """
        emsg = "Failed to get SSL certificate"

        try:
            # (01/04/2022) Workaround issues in newer Pythons (3.10+)
            # with ssl.get_server_certificate() when used with older
            # ICS/OT devices (in other words, what PEAT does).
            #
            # References:
            #   https://stackoverflow.com/a/49132495
            #   https://stackoverflow.com/a/71007463
            #
            # These code snippets may be useful in future:
            #   context.options &= ~ssl.OP_NO_SSLv3
            #   context.check_hostname = False
            #   context.verify_mode = ssl.CERT_NONE
            #
            # NOTE: the certificate is deliberately NOT verified here, since
            # this only records the certificate (no credentials are sent).
            #
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.set_ciphers("DEFAULT")

            with socket.create_connection(
                address=(self.ip, self.port), timeout=self.timeout
            ) as connection:
                with context.wrap_socket(connection, server_hostname=self.ip) as ssl_sock:
                    der_cert = ssl_sock.getpeercert(True)

            if not der_cert:
                self.log.warning(f"{emsg}: No certificate returned from server")
                return None

            raw_cert = ssl.DER_cert_to_PEM_cert(der_cert)  # type: str
        except Exception as ex:
            self.log.exception(f"{emsg}: {ex}")
            return None

        if not raw_cert:
            self.log.warning(f"{emsg}: Empty certificate or no certificate was returned")
            return None

        decoded = self.decode_ssl_certificate(raw_cert)

        return self.parse_decoded_ssl_certificate(decoded[0], decoded[1])

    def decode_ssl_certificate(
        self, source: str | bytes | Path
    ) -> tuple[dict[str, str | tuple | int], str]:
        """
        Decode a raw SSL certificate retrieved from a server into
        a raw :class:`dict`.

        Args:
            source: SSL certificate in string or bytes format, or the file path
                to a certificate (as a :class:`~pathlib.Path` object).

        Returns:
            Decoded SSL certificate data as a :class:`dict`
        """
        tmp_name_base = f"{self.ip.replace('.', '_')}_{self.port}"

        if isinstance(source, Path):
            raw = source.read_text(encoding="utf-8")
            path = source.resolve()
        else:
            raw = source
            if isinstance(raw, bytes):
                raw = raw.decode()

            f_name = f"{tmp_name_base}_raw-ssl-certificate.crt"
            if config.TEMP_DIR:
                path = utils.write_temp_file(raw, f_name)
            else:
                # Create a temporary directory to put the cert data to be parsed
                t_dir = tempfile.mkdtemp()
                path = Path(t_dir, f_name)
                path.write_text(raw, encoding="utf-8")

        # Source: https://stackoverflow.com/a/50072461
        decoded = ssl._ssl._test_decode_cert(path)
        utils.write_temp_file(decoded, f"{tmp_name_base}_decoded-ssl-certificate.json")
        self.log.trace2(f"Decoded SSL cert\n{decoded}")

        return decoded, raw

    def parse_decoded_ssl_certificate(
        self, decoded: dict[str, str | tuple | int], raw: str
    ) -> peat.data.models.X509:
        """
        Parse a decoded SSL certificate into Elastic Common Schema (:term:`ECS`)
        format usable with the x509 data model (:class:`~peat.data.models.X509`).

        Args:
            decoded: Decoded SSL certificate, usually obtained from calling
                :meth:`~peat.protocols.http.decode_ssl_certificate`.
            raw: The original SSL certificate text

        Returns:
            SSL certificate data in Elastic Common Schema (:term:`ECS`)-compliant format
        """
        serial_number = str(decoded.get("serialNumber", ""))
        serial_number = serial_number.strip().upper().replace(":", "")

        # NOTE: hashes will get generated by annotate()
        cert = peat.data.models.X509(
            original=raw,
            serial_number=serial_number,
            version_number=str(decoded.get("version", "")),
            not_after=(utils.parse_date(decoded["notAfter"]) if decoded.get("notAfter") else None),
        )

        if decoded.get("notAfter"):
            cert.not_after = utils.parse_date(decoded["notAfter"])
        if decoded.get("notBefore"):
            cert.not_before = utils.parse_date(decoded["notBefore"])

        # Extract Issuer and Subject fields
        alternative_names = set()
        for group in ["issuer", "subject"]:
            if group not in decoded:
                continue

            entity = peat.data.models.CertEntity()

            for field in decoded[group]:
                if len(field) > 1 or len(field[0]) > 2:
                    self.log.warning(f"Abnormal length for SSL field {field}")

                f_name = utils.convert_to_snake_case(field[0][0])
                if "common" not in f_name and "distinguished" not in f_name:
                    f_name = f_name.replace("_name", "")

                val = str(field[0][1]).strip()

                if hasattr(entity, f_name):
                    setattr(entity, f_name, val)
                elif f_name == "email_address":
                    alternative_names.add(val)
                else:
                    self.log.warning(
                        f"Skipping value '{f_name}' with value '{val}' for "
                        f"'{group}' since it's not a valid CertEntity field"
                    )

            setattr(cert, group, entity)

        cert.alternative_names.extend(alternative_names)
        cert.annotate(None)
        self.log.trace2(f"Parsed SSL cert\n{cert}")

        return cert

    @staticmethod
    def gen_soup(text: str | bytes) -> BeautifulSoup:
        """
        Generate a BeautifulSoup instance from the text using the efficient
        ``lxml`` library if it's available or ``html.parser`` otherwise.

        Returns:
            A ``bs4.BeautifulSoup`` instance with the parser set to
                the value of :data:`peat.consts.BS4_PARSER`
        """
        return BeautifulSoup(text, features=consts.BS4_PARSER)

    @staticmethod
    def gen_session(verify: bool | str | None = None) -> Session:
        """
        Session with no proxies, ``.netrc`` credentials, or CA bundles
        from the environment (e.g. ``https_proxy`` or ``REQUESTS_CA_BUNDLE``),
        that only follows redirects to the same host
        (refer to :class:`~peat.protocols.http.SameHostSession`).

        Args:
            verify: TLS certificate verification setting for the session
                (the ``verify`` argument of :mod:`requests`). If :obj:`None`,
                the global configuration is used (refer to
                :func:`~peat.protocols.http.resolve_tls_verify`).
        """
        if verify is None:
            verify = resolve_tls_verify()

        session = SameHostSession()
        session.verify = verify
        session.trust_env = False
        return session


__all__ = [
    "HTTP",
    "MAX_HTTP_BODY",
    "MAX_HTTP_REDIRECTS",
    "TLS_VERIFY_HINT",
    "PageCache",
    "SameHostSession",
    "is_safe_url",
    "is_same_host",
    "resolve_tls_verify",
    "url_hostname",
]
