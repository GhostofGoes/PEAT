from __future__ import annotations

import copy
import json
import re
import socket
import ssl
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any, Literal

from bs4 import BeautifulSoup
from requests import Response, Session
from requests.auth import HTTPBasicAuth, HTTPDigestAuth, HTTPProxyAuth
from requests.cookies import RequestsCookieJar, merge_cookies
from requests.models import PreparedRequest
from requests.sessions import merge_setting
from requests.structures import CaseInsensitiveDict

import peat  # Avoid circular imports
from peat import config, consts, log, utils

from .cache import NS_HTTP, NS_HTTP_POST, NS_TLS_CERT, CacheKey, data_cache

# Keyword arguments to Requests that can be included in a cache key.
# Requests with any other keyword arguments (e.g. "stream", "hooks",
# "files") are never cached.
_KEYABLE_KWARGS = frozenset(
    {"headers", "cookies", "allow_redirects", "verify", "cert", "proxies", "data", "json"}
)

# Attributes PEAT adds to Response objects, which copy.copy() drops
_RESPONSE_EXTRA_ATTRS = ("request_timestamp", "response_timestamp", "file_path")


def _auth_fingerprint(auth: Any) -> tuple | None:
    """
    Identify the credentials of a Requests "auth" argument.

    The auth object is never called, since some (e.g. ``HTTPDigestAuth``)
    change their state when called. Unknown types of auth return
    :obj:`None`, which means the request is not cached.
    """
    if auth is None:
        return ("none",)
    if isinstance(auth, tuple) and len(auth) == 2:
        return ("basic", str(auth[0]), str(auth[1]))
    if isinstance(auth, HTTPDigestAuth):
        return ("digest", auth.username, auth.password)
    if isinstance(auth, HTTPProxyAuth):  # subclass of HTTPBasicAuth, so check first
        return ("proxy", auth.username, auth.password)
    if isinstance(auth, HTTPBasicAuth):
        return ("basic", auth.username, auth.password)
    return None


def _body_fingerprint(data: Any, json_body: Any) -> tuple | None:
    """
    Identify a request body. File-like objects and generators return :obj:`None`.
    """
    if data is not None and not isinstance(data, (str, bytes, dict, list, tuple)):
        return None
    try:
        return (repr(data), json.dumps(json_body, sort_keys=True, default=str))
    except (TypeError, ValueError):
        return None


def _response_is_cacheable(response: Response | None) -> bool:
    """
    Only successful responses that don't set cookies are cached.

    A response that sets a cookie establishes a session. A cached copy would
    not set the cookie in another caller's session, so it's transient data.
    """
    if response is None or response.status_code != 200:
        return False
    return not any("set-cookie" in r.headers for r in (*response.history, response))


def _response_size(response: Response) -> int:
    headers_size = sum(len(k) + len(v) for k, v in response.headers.items())
    return len(response.content or b"") + headers_size + 512


def _clone_response(response: Response) -> Response:
    """
    Copy of a response that can't affect the original.

    The copy (and the copies of the redirect responses in its ``history``)
    doesn't have the ``raw`` and ``connection`` attributes, so a cached
    response doesn't keep network connection objects in memory.
    """
    clone = copy.copy(response)  # uses Response.__getstate__()
    clone.headers = CaseInsensitiveDict(response.headers)
    clone.cookies = response.cookies.copy()
    clone.history = [_clone_response(hop) for hop in response.history]
    if response.request is not None:
        clone.request = response.request.copy()
    for attr in _RESPONSE_EXTRA_ATTRS:
        setattr(clone, attr, getattr(response, attr, None))
    clone.from_cache = getattr(response, "from_cache", False)
    return clone


def _follower_wait(timeout: Any) -> float:
    """
    Seconds to wait for another thread that's making the same request.
    ``timeout`` may be a number, a ``(connect, read)`` tuple, or :obj:`None`.
    """
    try:
        total = sum(timeout) if isinstance(timeout, (tuple, list)) else float(timeout)
    except (TypeError, ValueError):
        total = 0.0
    return max(30.0, 3 * total)


def _normalize_url(url: str) -> tuple[str, str, int]:
    """
    Normalize a URL for use in a cache key.

    Returns:
        Tuple of (URL, host, port). The URL has a lowercase scheme and host,
        an explicit port, and no fragment.
    """
    parts = urllib.parse.urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = parts.port or (443 if scheme == "https" else 80)
    netloc = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    base = urllib.parse.urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
    return base, host, port


class HTTP:
    """
    Basic set of reusable HTTP functionality.
    """

    USE_CACHE: bool = True
    """
    Default value for the ``use_cache`` argument of :meth:`get` and
    :meth:`get_ssl_certificate`. Subclasses for devices where all
    pages are dynamic can set this to :obj:`False`.
    """

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
    def session(self) -> Session:
        if self._session is None:
            self._session = self.gen_session()
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
                        f_name = fn_match[0].strip('"')

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

    def _cache_key(
        self,
        method: str,
        url: str,
        params: Any,
        auth: Any,
        kwargs: dict[str, Any],
        namespace: str = NS_HTTP,
    ) -> CacheKey | None:
        """
        Build the cache key for a request.

        The key includes everything that can change the response: method,
        URL and parameters, headers and cookies (of the session and the
        request), credentials, body and connection options.

        Returns:
            The key, or :obj:`None` if the request can't be cached
        """
        unknown = set(kwargs) - _KEYABLE_KWARGS
        auth_fp = _auth_fingerprint(auth if auth is not None else self.session.auth)
        body_fp = _body_fingerprint(kwargs.get("data"), kwargs.get("json"))
        if unknown or auth_fp is None or body_fp is None:
            self.log.trace2(f"Not caching {method} {url}: unsupported request options")
            return None

        try:
            base, host, port = _normalize_url(url)
            # Requests uses credentials in the URL if "auth" isn't set
            split_url = urllib.parse.urlsplit(url)
            url_creds = (split_url.username, split_url.password)
            prepped = PreparedRequest()
            prepped.prepare_url(base, params)  # encodes the parameters

            headers = merge_setting(
                kwargs.get("headers"), self.session.headers, dict_class=CaseInsensitiveDict
            )
            header_items = sorted(
                (str(k).lower(), str(v)) for k, v in headers.items() if v is not None
            )

            jar = merge_cookies(RequestsCookieJar(), self.session.cookies)
            jar = merge_cookies(jar, kwargs.get("cookies"))
            cookie_items = sorted((c.domain, c.path, c.name, c.value or "") for c in jar)

            options = (
                kwargs.get("allow_redirects", True),
                kwargs.get("verify", self.session.verify),
                repr(kwargs.get("cert", self.session.cert)),
                repr(sorted((kwargs.get("proxies") or {}).items())),
            )
        except Exception as ex:
            self.log.trace2(f"Not caching {method} {url}: {ex}")
            return None

        variant = data_cache.fingerprint(
            method, prepped.url, url_creds, header_items, cookie_items, auth_fp, options, body_fp
        )

        # The resource is logged, so it excludes the "params" argument
        # (which may contain session tokens) and any credentials in the URL.
        return CacheKey(namespace, host, port, f"{method} {base}", variant)

    def get(
        self,
        page: str = "",
        protocol: Literal["http", "https", ""] = "",
        url: str = "",
        use_cache: bool | None = None,
        params: dict | None = None,
        auth=None,
        allow_errors: bool = False,
        dev: peat.data.models.DeviceData | None = None,
        timeout: float | None = None,
        cache_ttl: float | None = None,
        **kwargs,
    ) -> Response | None:
        """
        Perform a HTTP ``GET`` request and return the response.

        .. warning::
           Successful responses are cached in memory (:mod:`peat.protocols.cache`)
           and reused by any instance of this class (and subclasses) that makes
           an identical request during the same run of PEAT, until they expire
           (:attr:`~peat.settings.Configuration.CACHE_TTL`). Requests with
           different parameters, credentials, headers or cookies are cached
           separately. Responses with an error status code or that set cookies
           are never cached. If the page is dynamic (e.g. status or uptime),
           or your code is looking for changes within a single run of PEAT,
           then set ``use_cache`` to :obj:`False`.

        .. note::
           The response object will have four additional attributes:
           ``request_timestamp``, ``response_timestamp``, ``file_path``,
           and ``from_cache``. For a cached response, the timestamps and
           file path are from the original request.

        Args:
            page: URL path of the page to get
            protocol: Name of the protocol to use
                If empty string (default), the HTTP instance's "protocol" will be used, if set.
                Otherwise, it will default to "http".
            url: URL to use instead of the auto-constructed one
            use_cache: If cached data should be used, and the response cached.
                If :obj:`None`, the class attribute ``USE_CACHE`` is used
                (default: :obj:`True`).
            params: Additional HTTP parameters to include in the request
            auth: Authentication to use for the request (refer to Requests docs)
            allow_errors: Return the response even if the status code is not 200
            dev: DeviceData object to save files to
            timeout: Timeout for the query. If :obj:`None`, the default
                timeout for this class instance is used instead.
            cache_ttl: Seconds the response stays fresh in the cache. If :obj:`None`,
                :attr:`~peat.settings.Configuration.CACHE_TTL` is used.
                A value of ``0`` means the cache is not used for this request.
            kwargs: Additional keyword arguments that will be passed
                directly to ``Requests.get()``

        Returns:
            The response object, or :obj:`None` if the request failed.
            The response object will have four additional attributes:
            ``request_timestamp``, ``response_timestamp``, ``file_path``,
            and ``from_cache``.
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

        if use_cache is None:
            use_cache = self.USE_CACHE

        if not dev and self.dev:
            dev = self.dev

        if timeout is None:
            timeout = self.timeout

        def _fetch() -> Response | None:
            self.log.info(f"GET -> {url}")
            try:
                req_ts = utils.utc_now()  # rough timestamp of send time
                resp: Response = self.session.get(
                    url, timeout=timeout, params=params, auth=auth, **kwargs
                )
            except Exception as ex:
                self.log.warning(f"Failed to GET '{url}': {ex}")
                return None

            # Record where the file was saved as a Path object
            resp.file_path = self._save_response_to_file(resp, page, url, dev)
            # Record rough timestamps of request and response
            resp.request_timestamp = req_ts
            resp.response_timestamp = req_ts + resp.elapsed
            resp.from_cache = False
            return resp

        key = self._cache_key("GET", url, params, auth, kwargs) if use_cache else None
        if key is None:
            response = _fetch()
        else:
            result = data_cache.get_or_fetch(
                key,
                _fetch,
                ttl=cache_ttl,
                store_if=_response_is_cacheable,
                size_of=_response_size,
                copier=_clone_response,
                wait_timeout=_follower_wait(timeout),
            )
            response = result.value
            if result.from_cache:
                response.from_cache = True
                self.log.info(f"GET -> {url} (cached response from {result.age:.1f}s ago)")

        if response is None:
            return None

        if not allow_errors and response.status_code != 200:
            self.log.warning(f"Failed to GET '{url}': status code {response.status_code}")
            return None

        return response

    def post(
        self,
        url: str,
        timeout: float | None = None,
        dev: peat.data.models.DeviceData | None = None,
        use_cache: bool = False,
        cache_ttl: float | None = None,
        **kwargs,
    ) -> Response | None:
        """
        Perform a HTTP ``POST`` request and return the response.

        A successful ``POST`` removes cached ``GET`` responses for the same URL
        from the cache, since the request may have changed the data on the device.

        .. note::
           The response object will have four additional attributes:
           ``request_timestamp``, ``response_timestamp``, ``file_path``,
           and ``from_cache``.

        Args:
            url: URL to use for the request
            timeout: Timeout for the query. If :obj:`None`, the default
                timeout for this class instance is used instead.
            dev: DeviceData object to save files to
            use_cache: If the response should be cached and an identical
                cached ``POST`` response reused. Only use this if the
                ``POST`` doesn't change anything on the device.
                ``GET`` responses are never used for a ``POST``.
            cache_ttl: Seconds the response stays fresh in the cache. If :obj:`None`,
                :attr:`~peat.settings.Configuration.CACHE_TTL` is used.
            kwargs: Additional keyword arguments that will be passed
                directly to ``Requests.post()``

        Returns:
            The response object, or :obj:`None` if the request failed.
            The response object will have four additional attributes:
            ``request_timestamp``, ``response_timestamp``, ``file_path``,
            and ``from_cache``.
        """
        if not dev and self.dev:
            dev = self.dev

        if timeout is None:
            timeout = self.timeout

        def _fetch() -> Response | None:
            self.log.info(f"POST -> {url}")
            try:
                req_ts = utils.utc_now()  # rough timestamp of send time
                resp: Response = self.session.post(url, timeout=timeout, **kwargs)
            except Exception as ex:
                self.log.warning(f"Failed to POST '{url}': {ex}")
                return None

            # Save the raw response text body to disk as an artifact
            parts = urllib.parse.urlparse(url)
            page = parts.path.strip("/")
            # handle paths with args, e.g. ?0x0D00 vs ?0X0000 are different
            if parts.query:
                page = f"{page}{parts.query}.html"

            # Record where the file was saved as a Path object
            resp.file_path = self._save_response_to_file(resp, page, url, dev)
            # Record rough timestamps of request and response
            resp.request_timestamp = req_ts
            resp.response_timestamp = req_ts + resp.elapsed
            resp.from_cache = False
            return resp

        key = None
        if use_cache:
            other_kwargs = {k: v for k, v in kwargs.items() if k not in ("params", "auth")}
            key = self._cache_key(
                "POST",
                url,
                kwargs.get("params"),
                kwargs.get("auth"),
                other_kwargs,
                namespace=NS_HTTP_POST,
            )

        if key is None:
            response = _fetch()
        else:
            result = data_cache.get_or_fetch(
                key,
                _fetch,
                ttl=cache_ttl,
                store_if=_response_is_cacheable,
                size_of=_response_size,
                copier=_clone_response,
                wait_timeout=_follower_wait(timeout),
            )
            response = result.value
            if result.from_cache:
                response.from_cache = True
                self.log.info(f"POST -> {url} (cached response from {result.age:.1f}s ago)")

        if response is None:
            return None

        # A successful POST may change the resource, so drop cached GETs
        # of the same URL (RFC 9111, section 4.4).
        if response.status_code < 400 and not getattr(response, "from_cache", False):
            try:
                base, host, port = _normalize_url(url)
                data_cache.invalidate(
                    namespace=NS_HTTP, host=host, port=port, resource=f"GET {base}"
                )
            except ValueError:
                pass

        if response.status_code != 200:
            self.log.warning(f"Failed to POST '{url}': status code {response.status_code}")
            return None

        return response

    def get_ssl_certificate(self, use_cache: bool | None = None) -> peat.data.models.X509 | None:
        """
        Retrieve and parse the server's SSL certificate.

        The parsed certificate is cached (:mod:`peat.protocols.cache`) and
        reused by other instances of this class for the same IP and port,
        until it expires (:attr:`~peat.settings.Configuration.CACHE_TTL`).
        Each call returns a separate copy.

        Args:
            use_cache: If a cached certificate should be used, and the certificate
                cached. If :obj:`None`, the class attribute ``USE_CACHE`` is used
                (default: :obj:`True`).

        Returns:
            SSL certificate data in Elastic Common Schema (:term:`ECS`)-compliant format
        """
        if not (self.USE_CACHE if use_cache is None else use_cache):
            return self._fetch_ssl_certificate()

        # The TLS handshake uses no client credentials and the
        # server name indication (SNI) is always the IP, so the IP
        # and port identify the server's certificate.
        key = CacheKey(NS_TLS_CERT, self.ip, self.port, f"certificate (sni: {self.ip})")
        result = data_cache.get_or_fetch(
            key,
            self._fetch_ssl_certificate,
            size_of=lambda c: 2 * len(c.original or "") + 2048,
            copier=lambda c: c.copy(deep=True),
            wait_timeout=_follower_wait(self.timeout),
        )

        if result.from_cache:
            self.log.debug(f"Using cached SSL certificate (fetched {result.age:.1f}s ago)")

        return result.value

    def _fetch_ssl_certificate(self) -> peat.data.models.X509 | None:
        """
        Retrieve and parse the server's SSL certificate, without using the cache.
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
    def gen_session() -> Session:
        """
        Session with SSL certificate verification disabled and no
        proxies from environment (e.g. ``http_proxy``/``https_proxy``).
        """
        session = Session()
        session.verify = False
        session.trust_env = False
        return session


__all__ = ["HTTP"]
