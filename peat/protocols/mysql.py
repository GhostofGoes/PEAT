"""MySQL/MariaDB connection protocol for PEAT."""

from __future__ import annotations

import socket
import ssl
from typing import Any

import pymysql
import pymysql.cursors
from pymysql.constants import CLIENT

from peat import CommError, log


def _is_cert_verify_error(exc: BaseException) -> bool:
    # PyMySQL wraps socket errors in OperationalError, with the original
    # exception in "original_exception"
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, ssl.SSLCertVerificationError):
            return True
        current = (
            getattr(current, "original_exception", None)
            or current.__cause__
            or current.__context__
        )
    return False


def quote_identifier(name: str) -> str:
    """
    Quote a MySQL identifier (e.g. a database or table name) with backticks,
    escaping any backticks in it, so it can be safely used in a query.
    """
    return "`" + str(name).replace("`", "``") + "`"


class MySQL:
    """
    MySQL/MariaDB connection wrapper.

    A thin wrapper around PyMySQL for connecting to and querying
    MySQL/MariaDB servers. The underlying connection is established
    lazily on first use via the :attr:`conn` property.

    Args:
        ip: Server hostname or IP address.
        port: MySQL port (default 3306).
        username: MySQL username.
        password: MySQL password.
        database: Default database to connect to (optional).
        timeout: Connection and query timeout in seconds.
        tls_verify: If the server's TLS certificate should be verified, or the
            path to a CA bundle to verify it with. If :obj:`None` (the default),
            this is determined by :func:`~peat.protocols.http.resolve_tls_verify`
            (the :attr:`TLS_VERIFY <peat.settings.Configuration.TLS_VERIFY>` and
            :attr:`TLS_CA_BUNDLE <peat.settings.Configuration.TLS_CA_BUNDLE>`
            settings, and the ``https.verify`` option of the device), the same
            as for HTTPS.

    .. note::
       TLS is required. If the server doesn't offer TLS (or an attacker
       removed the offer from its greeting), the connection is refused
       before any credentials are sent.
    """

    def __init__(
        self,
        ip: str,
        port: int = 3306,
        username: str = "root",
        password: str = "",
        database: str = "",
        timeout: float = 10.0,
        tls_verify: bool | str | None = None,
    ) -> None:
        self.ip = ip
        self.port = port
        self.username = username
        self.password = password
        self.database = database
        self.timeout = timeout
        self.tls_verify = tls_verify
        self._conn = None
        self.server_info: str = ""
        self.server_version: tuple[int, ...] = ()

        self.log = log.bind(
            classname=self.__class__.__name__,
            target=f"{self.ip}:{self.port}",
        )

    def __enter__(self) -> MySQL:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.disconnect()

    @staticmethod
    def read_greeting(ip: str, port: int = 3306, timeout: float = 5.0) -> str | None:
        """
        Read the MySQL/MariaDB initial handshake packet over a raw TCP connection.

        MySQL sends a greeting immediately after TCP connect, before any
        authentication. This allows fingerprinting the server without credentials.

        The packet layout (Protocol v10, used since MySQL 4.1):

        - bytes 0-2: payload length (little-endian uint24)
        - byte  3:   sequence number (``0x00``)
        - byte  4:   protocol version (``0x0a`` = 10)
        - bytes 5-N: server version string, null-terminated

        Args:
            ip: Server IP address or hostname.
            port: MySQL port (default 3306).
            timeout: Seconds to wait for the greeting.

        Returns:
            The null-terminated version string (e.g. ``"8.0.32"`` or
            ``"10.6.12-MariaDB"``), or ``None`` if the host did not respond
            with a valid MySQL greeting.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((ip, port))
                data = sock.recv(256)
        except Exception as exc:
            log.debug(f"MySQL greeting read failed ({ip}:{port}): {exc}")
            return None

        if len(data) < 6 or data[4] != 0x0A:
            return None

        try:
            null_pos = data.index(b"\x00", 5)
            return data[5:null_pos].decode("ascii", errors="replace")
        except ValueError:
            return None

    def ssl_context(self) -> ssl.SSLContext:
        """
        SSL context for the connection, that verifies the server's certificate
        unless verification has been disabled (refer to ``tls_verify``).
        """
        verify = self.tls_verify
        if verify is None:
            # Imported here to avoid a circular import
            from peat.protocols.http import device_tls_verify, resolve_tls_verify

            verify = resolve_tls_verify(
                host=f"{self.ip}:{self.port}", device_verify=device_tls_verify(self.ip)
            )

        if verify is False:
            context = ssl._create_unverified_context()
        else:
            context = ssl.create_default_context(
                cafile=verify if isinstance(verify, str) else None
            )
        # Same minimum as the SSL contexts built in peat.protocols.http
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context

    @property
    def connected(self) -> bool:
        """True if currently connected to a MySQL server."""
        return self._conn is not None

    @property
    def conn(self):
        """
        PyMySQL connection, established lazily on first access.

        Raises:
            CommError: If the connection attempt fails.
        """
        if self._conn is not None:
            return self._conn

        try:
            self._conn = self._connect_tls()
            self.server_info = self._conn.get_server_info()

            version_str = self.server_info.split("-")[0]
            try:
                self.server_version = tuple(int(x) for x in version_str.split("."))
            except ValueError:
                self.log.trace(f"Could not parse server version from {self.server_info!r}")
                self.server_version = ()

            self.on_connected()

        except Exception as exc:
            self.disconnect()
            msg = f"MySQL connect failed ({self.ip}:{self.port}): {exc}"
            if _is_cert_verify_error(exc):
                # Imported here to avoid a circular import
                from peat.protocols.http import log_tls_verify_failure

                log_tls_verify_failure(
                    self.log,
                    f"{self.ip}:{self.port}",
                    f"MySQL connect failed: TLS certificate verification failed: {exc}",
                )
            raise CommError(msg) from exc

        return self._conn

    def _connect_tls(self):
        """
        Connect and authenticate, refusing the connection if it isn't
        encrypted with TLS.

        PyMySQL only upgrades to TLS if the server's greeting says it supports
        it (depending on the version, even when given an SSL context), so an
        attacker could remove that from the greeting and receive the
        authentication in cleartext. The check runs after the greeting is
        read and before authentication.
        """
        conn = pymysql.connect(
            host=self.ip,
            port=self.port,
            user=self.username,
            password=self.password,
            database=self.database or None,
            connect_timeout=int(self.timeout),
            read_timeout=int(self.timeout),
            write_timeout=int(self.timeout),
            autocommit=True,
            ssl=self.ssl_context(),
            defer_connect=True,
        )
        authenticate = conn._request_authentication

        def _require_tls() -> None:
            if not conn.server_capabilities & CLIENT.SSL:
                raise CommError(
                    "the server doesn't support TLS, refusing to send credentials unencrypted"
                )
            authenticate()

        conn._request_authentication = _require_tls
        conn.connect()

        if getattr(conn, "_secure", False) is not True:
            try:
                conn.close()
            except Exception:
                pass
            raise CommError("the connection isn't encrypted with TLS")

        return conn

    def connect(self) -> bool:
        """
        Explicitly establish an authenticated connection to the MySQL server.

        Calling this is optional — the connection is also established
        automatically on first use of any query method.

        Returns:
            True if the connection succeeded, False otherwise.
        """
        try:
            _ = self.conn
            return True
        except CommError as exc:
            self.log.debug(str(exc))
            return False

    def disconnect(self) -> None:
        """Close the MySQL connection."""
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass

            self._conn = None

    def on_connected(self) -> None:
        """
        Hook called immediately after a successful authenticated connection.

        Override in subclasses to run device-specific setup queries or
        populate additional instance attributes before enumeration begins.
        """

    def enumerate(self) -> dict[str, Any]:
        """
        Hook for device-specific enumeration queries.

        Override in subclasses to run additional queries and return the
        results as a dict. The returned dict is merged into the pull result
        under the key ``"extra_enumeration"``.

        Returns:
            Dict of additional enumeration results, or empty dict.
        """
        return {}

    def query(self, sql: str, args: tuple | None = None) -> list[dict[str, Any]]:
        """
        Execute a SQL statement and return all rows as a list of dicts.

        Args:
            sql: SQL statement to execute.
            args: Optional tuple of arguments for parameterized queries.

        Returns:
            List of row dicts, or empty list on error or failed connection.
        """
        try:
            with self.conn.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute(sql, args)
                return list(cursor.fetchall())
        except CommError:
            return []
        except Exception as exc:
            self.log.debug(f"MySQL query failed: {exc}")
            return []

    def get_databases(self) -> list[str]:
        """
        Return names of all databases visible to the current user.

        Returns:
            List of database name strings.
        """
        rows = self.query("SHOW DATABASES")
        return [r["Database"] for r in rows]

    def get_tables(self, database: str) -> list[str]:
        """
        Return table names for the given database.

        Args:
            database: Name of the database to list tables from.

        Returns:
            List of table name strings.
        """
        rows = self.query(f"SHOW TABLES FROM {quote_identifier(database)}")
        key = f"Tables_in_{database}"
        return [r[key] for r in rows if key in r]

    def get_table_row_count(self, database: str, table: str) -> int | None:
        """
        Return the approximate row count for a table from information_schema.

        Args:
            database: Database the table belongs to.
            table: Table name.

        Returns:
            Approximate row count as an integer, or ``None`` if unavailable.
        """
        rows = self.query(
            "SELECT TABLE_ROWS FROM information_schema.TABLES "
            "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s",
            (database, table),
        )
        if rows and rows[0].get("TABLE_ROWS") is not None:
            return int(rows[0]["TABLE_ROWS"])
        return None

    def get_users(self) -> list[dict[str, str]]:
        """
        Return all MySQL user accounts from mysql.user.

        Returns:
            List of dicts with ``"user"`` and ``"host"`` keys.
        """
        rows = self.query("SELECT User, Host FROM mysql.user ORDER BY User, Host")
        return [{"user": r["User"], "host": r["Host"]} for r in rows]

    def get_grants(self, user: str, host: str) -> list[str]:
        """
        Return SHOW GRANTS output lines for a specific user@host.

        Args:
            user: MySQL username.
            host: MySQL host the user connects from.

        Returns:
            List of GRANT statement strings, or empty list if none found.
        """
        rows = self.query("SHOW GRANTS FOR %s@%s", (user, host))
        if not rows:
            return []

        key = next(iter(rows[0]))
        return [r[key] for r in rows]

    def get_global_variables(self, like: str = "%") -> dict[str, str]:
        """
        Return global system variables whose names match a LIKE pattern.

        Args:
            like: SQL LIKE pattern to filter variable names (default ``"%"``).

        Returns:
            Dict mapping variable name to value.
        """
        rows = self.query("SHOW GLOBAL VARIABLES LIKE %s", (like,))
        return {r["Variable_name"]: r["Value"] for r in rows}

    def get_process_list(self) -> list[dict[str, Any]]:
        """
        Return active MySQL connections and queries from SHOW FULL PROCESSLIST.

        Returns:
            List of process dicts as returned by MySQL.
        """
        return self.query("SHOW FULL PROCESSLIST")
