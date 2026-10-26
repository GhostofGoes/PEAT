import socket
import ssl
import struct
import threading
from unittest.mock import MagicMock

import pymysql
import pytest
from pymysql.constants import CLIENT

from peat import datastore
from peat.protocols import http as http_module
from peat.protocols.mysql import MySQL


def _make_greeting(version: bytes) -> bytes:
    """Build a minimal MySQL Initial Handshake Packet for the given version string."""
    payload = b"\x0a" + version + b"\x00" + b"\x00" * 20
    length = len(payload).to_bytes(3, "little")
    return length + b"\x00" + payload


MYSQL_GREETING = _make_greeting(b"8.0.32")
MARIADB_GREETING = _make_greeting(b"10.6.12-MariaDB")
NOT_MYSQL = b"HTTP/1.1 200 OK\r\n\r\n"
TOO_SHORT = b"\x00\x00"


def _mock_socket(data: bytes):
    sock = MagicMock()
    sock.recv.return_value = data
    sock.__enter__ = lambda s: s
    sock.__exit__ = MagicMock(return_value=False)
    return sock


def _mock_pymysql(mocker, server_info="8.0.32"):
    mock_conn = MagicMock(_secure=True)
    mock_conn.get_server_info.return_value = server_info
    mocker.patch("pymysql.connect", return_value=mock_conn)
    return mock_conn


@pytest.fixture
def connected_mysql(mocker):
    def _make(rows=None):
        mock_cursor = MagicMock()
        mock_cursor.__enter__ = lambda s: s
        mock_cursor.__exit__ = MagicMock(return_value=False)
        mock_cursor.fetchall.return_value = rows or []

        mock_conn = MagicMock(_secure=True)
        mock_conn.get_server_info.return_value = "8.0.32"
        mock_conn.cursor.return_value = mock_cursor
        mocker.patch("pymysql.connect", return_value=mock_conn)
        mocker.patch("pymysql.cursors.DictCursor", MagicMock())

        m = MySQL("127.0.0.1")
        m.connect()
        return m, mock_cursor

    return _make


def test_read_greeting_mysql_version_returned(mocker):
    mocker.patch("socket.socket", return_value=_mock_socket(MYSQL_GREETING))
    assert MySQL.read_greeting("127.0.0.1") == "8.0.32"


def test_read_greeting_mariadb_version_returned(mocker):
    mocker.patch("socket.socket", return_value=_mock_socket(MARIADB_GREETING))
    assert MySQL.read_greeting("127.0.0.1") == "10.6.12-MariaDB"


def test_read_greeting_non_mysql_response_returns_none(mocker):
    mocker.patch("socket.socket", return_value=_mock_socket(NOT_MYSQL))
    assert MySQL.read_greeting("127.0.0.1") is None


def test_read_greeting_too_short_returns_none(mocker):
    mocker.patch("socket.socket", return_value=_mock_socket(TOO_SHORT))
    assert MySQL.read_greeting("127.0.0.1") is None


def test_read_greeting_connection_error_returns_none(mocker):
    sock = MagicMock()
    sock.connect.side_effect = TimeoutError("timed out")
    sock.__enter__ = lambda s: s
    sock.__exit__ = MagicMock(return_value=False)
    mocker.patch("socket.socket", return_value=sock)
    assert MySQL.read_greeting("127.0.0.1", timeout=0.01) is None


def test_read_greeting_custom_port_and_timeout_passed(mocker):
    mock_sock = _mock_socket(MYSQL_GREETING)
    mocker.patch("socket.socket", return_value=mock_sock)
    MySQL.read_greeting("10.0.0.1", port=3307, timeout=2.0)
    mock_sock.settimeout.assert_called_once_with(2.0)
    mock_sock.connect.assert_called_once_with(("10.0.0.1", 3307))


def test_init_defaults():
    m = MySQL("192.168.1.1")
    assert m.ip == "192.168.1.1"
    assert m.port == 3306
    assert m.username == "root"
    assert m.password == ""
    assert m.database == ""
    assert m.timeout == 10.0
    assert not m.connected
    assert m.server_info == ""
    assert m.server_version == ()


def test_init_custom_args():
    m = MySQL("10.0.0.1", port=3307, username="admin", password="secret", timeout=5.0)
    assert m.port == 3307
    assert m.username == "admin"
    assert m.password == "secret"
    assert m.timeout == 5.0


def test_connect_success(mocker):
    _mock_pymysql(mocker)
    m = MySQL("127.0.0.1")
    assert m.connect()
    assert m.connected
    assert m.server_info == "8.0.32"
    assert m.server_version == (8, 0, 32)


def test_connect_parses_mariadb_version(mocker):
    _mock_pymysql(mocker, server_info="10.6.12-MariaDB")
    m = MySQL("127.0.0.1")
    assert m.connect()
    assert m.server_version == (10, 6, 12)


def test_connect_failure_returns_false(mocker):
    mocker.patch("pymysql.connect", side_effect=Exception("refused"))
    m = MySQL("127.0.0.1")
    assert not m.connect()
    assert not m.connected


def test_on_connected_hook_called(mocker):
    _mock_pymysql(mocker)
    m = MySQL("127.0.0.1")
    m.on_connected = MagicMock()
    m.connect()
    m.on_connected.assert_called_once()


def test_disconnect_clears_connection(mocker):
    _mock_pymysql(mocker)
    m = MySQL("127.0.0.1")
    m.connect()
    assert m.connected
    m.disconnect()
    assert not m.connected


def test_disconnect_when_not_connected():
    m = MySQL("127.0.0.1")
    m.disconnect()
    assert not m.connected


def test_query_returns_rows(connected_mysql):
    rows = [{"id": 1}, {"id": 2}]
    m, _ = connected_mysql(rows)
    assert m.query("SELECT 1") == rows


def test_query_without_connection_returns_empty():
    m = MySQL("127.0.0.1")
    assert m.query("SELECT 1") == []


def test_get_databases(connected_mysql):
    rows = [{"Database": "app"}, {"Database": "logs"}]
    m, _ = connected_mysql(rows)
    assert m.get_databases() == ["app", "logs"]


def test_get_tables(connected_mysql):
    rows = [{"Tables_in_app": "users"}, {"Tables_in_app": "events"}]
    m, _ = connected_mysql(rows)
    assert m.get_tables("app") == ["users", "events"]


def test_get_table_row_count(connected_mysql):
    rows = [{"TABLE_ROWS": 42}]
    m, _ = connected_mysql(rows)
    assert m.get_table_row_count("app", "users") == 42


def test_get_table_row_count_none(connected_mysql):
    rows = [{"TABLE_ROWS": None}]
    m, _ = connected_mysql(rows)
    assert m.get_table_row_count("app", "users") is None


def test_get_users(connected_mysql):
    rows = [{"User": "root", "Host": "localhost"}, {"User": "app", "Host": "%"}]
    m, _ = connected_mysql(rows)
    assert m.get_users() == [
        {"user": "root", "host": "localhost"},
        {"user": "app", "host": "%"},
    ]


def test_get_grants(connected_mysql):
    rows = [{"Grants for root@localhost": "GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost'"}]
    m, _ = connected_mysql(rows)
    result = m.get_grants("root", "localhost")
    assert len(result) == 1
    assert "GRANT ALL" in result[0]


def test_get_grants_empty(connected_mysql):
    m, _ = connected_mysql(rows=[])
    assert m.get_grants("nobody", "localhost") == []


def test_get_global_variables(connected_mysql):
    rows = [{"Variable_name": "version", "Value": "8.0.32"}]
    m, _ = connected_mysql(rows)
    assert m.get_global_variables(like="version") == {"version": "8.0.32"}


def test_get_process_list(connected_mysql):
    rows = [{"Id": 1, "User": "root", "Command": "Query"}]
    m, _ = connected_mysql(rows)
    assert m.get_process_list() == rows


def test_on_connected_default_is_noop():
    m = MySQL("127.0.0.1")
    m.on_connected()


def test_enumerate_default_returns_empty_dict():
    m = MySQL("127.0.0.1")
    assert m.enumerate() == {}


def test_subclass_on_connected_called(mocker):
    called = []

    class CustomMySQL(MySQL):
        def on_connected(self):
            called.append(True)

    mock_conn = MagicMock(_secure=True)
    mock_conn.get_server_info.return_value = "8.0.32"
    mocker.patch("pymysql.connect", return_value=mock_conn)

    c = CustomMySQL("127.0.0.1")
    c.connect()
    assert called == [True]


def test_subclass_enumerate_returned(mocker):
    class CustomMySQL(MySQL):
        def enumerate(self):
            return {"custom_table": [{"row": 1}]}

    mock_cursor = MagicMock()
    mock_cursor.__enter__ = lambda s: s
    mock_cursor.__exit__ = MagicMock(return_value=False)
    mock_cursor.fetchall.return_value = []
    mock_conn = MagicMock(_secure=True)
    mock_conn.get_server_info.return_value = "8.0.32"
    mock_conn.cursor.return_value = mock_cursor
    mocker.patch("pymysql.connect", return_value=mock_conn)
    mocker.patch("pymysql.cursors.DictCursor", MagicMock())

    c = CustomMySQL("127.0.0.1")
    c.connect()
    assert c.enumerate() == {"custom_table": [{"row": 1}]}


@pytest.fixture
def tls_config(mocker):
    from peat import config

    mocker.patch.dict(config["CONFIG"], {"TLS_VERIFY": True, "TLS_CA_BUNDLE": None})
    return config


def test_connect_uses_verified_tls(mocker, tls_config):  # noqa: ARG001
    connect = mocker.patch(
        "pymysql.connect", return_value=MagicMock(get_server_info=lambda: "8", _secure=True)
    )
    assert MySQL("127.0.0.1").connect()

    context = connect.call_args.kwargs["ssl"]
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2


def test_connect_tls_ca_bundle(mocker, tls_config, https_server):
    tls_config["CONFIG"]["TLS_CA_BUNDLE"] = https_server.cert_path
    connect = mocker.patch(
        "pymysql.connect", return_value=MagicMock(get_server_info=lambda: "8", _secure=True)
    )
    assert MySQL("127.0.0.1").connect()

    context = connect.call_args.kwargs["ssl"]
    assert context.verify_mode == ssl.CERT_REQUIRED
    # The CA bundle's certificate is trusted
    assert any(c["subject"] == ((("commonName", "127.0.0.1"),),) for c in context.get_ca_certs())


def test_connect_tls_verify_disabled(mocker, tls_config):
    tls_config["CONFIG"]["TLS_VERIFY"] = False
    connect = mocker.patch(
        "pymysql.connect", return_value=MagicMock(get_server_info=lambda: "8", _secure=True)
    )
    assert MySQL("127.0.0.1").connect()
    assert connect.call_args.kwargs["ssl"].verify_mode == ssl.CERT_NONE
    assert connect.call_args.kwargs["ssl"].minimum_version == ssl.TLSVersion.TLSv1_2

    # Per-connection override
    assert MySQL("127.0.0.2", tls_verify=True).connect()
    assert connect.call_args.kwargs["ssl"].verify_mode == ssl.CERT_REQUIRED


def test_get_tables_quotes_identifier(connected_mysql):
    m, cursor = connected_mysql([])
    m.get_tables("app`; DROP DATABASE x; --")
    assert cursor.execute.call_args.args == ("SHOW TABLES FROM `app``; DROP DATABASE x; --`", None)


def test_get_grants_parametrized(connected_mysql):
    m, cursor = connected_mysql([])
    m.get_grants("root' OR '1", "local'host")
    assert cursor.execute.call_args.args == (
        "SHOW GRANTS FOR %s@%s",
        ("root' OR '1", "local'host"),
    )


def _full_greeting(capabilities: int) -> bytes:
    """MySQL protocol v10 handshake packet with the given capability flags."""
    payload = (
        b"\x0a8.0.32\x00"
        + struct.pack("<I", 1)  # thread id
        + b"A" * 8  # auth plugin data, part 1
        + b"\x00"
        + struct.pack("<H", capabilities & 0xFFFF)
        + b"\x21"  # charset
        + struct.pack("<H", 2)  # status
        + struct.pack("<H", capabilities >> 16)
        + b"\x15"  # length of auth plugin data
        + b"\x00" * 10
        + b"B" * 12
        + b"\x00"
        + b"mysql_native_password\x00"
    )
    return len(payload).to_bytes(3, "little") + b"\x00" + payload


@pytest.fixture
def stripped_tls_server():
    """MySQL server whose greeting doesn't offer TLS, recording what the client sends."""
    server = socket.create_server(("127.0.0.1", 0))
    received: list[bytes] = []

    def serve() -> None:
        conn, _ = server.accept()
        with conn:
            capabilities = CLIENT.CAPABILITIES & ~CLIENT.SSL
            conn.sendall(_full_greeting(capabilities))
            conn.settimeout(2)
            try:
                while data := conn.recv(4096):
                    received.append(data)
            except OSError:
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield server.getsockname()[1], received
    server.close()
    thread.join(timeout=5)


def test_connect_refuses_server_without_tls(tls_config, stripped_tls_server, log_messages):  # noqa: ARG001
    port, received = stripped_tls_server
    m = MySQL("127.0.0.1", port=port, username="root", password="Pw-UNIQUE", timeout=3)

    assert not m.connect()
    assert not m.connected
    assert any("doesn't support TLS" in msg for msg in log_messages)
    assert received == []  # No authentication (or anything else) was sent


def test_connect_refuses_unencrypted_connection(mocker, tls_config):  # noqa: ARG001
    conn = MagicMock(get_server_info=lambda: "8", _secure=False)
    mocker.patch("pymysql.connect", return_value=conn)

    assert not MySQL("127.0.0.1").connect()
    conn.close.assert_called()


def test_connect_tls_verify_disabled_per_device(mocker, tls_config):  # noqa: ARG001
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.object(http_module, "_tls_warned_hosts", set())
    datastore.get("127.0.0.2")._runtime_options["https"] = {"verify": False}
    connect = mocker.patch(
        "pymysql.connect", return_value=MagicMock(get_server_info=lambda: "8", _secure=True)
    )

    assert MySQL("127.0.0.2").connect()
    assert connect.call_args.kwargs["ssl"].verify_mode == ssl.CERT_NONE
    assert MySQL("127.0.0.3").connect()  # other hosts are unaffected
    assert connect.call_args.kwargs["ssl"].verify_mode == ssl.CERT_REQUIRED


def test_connect_tls_failure_logs_hint(mocker, tls_config, log_messages):  # noqa: ARG001
    mocker.patch.object(http_module, "_tls_hint_hosts", set())
    error = pymysql.err.OperationalError(2003, "Can't connect (certificate verify failed)")
    error.original_exception = ssl.SSLCertVerificationError("certificate verify failed")
    conn = MagicMock(_secure=False)
    conn.connect.side_effect = error
    mocker.patch("pymysql.connect", return_value=conn)

    assert not MySQL("127.0.0.1").connect()
    assert not MySQL("127.0.0.1").connect()
    hints = [m for m in log_messages if http_module.TLS_VERIFY_HINT in m]
    assert len(hints) == 1  # once per host
    assert "MySQL" in hints[0]
