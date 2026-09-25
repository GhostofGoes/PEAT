"""
Checks that login credentials don't end up in PEAT's logging output.

Credentials can come from the defaults of a module or protocol (e.g. the
``default_options`` of a :class:`~peat.device.DeviceModule`), from the YAML
config (``device_options`` and ``hosts``), or from the command line (e.g.
``--elastic-server https://user:pass@host``). None of these should show up in
the terminal output or in any of the log files (``peat.log``,
``json-log.jsonl``, ``debug-info.txt``, ``telnet.log``, etc.).

There are two kinds of checks here:

- Runtime: PEAT is run with a config where every credential is replaced with
  a unique "canary" value, then the terminal output and every file in the
  log directory are searched for those canaries.
- Static: the source code is checked for logging calls that include
  a password (or other secret) variable, or that dump a full set of device
  options (which include the credentials).

Usernames are allowed in log messages (e.g. "Logging in as user 'admin'"),
since they're useful for troubleshooting failed logins. They're still
included in the runtime check, since dumps of the configuration and options
shouldn't include them.
"""

import ast
import itertools
import re
from collections.abc import Iterator
from copy import deepcopy
from pathlib import Path

import pytest
import yaml

import peat
from peat import consts, module_api
from peat.data.default_options import DEFAULT_OPTIONS

PEAT_SRC_DIR = Path(peat.__file__).parent

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _all_default_options() -> dict:
    """
    Global default options merged with the ``default_options`` of every module.
    """

    def _merge(dst: dict, src: dict) -> None:
        for key, value in src.items():
            if isinstance(value, dict) and isinstance(dst.get(key), dict):
                _merge(dst[key], value)
            elif key not in dst:
                dst[key] = deepcopy(value)

    options = deepcopy(DEFAULT_OPTIONS)
    for module in module_api.classes:
        _merge(options, getattr(module, "default_options", None) or {})
    return options


def _credential_sections(options: dict) -> set[str]:
    """
    Names of option sections that contain credentials, e.g. "ftp" or "sel".
    """
    return {
        name
        for name, section in options.items()
        if isinstance(section, dict) and any(consts.is_credential_key(k) for k in section)
    }


class CanaryConfig:
    """
    Generates options with every credential replaced by a unique canary value.
    """

    PREFIX = "peatcanary"

    def __init__(self) -> None:
        self._counter = itertools.count()
        self.canaries: set[str] = set()

    def new(self, label: str) -> str:
        # Alphanumeric only, so the value isn't altered by URL encoding, quoting, etc.
        canary = f"{self.PREFIX}{re.sub(r'[^a-z0-9]', '', label.lower())}{next(self._counter)}"
        self.canaries.add(canary)
        return canary

    def _poison(self, value, label: str):
        if isinstance(value, str):
            return self.new(label)
        elif isinstance(value, (list, tuple)):
            # Empty lists (e.g. "creds": []) still get a canary
            return [self._poison(v, label) for v in value] or [self.new(label)]
        elif isinstance(value, dict):
            return {k: self._poison(v, str(k)) for k, v in value.items()}
        return value  # e.g. booleans or ints

    def options(self, options: dict) -> dict:
        """
        Options with only the credentials, set to canary values.
        """
        result = {}
        for key, value in options.items():
            if consts.is_credential_key(key):
                result[key] = self._poison(value, key)
            elif isinstance(value, dict) and (sub := self.options(value)):
                result[key] = sub
        return result

    def find(self, text: str) -> set[str]:
        """
        Canaries present in the text (case-insensitive, since some
        protocols upper-case the passwords).
        """
        lowered = text.lower()
        return {c for c in self.canaries if c in lowered}


@pytest.fixture
def canary_config(tmp_path: Path) -> tuple[CanaryConfig, Path]:
    canary = CanaryConfig()
    options = _all_default_options()

    conf = {
        "device_options": canary.options(options),
        "hosts": [
            {
                "label": "canary-host",
                "identifiers": {"ip": "127.0.0.1"},
                "options": canary.options(options),
            }
        ],
        # Elasticsearch connection fails (nothing listens on port 9),
        # don't let the logging sink failure stop the run.
        "elastic_save_logs": False,
    }

    config_path = tmp_path / "canary-config.yaml"
    config_path.write_text(yaml.safe_dump(conf), encoding="utf-8")
    return canary, config_path


def _run_peat(exec_peat, run_dir: Path, args: list[str]):
    return exec_peat(
        [
            *args,
            "--run-dir",
            run_dir.as_posix(),
            # Highest debugging level and verbose output, to include as many
            # messages (and the debug-info.txt config dump) as possible.
            "-VVVV",
            "--verbose",
            "--no-color",
        ]
    )


def _assert_no_canaries(result, run_dir: Path, canary: CanaryConfig) -> None:
    """
    Check the terminal output and every file in the log directory for canaries.
    """
    log_dir = run_dir / "logs"
    log_files = sorted(p for p in log_dir.rglob("*") if p.is_file())
    assert (log_dir / "peat.log") in log_files, result.stderr.decode(errors="replace")
    assert (log_dir / "json-log.jsonl") in log_files
    assert (log_dir / "debug-info.txt") in log_files

    outputs = {
        "stdout": result.stdout.decode(errors="replace"),
        "stderr": result.stderr.decode(errors="replace"),
    }
    outputs.update({p.name: p.read_text(encoding="utf-8", errors="replace") for p in log_files})

    leaks = {}
    for name, text in outputs.items():
        if found := canary.find(text):
            leaks[name] = sorted(found)

    assert not leaks, f"Credentials found in log output: {leaks}"


def _run_with_canaries(exec_peat, tmp_path: Path, canary_config, args: list[str]) -> None:
    canary, config_path = canary_config
    run_dir = tmp_path / "run"
    es_url = f"http://{canary.new('esuser')}:{canary.new('espass')}@127.0.0.1:9/"

    result = _run_peat(
        exec_peat,
        run_dir,
        [*args, "--config-file", config_path.as_posix(), "--elastic-server", es_url],
    )
    _assert_no_canaries(result, run_dir, canary)


# ---------------------------------------------------------------------------
# Runtime checks
# ---------------------------------------------------------------------------


def test_no_credentials_in_logs_dry_run(exec_peat, tmp_path, canary_config):
    """
    Loading the config and setting up the run (initialize_peat) doesn't log credentials.
    """
    _run_with_canaries(
        exec_peat, tmp_path, canary_config, ["scan", "--dry-run", "-i", "127.0.0.1"]
    )


def test_no_credentials_in_logs_encrypt_config(exec_peat, tmp_path, canary_config):
    """
    The password given on the command line to encrypt a config file isn't logged.
    """
    canary, config_path = canary_config
    run_dir = tmp_path / "run"
    password = canary.new("clipassword")

    result = _run_peat(
        exec_peat,
        run_dir,
        ["encrypt-config", "--file-path", config_path.as_posix(), "--password", password],
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    _assert_no_canaries(result, run_dir, canary)


@pytest.mark.slow
def test_no_credentials_in_logs_scan_localhost(exec_peat, tmp_path, canary_config):
    """
    A scan using every module doesn't log credentials.
    """
    _run_with_canaries(
        exec_peat,
        tmp_path,
        canary_config,
        ["scan", "--assume-online", "-i", "127.0.0.1", "--timeout", "1"],
    )


# ---------------------------------------------------------------------------
# Static checks of logging calls in the source code
# ---------------------------------------------------------------------------

LOG_METHODS = {
    "trace",
    "trace1",
    "trace2",
    "trace3",
    "trace4",
    "debug",
    "info",
    "success",
    "warning",
    "error",
    "critical",
    "exception",
    "log",
}

# Variable, attribute, or key names that hold secrets. Usernames are allowed.
SECRET_NAME_RE = re.compile(
    r"^(?:.*_)?(?:pass|passwd|password|passwords|passphrase|pwd|secret|secrets"
    r"|creds?|credentials?|community|communities|api_?key|unsafe_url)$",
    re.IGNORECASE,
)

# Objects that hold all of the options for a device, including credentials
OPTIONS_CONTAINER_NAMES = {
    "options",
    "default_options",
    "global_options",
    "_runtime_options",
    "_host_option_overrides",
    "DEVICE_OPTIONS",
    "HOSTS",
}

# Local variables with the arguments or configuration PEAT was started with
CONFIG_VARIABLE_NAMES = {"args", "conf"}

CREDENTIAL_SECTIONS = _credential_sections(_all_default_options())


def _is_logger(node: ast.expr) -> bool:
    """
    If the object a method is called on is a logger, e.g. "log", "self.log", or "_log".
    """
    while isinstance(node, ast.Call):  # e.g. log.bind(...).info(...)
        node = node.func
        if isinstance(node, ast.Attribute):
            node = node.value
    if isinstance(node, ast.Attribute):
        name = node.attr
    elif isinstance(node, ast.Name):
        name = node.id
    else:
        return False
    return bool(re.search(r"(?:^|_)log(?:ger)?$", name, re.IGNORECASE))


def _log_calls(tree: ast.AST) -> Iterator[ast.Call]:
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in LOG_METHODS
            and _is_logger(node.func.value)
        ):
            yield node


def _log_call_args(call: ast.Call) -> list[ast.expr]:
    return [*call.args, *[k.value for k in call.keywords]]


def _name_of(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _ancestors(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> Iterator[ast.AST]:
    while node in parents:
        node = parents[node]
        yield node


def _check_log_arg(arg: ast.expr) -> list[str]:
    """
    Problems with an argument to a logging call.
    """
    problems = []
    parents = {child: parent for parent in ast.walk(arg) for child in ast.iter_child_nodes(parent)}

    for node in ast.walk(arg):
        # The number of secrets is fine, e.g. "{len(passwords)}"
        ancestors = _ancestors(node, parents)
        if any(isinstance(a, ast.Call) and _name_of(a.func) == "len" for a in ancestors):
            continue

        # Secrets in variables or attributes, e.g. "{password}" or "{self.passwd}"
        name = _name_of(node)
        if name and SECRET_NAME_RE.match(name):
            problems.append(f"'{name}' may be a secret")

        # Secrets looked up by key, e.g. "{dev.options['ftp']['pass']}"
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, str)
            and SECRET_NAME_RE.match(node.slice.value)
        ):
            problems.append(f"key '{node.slice.value}' may be a secret")

        # Full dumps of device options, or of a section of the options that
        # contains credentials (e.g. "{dev.options['ftp']}"). Lookups of
        # specific non-credential values are fine, e.g. "{dev.options['ftp']['timeout']}".
        if name in OPTIONS_CONTAINER_NAMES or (
            isinstance(node, ast.Name) and name in CONFIG_VARIABLE_NAMES
        ):
            outer = node
            while isinstance(parents.get(outer), ast.Subscript) and parents[outer].value is outer:
                outer = parents[outer]
            key = outer.slice.value if isinstance(outer, ast.Subscript) else None
            key = key if isinstance(key, str) else None
            if key is None or key in CREDENTIAL_SECTIONS:
                problems.append(
                    f"'{ast.unparse(outer)}' may include credentials, "
                    f"log specific values or use consts.redact_credentials()"
                )

    return problems


def _source_files() -> list[Path]:
    return sorted(PEAT_SRC_DIR.rglob("*.py"))


def test_log_call_check_finds_leaks():
    """
    Sanity check that the static check catches the things it should.
    """
    bad = [
        "log.debug(f'Logging in with {username}:{password}')",
        "self.log.trace(f'creds: {creds}')",
        "cls.log.info('pass: ' + dev.options['http']['pass'])",
        "log.debug('{}', self.passwd)",
        "log.trace2(f'global_options {pformat(datastore.global_options)}')",
        "self.log.debug(f'ftp options: {dev.options[\"ftp\"]}')",
        "log.bind(target=ip).warning(f'community {community}')",
        "log.info(f'Connecting to {self.unsafe_url}')",
        "log.trace4(f'Raw CLI arguments {pformat(args)}')",
    ]
    good = [
        "log.debug(f'Logging in as {username}')",
        'self.log.debug(f\'timeout: {dev.options["ftp"]["timeout"]}\')',
        "log.info('Getting password management messages...')",
        "log.info(f'Connecting to {self.safe_url}')",
        "log.trace(f'Tried {len(snmp_communities)} community strings')",
        "log.info(f'redacted {pformat(consts.redact_credentials(global_options))}')",
        "log.warning(f'Failed: {err.args}')",
        "log.info(f\"Loaded config from {conf['config_file']}\")",
        "print(f'{password}')",  # not a logging call
    ]

    for src in bad:
        calls = list(_log_calls(ast.parse(src)))
        assert calls, src
        assert any(_check_log_arg(a) for c in calls for a in _log_call_args(c)), src

    for src in good:
        for call in _log_calls(ast.parse(src)):
            for arg in _log_call_args(call):
                if "redact_credentials" in ast.unparse(arg):
                    continue
                assert not _check_log_arg(arg), src


def test_log_calls_do_not_include_secrets():
    """
    Logging calls in PEAT's source code don't include passwords or other secrets.

    If this fails, don't log the value. If it's a false positive (e.g. a
    variable named "password_attempts" that's an int), rename the variable.
    Dumps of options can use :func:`peat.consts.redact_credentials`.
    """
    failures = []

    for path in _source_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        rel_path = path.relative_to(PEAT_SRC_DIR.parent).as_posix()

        for call in _log_calls(tree):
            for arg in _log_call_args(call):
                # Values that are redacted are fine
                if "redact_credentials" in ast.unparse(arg):
                    continue
                failures.extend(f"{rel_path}:{call.lineno}: {p}" for p in _check_log_arg(arg))

    assert not failures, "Logging calls that may leak credentials:\n" + "\n".join(failures)


# ---------------------------------------------------------------------------
# Redaction helpers
# ---------------------------------------------------------------------------


def test_redact_credentials():
    original = {
        "timeout": 5.0,
        "ftp": {"user": "admin", "pass": "hunter2", "creds": [["a", "b"]], "port": 21},
        "sel": {"creds": {"acc": "OTTER", "2ac": "TAIL"}},
        "snmp": {"community": "private", "communities": ["public", "private"]},
        "USER-PASSWORD": "hunter2",
        "elastic_server": "https://elastic:hunter2@localhost:9200/",
        "hosts": [{"identifiers": {"ip": "192.0.2.1"}, "options": {"ssh": {"passphrase": "x"}}}],
    }
    before = deepcopy(original)
    redacted = consts.redact_credentials(original)

    assert original == before  # input isn't modified
    assert "hunter2" not in str(redacted)
    assert redacted["timeout"] == 5.0
    assert redacted["ftp"] == {
        "user": consts.REDACTED,
        "pass": consts.REDACTED,
        "creds": consts.REDACTED,
        "port": 21,
    }
    assert redacted["sel"]["creds"] == consts.REDACTED
    assert redacted["snmp"] == {"community": consts.REDACTED, "communities": consts.REDACTED}
    assert redacted["USER-PASSWORD"] == consts.REDACTED
    assert redacted["elastic_server"] == f"https://{consts.REDACTED}@localhost:9200/"
    assert redacted["hosts"][0]["identifiers"] == {"ip": "192.0.2.1"}
    assert redacted["hosts"][0]["options"]["ssh"]["passphrase"] == consts.REDACTED


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        (5, 5),
        ("http://localhost:9200/", "http://localhost:9200/"),
        ("admin@example.com", "admin@example.com"),
        ("http://user:pass@localhost:9200", f"http://{consts.REDACTED}@localhost:9200"),
        ("http://token@localhost", f"http://{consts.REDACTED}@localhost"),
        (("a", "https://u:p@h/"), ("a", f"https://{consts.REDACTED}@h/")),
    ],
)
def test_redact_credentials_values(value, expected):
    assert consts.redact_credentials(value) == expected


def test_redact_argv():
    argv = [
        "peat",
        "encrypt-config",
        "-p",
        "hunter2",
        "--password=hunter2",
        "-f",
        "config.yaml",
        "--password",
        "hunter2",
        "-e",
        "https://elastic:hunter2@localhost:9200",
    ]
    assert consts.redact_argv(argv) == [
        "peat",
        "encrypt-config",
        "-p",
        consts.REDACTED,
        f"--password={consts.REDACTED}",
        "-f",
        "config.yaml",
        "--password",
        consts.REDACTED,
        "-e",
        f"https://{consts.REDACTED}@localhost:9200",
    ]
