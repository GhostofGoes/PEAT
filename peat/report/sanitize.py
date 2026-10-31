"""
Sanitization and redaction helpers for the HTML report.

Everything shown in a report is treated as untrusted (most of it was reported
by devices). HTML escaping is done by the template engine (Jinja2 autoescape);
the helpers here handle what escaping doesn't: invisible or direction-changing
characters, size limits, credentials, and safe links.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote

from . import consts as report_consts

REDACTED = "[REDACTED]"

# C0/C1 control characters (except tab, newline and carriage return), the
# Arabic letter mark, zero-width characters, bidirectional embeddings,
# overrides and isolates, line/paragraph separators, word joiners and the BOM.
# Bidi characters can make displayed text differ from the actual bytes
# ("Trojan Source", CVE-2021-42574).
# Raw string, so the regex gets the escapes rather than the control characters.
_UNSAFE_CHARS_RE = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u061c\u200b-\u200f"
    r"\u2028\u2029\u202a-\u202e\u2060-\u2069\ufeff]"
)

# The userinfo is everything up to the *last* "@" before the host, since an
# unencoded "@" in a password is accepted by urllib and requests
_URL_CREDS_RE = re.compile(r"(?P<scheme>\b[A-Za-z][A-Za-z0-9+.\-]*://)[^\s/?#]+@")

# Sub-commands with a "-p/--password" argument
_PASSWORD_FLAG_COMMANDS = frozenset(
    {
        "encrypt-config",
        "encrypt",
        "decrypt-config",
        "decrypt",
        "encrypt-results",
        "decrypt-results",
    }
)

_SECRET_KEY_RE = re.compile(
    r"(?i)(pass(word|wd|phrase)?|pwd|secret|token|api[_-]?key|"
    r"private[_-]?key|credential|creds|auth)"
)

# Configuration keys with host and per-device options (which can include
# credentials). These are summarized instead of shown.
_SUMMARIZED_KEYS = frozenset({"DEVICE_OPTIONS", "HOSTS", "PILLAGE"})

_HOST_ID_KEYS = ("ip", "hostname", "mac", "serial_port")


def neutralize(text: str) -> str:
    """
    Replace control, zero-width and bidirectional formatting characters
    with visible ``\\uXXXX`` markers.

    >>> neutralize("abc\\u202eexe.txt")
    'abc\\\\u202eexe.txt'
    >>> neutralize(neutralize("a\\x00b")) == neutralize("a\\x00b")
    True
    """
    return _UNSAFE_CHARS_RE.sub(lambda m: f"\\u{ord(m.group()):04x}", text)


def clean_text(value: Any, max_len: int | None = None) -> str:
    """
    Convert a value to a string that's safe to display.

    :obj:`None` becomes an empty string, other values are converted with
    :class:`str`, unsafe characters are neutralized with :func:`neutralize`,
    and long values are truncated with a visible marker.

    >>> clean_text(None)
    ''
    >>> clean_text(12)
    '12'
    >>> clean_text("x" * 10, max_len=4)
    'xxxx... [6 more characters]'
    """
    if value is None:
        return ""
    if max_len is None:
        max_len = report_consts.MAX_TEXT_LEN
    text = neutralize(value if isinstance(value, str) else str(value))
    if max_len and len(text) > max_len:
        text = f"{text[:max_len]}... [{len(text) - max_len} more characters]"
    return text


def redact_url_credentials(text: str) -> str:
    """
    Redact credentials (``user:password@``) in URLs.

    >>> redact_url_credentials("https://elastic:changeme@192.0.2.5:9200/")
    'https://[REDACTED]@192.0.2.5:9200/'
    >>> redact_url_credentials("http://192.0.2.5:9200/")
    'http://192.0.2.5:9200/'
    >>> redact_url_credentials("http://elastic:p@ss@host:9200/")
    'http://[REDACTED]@host:9200/'
    """
    return _URL_CREDS_RE.sub(rf"\g<scheme>{REDACTED}@", text)


def redact_argv(argv: list[str]) -> list[str]:
    """
    Redact credentials in command line arguments.

    URL credentials are redacted everywhere. The values of ``-p``/``--password``
    are redacted only for the encryption/decryption commands, since ``-p`` has
    other meanings for other commands.

    >>> redact_argv(["peat", "encrypt-results", "-f", "x", "-p", "secret"])
    ['peat', 'encrypt-results', '-f', 'x', '-p', '[REDACTED]']
    >>> redact_argv(["peat", "decrypt", "--password=secret", "-psecret"])
    ['peat', 'decrypt', '--password=[REDACTED]', '-p[REDACTED]']
    >>> redact_argv(["peat", "pull", "-e", "http://u:p@host:9200"])
    ['peat', 'pull', '-e', 'http://[REDACTED]@host:9200']
    """
    out: list[str] = []
    has_password = len(argv) > 1 and argv[1] in _PASSWORD_FLAG_COMMANDS
    redact_next = False
    for arg in argv:
        arg = str(arg)
        if redact_next:
            out.append(REDACTED)
            redact_next = False
        elif has_password and arg in ("-p", "--password"):
            out.append(arg)
            redact_next = True
        elif has_password and arg.startswith("--password="):
            out.append(f"--password={REDACTED}")
        elif has_password and arg.startswith("-p") and not arg.startswith("--"):
            out.append(f"-p{REDACTED}")
        else:
            out.append(redact_url_credentials(arg))
    return out


def _summarize_options(key: str, value: Any) -> str:
    if isinstance(value, dict):
        names = ", ".join(sorted(str(k) for k in value)[:20])
        return f"{len(value)} option group(s){': ' + names if names else ''} (values not shown)"
    if isinstance(value, list):
        return f"{len(value)} {key.lower()} entr{'y' if len(value) == 1 else 'ies'} (not shown)"
    return "(not shown)"


def redact_mapping(obj: Any) -> Any:
    """
    Recursively copy a configuration-like structure with secrets redacted.

    - Values under keys that look like secrets (e.g. ``password``, ``token``)
      are replaced with ``[REDACTED]``.
    - ``DEVICE_OPTIONS``, ``HOSTS`` and ``PILLAGE`` (at any depth, case-insensitive)
      are replaced with a short summary, since they can contain credentials.
    - Credentials in URLs in strings are redacted.

    >>> redact_mapping({"elastic_server": "http://u:p@h:9200", "sel": {"pass": "x"}})
    {'elastic_server': 'http://[REDACTED]@h:9200', 'sel': {'pass': '[REDACTED]'}}
    >>> redact_mapping({"HOSTS": [{"ip": "192.0.2.1"}]})
    {'HOSTS': '1 hosts entry (not shown)'}
    """
    if isinstance(obj, dict):
        result = {}
        for key, value in obj.items():
            skey = str(key)
            if skey.upper() in _SUMMARIZED_KEYS:
                result[key] = _summarize_options(skey, value)
            elif _SECRET_KEY_RE.search(skey) and value not in (None, "", [], {}):
                result[key] = REDACTED
            else:
                result[key] = redact_mapping(value)
        return result
    if isinstance(obj, (list, tuple)):
        return [redact_mapping(v) for v in obj]
    if isinstance(obj, str):
        return redact_url_credentials(obj)
    return obj


def hosts_overview(hosts: Any) -> list[dict[str, str]]:
    """
    Summarize the ``hosts`` configuration (label, identifiers, PEAT module,
    comment), never including the host-specific options.

    >>> hosts_overview(
    ...     [
    ...         {
    ...             "label": "a",
    ...             "identifiers": {"ip": "192.0.2.1"},
    ...             "peat_module": "SELRelay",
    ...             "options": {"x": 1},
    ...         }
    ...     ]
    ... )
    [{'label': 'a', 'identifiers': 'ip: 192.0.2.1', 'peat_module': 'SELRelay', 'comment': ''}]
    """
    rows: list[dict[str, str]] = []
    if not isinstance(hosts, list):
        return rows
    for host in hosts:
        if not isinstance(host, dict):
            continue
        idents = host.get("identifiers")
        if not isinstance(idents, dict):
            idents = {k: host[k] for k in _HOST_ID_KEYS if host.get(k)}
        rows.append(
            {
                "label": str(host.get("label") or ""),
                "identifiers": ", ".join(
                    f"{k}: {v}" for k, v in idents.items() if k in _HOST_ID_KEYS and v
                ),
                "peat_module": str(host.get("peat_module") or ""),
                "comment": str(host.get("comment") or ""),
            }
        )
    return rows


def safe_href(target: Path, base_dir: Path) -> str:
    """
    Create a safe link to a local file, relative to the report's directory.

    Every path segment is percent-encoded, so the result can never be
    interpreted as a URL scheme (e.g. ``javascript:``), query or fragment.
    If a relative path isn't possible (e.g. a different drive on Windows),
    a ``file:`` URI is returned.

    >>> safe_href(Path("/r/run/devices/x/javascript:alert(1)"), Path("/r/run"))
    './devices/x/javascript%3Aalert%281%29'
    >>> safe_href(Path("/r/other/a b#c.txt"), Path("/r/run"))
    '../other/a%20b%23c.txt'
    """
    try:
        rel = os.path.relpath(Path(target), Path(base_dir))
    except ValueError:
        return Path(target).resolve().as_uri()
    parts = [quote(p, safe="") for p in PurePosixPath(Path(rel).as_posix()).parts]
    if not parts or parts == ["."]:
        return "./"
    if parts[0] == "..":
        return "/".join(parts)
    return "./" + "/".join(parts)


def anchor_id(prefix: str, key: str) -> str:
    """
    Create a unique ASCII identifier that's safe in HTML ``id`` attributes,
    CSS selectors, and URL fragments.

    >>> anchor_id("dev", "192.0.2.10")
    'dev-192-0-2-10-6d99cbd0'
    >>> anchor_id("dev", "<script>")
    'dev-script-5b63e5b2'
    """
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", key).strip("-")[:40] or "x"
    digest = hashlib.sha256(key.encode("utf-8", "surrogatepass")).hexdigest()[:8]
    return f"{prefix}-{slug}-{digest}"


def ip_sort_key(value: Any) -> str:
    """
    Sort key that orders IPv4 and IPv6 addresses (optionally with a ``:port``)
    numerically, followed by everything else (case-insensitive).

    >>> sorted(["COM4", "10.0.0.10", "10.0.0.2", "fe80::1"], key=ip_sort_key)
    ['10.0.0.2', '10.0.0.10', 'fe80::1', 'COM4']
    """
    text = str(value)
    candidate = text.rsplit(":", 1)[0] if text.count(":") == 1 else text
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return f"1:{text.lower()}"
    return f"0:{ip.version}:{int(ip):039d}"


__all__ = [
    "REDACTED",
    "anchor_id",
    "clean_text",
    "hosts_overview",
    "ip_sort_key",
    "neutralize",
    "redact_argv",
    "redact_mapping",
    "redact_url_credentials",
    "safe_href",
]
