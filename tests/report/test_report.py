import base64
import hashlib
import json
import os
import re
import shutil
import sys
from html.parser import HTMLParser
from pathlib import Path
from unittest import mock

import pytest

import peat
from peat import cli_main, config, state, utils
from peat.api.report_api import report_api
from peat.report import REPORT_FILENAME, LiveRunInfo, generate_report
from peat.report import consts as report_consts
from peat.report import context as report_context
from peat.report.context import build_report_context
from peat.report.render import TEMPLATE_DIR, ReportError, render_report
from peat.run_results import RunResults

from .conftest import ARTIFACT_TEXT, FAILED_IP, ONLINE_IP, PULLED_IP, SECRET

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "' onmouseover='alert(1)",
    "javascript:alert(1)",
    "</style><script>alert(1)</script>",
    "{{7*7}}{% raw %}",
    "\u202eexe.txt",
    "nul\x00byte",
]


class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, dict]] = []
        self.data: dict[str, list[str]] = {"script": [], "style": []}
        self._current: str | None = None

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        if tag in self.data:
            self._current = tag
            self.data[tag].append("")

    def handle_endtag(self, tag):
        if tag == self._current:
            self._current = None

    def handle_data(self, data):
        if self._current:
            self.data[self._current][-1] += data


def _csp_hash(text: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode()).digest()).decode() + "'"


def check_html_structure(html_text: str) -> _Collector:
    """Structural security checks that must hold for every report."""
    parser = _Collector()
    parser.feed(html_text)
    parser.close()

    assert len(parser.data["script"]) == 1
    assert len(parser.data["style"]) == 1
    csp = next(a["content"] for t, a in parser.tags if t == "meta" and "http-equiv" in a)
    assert csp.startswith("default-src 'none';")
    assert _csp_hash(parser.data["style"][0]) in csp
    assert _csp_hash(parser.data["script"][0]) in csp

    ids = {a["id"] for _, a in parser.tags if a.get("id")}
    for tag, attrs in parser.tags:
        assert tag not in ("img", "iframe", "object", "embed", "form", "base", "link")
        for name, value in attrs.items():
            assert not name.startswith("on"), (tag, attrs)
            assert name != "style", (tag, attrs)
            if name in ("href", "src", "action"):
                assert not re.match(r"(?i)\s*(https?:|//|javascript:|data:|vbscript:)", value)
                if value.startswith("#") and len(value) > 1:
                    assert value[1:] in ids, f"dangling link {value}"
    return parser


@pytest.fixture
def full_run_dir(make_run_dir):
    return make_run_dir(parse=True)


def test_context(full_run_dir):
    ctx = build_report_context(RunResults.open(full_run_dir))

    assert ctx.command == "pull"
    assert ctx.mode == "regenerated"
    assert ctx.status.label == "Completed with errors"
    tiles = {t.label: t for t in ctx.tiles}
    assert tiles["Targets"].value == "4"
    assert tiles["Active hosts"].value == "3"
    assert tiles["Verified devices"].value == "2"
    assert tiles["Pulled devices"].value == "1 of 2"
    assert tiles["Pulled devices"].badge.label == "1 failed"
    assert tiles["Files parsed"].value == "2"
    assert tiles["Warnings"].value == "1"
    assert tiles["Errors"].value == "1"

    # Device statuses, merged from all sources
    rows = {r[1].text: r for r in ctx.hosts_table.rows}
    assert list(rows) == [ONLINE_IP, PULLED_IP, FAILED_IP, "192.0.2.200"]  # IP order
    labels = {ip: [b.label for b in r[-1].badges] for ip, r in rows.items()}
    assert labels[PULLED_IP] == ["pulled", "verified"]
    assert labels[FAILED_IP] == ["verified", "pull failed"]
    assert labels[ONLINE_IP] == ["online"]
    assert labels["192.0.2.200"] == ["parsed"]
    assert rows[ONLINE_IP][0].href is None  # no data, no section
    assert rows[PULLED_IP][0].href.startswith("#dev-")

    # Run overview
    items = {kv.label: kv.value.text for kv in ctx.run_items}
    assert items["PEAT version"] == "2.9.0"
    assert items["Run ID"] == "179343190989"
    assert items["Duration"] == "11.5 seconds"
    assert items["Configuration name"] == "site-a"
    assert "[REDACTED]@192.0.2.5" in items["Command line"]
    assert SECRET not in items["Command line"]

    # Device details
    dev = next(d for d in ctx.devices if d.title == "relay1")
    counts = {kv.label: kv.value.text for kv in dev.counts}
    assert counts["Event"] == "3"
    assert counts["Files"] == "1"
    assert counts["Top event datasets"] == "ser (2), login (1)"
    tables = {t.caption: t for t in dev.tables}
    artifacts = {r[0].text: r[2].text for r in tables["Files saved by PEAT for this device"].rows}
    artifact = full_run_dir / "devices" / PULLED_IP / "ftp" / "config.txt"
    assert artifact.read_text() == ARTIFACT_TEXT
    assert artifacts["ftp/config.txt"] == utils.calc_hash(artifact, "sha256")
    # Hashes are calculated from the files, never taken from the (untrusted) File models
    set_all = full_run_dir / "devices" / PULLED_IP / "ftp" / "set_all.txt"
    assert artifacts["ftp/set_all.txt"] == utils.calc_hash(set_all, "sha256")
    assert "AB" * 32 not in artifacts.values()
    assert [r[0].text for r in tables["Services"].rows] == ["21", "502"]
    assert "Users" not in tables  # empty tables are left out
    assert [b.title for b in dev.blocks] == ["Extra data reported for the device"]
    assert SECRET not in dev.blocks[0].text

    # Problems (malformed log line)
    assert any("malformed" in p for p in ctx.problems)
    assert ctx.toc[0] == ("problems", "Problems")

    # Logs
    log_rows = ctx.logs_table.rows
    assert [r[1].badges[0].label for r in log_rows] == ["warning", "error"]
    assert "[REDACTED]@" in log_rows[1][3].text
    assert log_rows[1][4].text == "CommError: timed out"

    # Configuration: credentials never appear
    config_text = repr(ctx.config_items) + repr(ctx.config_table) + repr(ctx.config_hosts_table)
    assert SECRET not in config_text
    settings = {r[0].text: r[1].text for r in ctx.config_table.rows}
    assert settings["default_timeout"] == "9"
    assert "debug" not in settings  # default value
    assert "env_prefix" not in settings
    assert ctx.config_hosts_table.rows[0][1].text == f"ip: {PULLED_IP}"

    # Files
    files = [r[0].text for r in ctx.files_table.rows]
    assert "logs/peat.log" in files
    assert [r[0].text for r in ctx.outside_files_table.rows] == ["/outside/peat_results/README.md"]
    assert {kv.label for kv in ctx.environment_items} >= {"Hostname", "Operating system"}
    assert ctx.interfaces_table.rows[0][1].text == "192.0.2.2"

    # Operations in run order, with the parse results
    assert [op.title for op in ctx.operations] == ["Scan", "Pull", "Parse"]
    parse_op = ctx.operations[2]
    assert [t.caption for t in parse_op.tables] == ["Parsed files", "Files that failed to parse"]


def test_context_generic_summary_and_duplicates(make_run_dir):
    run_dir = make_run_dir(scan=False)
    (run_dir / "summaries" / "pull-summary.json.1").write_text(json.dumps({"num_pull_results": 0}))
    (run_dir / "summaries" / "import-summary.json").write_text(
        json.dumps({"imported": 3, "sources": ["a", "b"], "url": f"http://u:{SECRET}@h/"})
    )
    ctx = build_report_context(RunResults.open(run_dir))
    assert [op.title for op in ctx.operations] == ["Pull", "Pull (2)", "Import summary"]
    generic = ctx.operations[2]
    items = {kv.label: kv.value.text for kv in generic.items}
    assert items["Imported"] == "3"
    assert items["Sources"] == "2 item(s)"
    assert SECRET not in repr(generic)
    assert generic.blocks[0].title == "Full summary"


def test_context_generic_summary_secret_keys(make_run_dir):
    """Top-level values with secret-like key names are redacted in the key-value list."""
    run_dir = make_run_dir(scan=False, pull=False)
    (run_dir / "summaries").mkdir()
    (run_dir / "summaries" / "pcap-summary.json").write_text(
        json.dumps({"api_key": "SUPERSECRET123", "password": "hunter2", "packets": 5})
    )
    ctx = build_report_context(RunResults.open(run_dir))
    op = next(o for o in ctx.operations if o.title == "Pcap summary")
    items = {kv.label: kv.value.text for kv in op.items}
    assert items["Api key"] == "[REDACTED]"
    assert items["Password"] == "[REDACTED]"
    assert items["Packets"] == "5"
    assert "SUPERSECRET123" not in repr(op)
    assert "hunter2" not in repr(op)


def test_context_pull_status_device_ids(make_run_dir):
    """
    Pulled devices are matched by the ID PEAT used for them (DeviceData.get_id()),
    which can be a label or name instead of an IP.
    """
    from peat.data.models import DeviceData

    labeled = DeviceData(ip="192.0.2.55", label="relay1")
    serial = DeviceData(serial_port="/dev/ttyUSB0", name="SEL-351", id="/dev/ttyUSB0")
    serial2 = DeviceData(serial_port="/dev/ttyUSB1", name="SEL-351", id="/dev/ttyUSB1")
    failed = DeviceData(ip="192.0.2.66", label="relay2")
    failed_serial = DeviceData(serial_port="/dev/ttyUSB2", name="SEL-700", id="/dev/ttyUSB2")
    assert report_context._DEVICE_ID_KEYS == tuple(DeviceData()._ID_KEY_ORDER)

    run_dir = make_run_dir(scan=False, pull=False)
    shutil.rmtree(run_dir / "devices")
    (run_dir / "summaries").mkdir()
    devices = [labeled, serial, serial2, failed, failed_serial]
    (run_dir / "summaries" / "scan-summary.json").write_text(
        json.dumps({"hosts_verified": [d.elastic() for d in devices]}, default=str)
    )
    (run_dir / "summaries" / "pull-summary.json").write_text(
        json.dumps(
            {
                "pull_devices": [d.get_id() for d in devices],
                "num_pull_results": 3,
                "pull_results": [d.elastic() for d in (labeled, serial, serial2)],
            },
            default=str,
        )
    )
    ctx = build_report_context(RunResults.open(run_dir))
    statuses = {
        (r[0].text, r[1].text): [b.label for b in r[-1].badges] for r in ctx.hosts_table.rows
    }
    # No phantom rows, and devices with the same name aren't merged
    assert statuses == {
        ("relay1", "192.0.2.55"): ["pulled", "verified"],
        ("SEL-351", "/dev/ttyUSB0"): ["pulled", "verified"],
        ("SEL-351", "/dev/ttyUSB1"): ["pulled", "verified"],
        ("relay2", "192.0.2.66"): ["verified", "pull failed"],
        ("SEL-700", "/dev/ttyUSB2"): ["verified", "pull failed"],
    }
    pull_op = next(o for o in ctx.operations if o.title == "Pull")
    pull_items = {kv.label: kv.value.text for kv in pull_op.items}
    assert pull_items["Failed pulls"] == "relay2, SEL-700"
    tiles = {t.label: t for t in ctx.tiles}
    assert tiles["Pulled devices"].value == "3 of 5"


def test_context_artifact_hashes(make_run_dir, mocker, monkeypatch):
    """
    The hash of a saved file is never another file's hash (e.g. one with the same
    name in another directory), and only files shown in the table are hashed.
    """
    run_dir = make_run_dir()
    dev_dir = run_dir / "devices" / PULLED_IP
    (dev_dir / "config.txt").write_text("top-level", encoding="utf-8")
    (dev_dir / "ftp" / "config.txt").write_text("ftp", encoding="utf-8")
    (dev_dir / "device-data-files.jsonl").write_text(
        json.dumps(
            {
                "path": "/config.txt",
                "local_path": (dev_dir / "ftp" / "config.txt").as_posix(),
                "hash": {"sha256": "EF" * 32},
            }
        ),
        encoding="utf-8",
    )
    ctx = build_report_context(RunResults.open(run_dir))
    dev = next(d for d in ctx.devices if d.title == "relay1")
    table = next(t for t in dev.tables if t.caption.startswith("Files saved"))
    hashes = {r[0].text: r[2].text for r in table.rows}
    assert hashes["config.txt"] == utils.calc_hash(dev_dir / "config.txt", "sha256")
    assert hashes["ftp/config.txt"] == utils.calc_hash(dev_dir / "ftp" / "config.txt", "sha256")

    monkeypatch.setattr(report_consts, "MAX_TABLE_ROWS", 2)
    spy = mocker.spy(utils, "calc_hash")
    ctx = build_report_context(RunResults.open(run_dir))
    dev = next(d for d in ctx.devices if d.title == "relay1")
    table = next(t for t in dev.tables if t.caption.startswith("Files saved"))
    assert (len(table.rows), table.total_rows) == (2, 3)
    assert spy.call_count == 2

    # Total size limit of the hashed files
    monkeypatch.setattr(report_consts, "MAX_TABLE_ROWS", 100)
    monkeypatch.setattr(report_consts, "ARTIFACT_HASH_TOTAL_MAX_BYTES", 5)
    ctx = build_report_context(RunResults.open(run_dir))
    dev = next(d for d in ctx.devices if d.title == "relay1")
    table = next(t for t in dev.tables if t.caption.startswith("Files saved"))
    hashes = {r[0].text: r[2].text for r in table.rows}
    assert hashes["ftp/config.txt"] == utils.calc_hash(dev_dir / "ftp" / "config.txt", "sha256")
    assert "limit of" in hashes["config.txt"]


def test_context_limits(make_run_dir, monkeypatch):
    run_dir = make_run_dir()
    dev_dir = run_dir / "devices" / PULLED_IP
    for i in range(10):
        (dev_dir / "ftp" / f"extra-{i}.bin").write_bytes(b"x" * 10)
    monkeypatch.setattr(report_consts, "MAX_TABLE_ROWS", 3)
    monkeypatch.setattr(report_consts, "ARTIFACT_HASH_MAX_BYTES", 5)
    monkeypatch.setattr(report_consts, "MAX_JSON_BLOCK", 10)
    ctx = build_report_context(RunResults.open(run_dir))

    dev = next(d for d in ctx.devices if d.title == "relay1")
    artifacts = next(t for t in dev.tables if t.caption.startswith("Files saved"))
    assert artifacts.truncated
    assert artifacts.total_rows == 12
    assert len(artifacts.rows) == 3
    assert artifacts.rows[0][2].text.startswith("not computed (larger than")
    assert dev.blocks[0].truncated
    assert len(dev.blocks[0].text) == 10

    html_text = render_report(ctx)
    assert "showing the first 3 of 12 rows" in html_text


def test_context_section_isolation(full_run_dir, monkeypatch):
    def boom(*_args):
        raise ValueError("kaboom")

    monkeypatch.setattr(report_context._ReportBuilder, "modules_table", boom)
    monkeypatch.setattr(report_context._ReportBuilder, "_device_section", boom)
    ctx = build_report_context(RunResults.open(full_run_dir))
    assert "Section 'modules' could not be generated: kaboom" in ctx.problems
    assert ctx.devices  # placeholders for the devices
    assert ctx.devices[0].badges[0].label == "Error building section"
    check_html_structure(render_report(ctx))


@pytest.mark.parametrize(
    "kwargs",
    [
        {"scan": False, "pull": False, "meta": False},  # logs only
        {"scan": False, "pull": False, "logs": False, "meta": False},  # devices only
        {},
    ],
)
def test_render_minimal_run_dirs(make_run_dir, kwargs):
    run_dir = make_run_dir(**kwargs)
    html_text = render_report(build_report_context(RunResults.open(run_dir)))
    check_html_structure(html_text)
    for section in ("overview", "operations", "hosts", "devices", "logs", "files", "config"):
        assert f'id="{section}"' in html_text


def test_render_empty_dir(tmp_path):
    ctx = build_report_context(RunResults.open(tmp_path))
    assert ctx.command == "unknown"
    assert ctx.status.label == "Succeeded"
    html_text = render_report(ctx)
    check_html_structure(html_text)
    assert "No command summaries were found" in html_text
    assert "No device data was collected" in html_text


def test_render_structure(full_run_dir):
    html_text = render_report(build_report_context(RunResults.open(full_run_dir)))
    parser = check_html_structure(html_text)
    hrefs = [a["href"] for t, a in parser.tags if t == "a"]
    assert f"./devices/{PULLED_IP}/ftp/config.txt" in hrefs
    # Device IPs are never links (clicking must never generate traffic to devices)
    assert not any(PULLED_IP in h and not h.startswith(("./", "#")) for h in hrefs)
    assert "raw-file-contents-must-not-appear" not in html_text
    assert SECRET not in html_text


@pytest.mark.parametrize("payload", XSS_PAYLOADS)
def test_render_xss(make_run_dir, payload):
    run_dir = make_run_dir(parse=True, payload=payload.replace("/", "_").replace("\x00", "0"))
    # Payloads in every device string, log messages, config and file names
    html_text = render_report(build_report_context(RunResults.open(run_dir)))
    check_html_structure(html_text)
    assert "<script>alert" not in html_text
    assert "<img" not in html_text
    assert "\u202e" not in html_text
    assert "\x00" not in html_text
    if "{{" in payload:  # Template syntax in data is never evaluated
        assert "relay1{{7*7}}{% raw %}" in html_text


def test_render_xss_in_raw_payload_values(make_run_dir):
    """Raw (unmodified) payloads in summaries and logs."""
    run_dir = make_run_dir()
    summary = run_dir / "summaries" / "pull-summary.json"
    data = json.loads(summary.read_text())
    data["pull_results"][0]["name"] = "</td></tr></table><script>alert(1)</script>"
    data["pull_results"][0]["label"] = '"><svg onload=alert(1)>'
    data["pull_failures"] = ["<b>x</b>"]
    summary.write_text(json.dumps(data))
    (run_dir / "devices" / PULLED_IP / "device-data-summary.json").unlink()
    html_text = render_report(build_report_context(RunResults.open(run_dir)))
    check_html_structure(html_text)
    assert "<script>alert" not in html_text
    assert "<svg" not in html_text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_text


def test_templates_lint():
    for template in TEMPLATE_DIR.glob("*.j2"):
        # Ignore Jinja comments (which document these rules)
        text = re.sub(r"\{#.*?#\}", "", template.read_text(encoding="utf-8"), flags=re.S)
        assert "|safe" not in text.replace(" ", "")
        assert "Markup" not in text
        assert "xmlattr" not in text
        assert "style=" not in text
        assert not re.search(r"\son[a-z]+=", text)
    for asset in ("report.css", "report.js"):
        text = (TEMPLATE_DIR / asset).read_text(encoding="utf-8")
        assert text.isascii()
        assert not re.search(r"(?i)</(style|script)", text)
        assert not re.search(r"(?i)(url\(|@import|https?://)", text)
    js = (TEMPLATE_DIR / "report.js").read_text(encoding="utf-8")
    assert "innerHTML" not in js
    assert "eval(" not in js


def test_packaging_includes_templates():
    root = Path(__file__).resolve().parents[2]
    spec = (root / "distribution" / "peat.spec").read_text(encoding="utf-8")
    assert "'peat', 'report', 'templates'" in spec
    assert "peat/report/templates" in spec
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    assert '"Jinja2' in pyproject
    for name in ("report.html.j2", "_macros.html.j2", "report.css", "report.js"):
        assert (TEMPLATE_DIR / name).is_file()


def test_generate_report(full_run_dir, tmp_path):
    report = generate_report(full_run_dir)
    assert report == full_run_dir.resolve() / REPORT_FILENAME
    assert report.as_posix() in state.written_files
    first = report.read_text(encoding="utf-8")
    assert "relay1" in first

    # Regenerating replaces the report (and doesn't list it as a file)
    report2 = generate_report(full_run_dir)
    assert report2 == report
    assert not list(full_run_dir.glob(f"{REPORT_FILENAME}.*"))
    assert f">{REPORT_FILENAME}<" not in report.read_text(encoding="utf-8")

    # Custom output path: links are relative to it
    out = tmp_path / "out" / "site-a.html"
    assert generate_report(full_run_dir, output_file=out) == out
    assert f'href="../{full_run_dir.name}/devices/' in out.read_text(encoding="utf-8")


def test_generate_report_failures(full_run_dir, tmp_path, mocker, caplog):
    assert generate_report(tmp_path / "missing") is None
    assert "Failed to generate HTML report" in caplog.text

    assert generate_report(full_run_dir, output_file=tmp_path) is None  # a directory

    # A failed write doesn't change state.error, and leaves no temporary files.
    # (Context managers, since mocker.stopall() would undo the fixtures' patches.)
    with mock.patch("os.replace", side_effect=OSError(28, "No space left on device")):
        assert generate_report(full_run_dir) is None
    assert "No space left on device" in caplog.text
    assert state.error is False
    assert not (full_run_dir / REPORT_FILENAME).exists()
    assert not list(full_run_dir.glob(".*.tmp"))

    # Unexpected errors (e.g. from bad content) are logged, never raised
    with mock.patch(
        "peat.report.build_report_context", side_effect=RecursionError("maximum recursion")
    ):
        assert generate_report(full_run_dir) is None
    assert "maximum recursion" in caplog.text

    mocker.patch.dict(sys.modules, {"jinja2": None})
    caplog.clear()
    assert generate_report(full_run_dir) is None
    assert "Jinja2 is required" in caplog.text


def test_generate_report_symlink_not_followed(full_run_dir, tmp_path):
    """
    A planted peat-report.html symlink (or a -w path that's a symlink) is
    replaced, and its target is never written to.
    """
    victim = tmp_path / "victim.txt"
    victim.write_text("IMPORTANT USER DATA", encoding="utf-8")
    link = full_run_dir / REPORT_FILENAME
    try:
        link.symlink_to(victim)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported")
    assert generate_report(full_run_dir) == full_run_dir.resolve() / REPORT_FILENAME
    assert victim.read_text(encoding="utf-8") == "IMPORTANT USER DATA"
    assert not link.is_symlink()
    assert link.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")

    out_link = tmp_path / "out.html"
    out_link.symlink_to(victim)
    assert generate_report(full_run_dir, output_file=out_link) == out_link
    assert victim.read_text(encoding="utf-8") == "IMPORTANT USER DATA"
    assert not out_link.is_symlink()


@pytest.mark.parametrize("name", ["site:a report?.html", "CON", ".."])
def test_generate_report_invalid_output_name(full_run_dir, tmp_path, caplog, name):
    """Names that aren't valid on all platforms are rejected (not silently renamed)."""
    out_dir = tmp_path / "wout"
    out_dir.mkdir()
    assert generate_report(full_run_dir, output_file=out_dir / name) is None
    assert "Invalid report file name" in caplog.text
    assert list(out_dir.iterdir()) == []


def test_render_bad_asset(mocker, tmp_path, full_run_dir):
    ctx = build_report_context(RunResults.open(full_run_dir))
    for name in ("report.html.j2", "_macros.html.j2", "report.js"):
        (tmp_path / name).write_text((TEMPLATE_DIR / name).read_text())
    (tmp_path / "report.css").write_text("body{}</style><script>alert(1)</script>")
    mocker.patch("peat.report.render.TEMPLATE_DIR", tmp_path)
    with pytest.raises(ReportError, match="closing style or script"):
        render_report(ctx)
    (tmp_path / "report.css").unlink()
    with pytest.raises(ReportError, match="Failed to read"):
        render_report(ctx)


@pytest.fixture
def live_config(mocker, tmp_path):
    """Point the configuration at a run directory in tmp_path."""
    run_dir = tmp_path / "live-run"
    dirs = {
        "RUN_DIR": run_dir,
        "OUT_DIR": tmp_path,
        "DEVICE_DIR": run_dir / "devices",
        "SUMMARIES_DIR": run_dir / "summaries",
        "LOG_DIR": run_dir / "logs",
        "META_DIR": run_dir / "peat_metadata",
        "ELASTIC_DIR": run_dir / "elastic_data",
        "HEAT_ARTIFACTS_DIR": run_dir / "heat_artifacts",
        "TEMP_DIR": run_dir / "temp",
        "DRY_RUN": True,
    }
    mocker.patch.dict(config["CONFIG"], dirs)
    mocker.patch.dict(state["CONFIG"], {"error": False})
    (run_dir / "summaries").mkdir(parents=True)
    (run_dir / "summaries" / "parse-summary.json").write_text(
        json.dumps({"num_files_parsed": 0, "parse_results": []})
    )
    return run_dir


def test_live_report(live_config, mocker):
    spy = mocker.spy(peat.log, "complete")
    mocker.patch("sys.argv", ["peat", "parse", "-e", f"http://u:{SECRET}@h:9200", "x"])
    live = LiveRunInfo.from_current_run("parse")
    assert spy.call_count == 1
    assert [p.name for p in live.pending_files] == ["peat_configuration.yaml", "peat_state.yaml"]

    report = generate_report(live_config, live=live)
    assert report == live_config.resolve() / REPORT_FILENAME
    html_text = report.read_text(encoding="utf-8")
    check_html_structure(html_text)
    assert "(written when PEAT exits)" in html_text
    assert "peat_metadata/peat_state.yaml" in html_text
    assert "Dry run" in html_text
    assert SECRET not in html_text
    assert f"by PEAT {peat.__version__} (live)" in html_text

    ctx = build_report_context(RunResults.from_config(), live)
    assert ctx.command == "parse"
    assert ctx.status.label in ("Succeeded", "Completed with warnings", "Completed with errors")


def test_write_run_report(live_config, mocker, caplog):
    assert cli_main.write_run_report({"func": "parse"})
    assert (live_config / REPORT_FILENAME).is_file()

    # Failures never raise, and don't fail the run
    real_open = os.open

    def _fail_open(path, *args, **kwargs):
        if REPORT_FILENAME in str(path):
            raise OSError(28, "No space left on device")
        return real_open(path, *args, **kwargs)

    with mock.patch("os.open", side_effect=_fail_open):
        assert not cli_main.write_run_report({"func": "parse"})
    assert "No space left on device" in caplog.text
    assert state.error is False

    mocker.patch("peat.report.generate_report", side_effect=RuntimeError("boom"))
    assert not cli_main.write_run_report({"func": "parse"})
    assert "Failed to generate HTML report: boom" in caplog.text
    assert state.error is False


def test_report_api(make_run_dir, tmp_path, mocker, capsys):
    out_dir = tmp_path / "peat_results"
    run_a = make_run_dir(name="pull_a", parent=out_dir)
    run_b = make_run_dir(name="scan_b", parent=out_dir)
    current = make_run_dir(name="report_current", parent=out_dir)
    old_report_run = out_dir / "report_default-config_2026-10-30_12-00-00_179343190900"
    (old_report_run / "logs").mkdir(parents=True)
    (old_report_run / "logs" / "peat.log").write_text("log")
    mocker.patch.dict(config["CONFIG"], {"RUN_DIR": current, "PRINT_RESULTS": True})

    assert not report_api([])
    assert not report_api([tmp_path / "missing"])
    assert not report_api([out_dir], output_file=tmp_path / "r.html")  # multiple dirs
    capsys.readouterr()

    assert report_api([out_dir])
    printed = json.loads(capsys.readouterr().out)
    assert printed["reports"] == [
        (run_a.resolve() / REPORT_FILENAME).as_posix(),
        (run_b.resolve() / REPORT_FILENAME).as_posix(),
    ]
    assert not (current / REPORT_FILENAME).exists()  # this run's own directory
    assert not (old_report_run / REPORT_FILENAME).exists()  # a previous "peat report" run
    assert report_api([old_report_run])  # unless it's explicitly requested

    assert report_api([run_a], output_file=tmp_path / "r.html")
    assert (tmp_path / "r.html").is_file()

    # A path that's missing or isn't a run directory fails the command,
    # but the reports for the other paths are still generated
    (run_a / REPORT_FILENAME).unlink()
    not_run_dir = tmp_path / "not-a-run-dir"
    not_run_dir.mkdir()
    assert not report_api([run_a, tmp_path / "missing", not_run_dir])
    assert (run_a / REPORT_FILENAME).is_file()

    mocker.patch("peat.api.report_api.generate_report", return_value=None)
    assert not report_api([run_a])


def test_oneshot_main_report(mocker):
    api = mocker.patch("peat.cli_main.report_api", return_value=True)
    assert cli_main.oneshot_main({"func": "report", "run_dirs": ["a"], "report_file": None})
    api.assert_called_once_with(["a"], output_file=None)
    api.return_value = False
    assert not cli_main.oneshot_main({"func": "report"})
    api.assert_called_with([], output_file=None)
