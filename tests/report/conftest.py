"""
Fixtures for the HTML report and run directory loader tests.

``make_run_dir`` creates a synthetic PEAT run directory, modeled on the
files PEAT writes (and examples/example-*-summary.json).
"""

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from peat import state

RUN_NAME = "pull_default-config_2026-10-31_13-08-59_179343190989"
PULLED_IP = "192.0.2.55"
FAILED_IP = "192.0.2.77"
ONLINE_IP = "192.0.2.10"
SECRET = "hunter2-very-secret"

ARTIFACT_TEXT = "hostname=relay1\npassword=not-in-report\n"


def _log(level: str, message: str, ts: str, **extra) -> str:
    record = {
        "@timestamp": ts,
        "message": message,
        "event": {"original": message, "severity": 30},
        "log": {"level": level, "logger": "peat.test"},
    }
    record.update(extra)
    return json.dumps(record, separators=(",", ":"))


def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=4), encoding="utf-8")


@pytest.fixture(autouse=True)
def _isolate_state(mocker) -> None:
    """Generating a report adds to state.written_files: keep the global state unchanged."""
    mocker.patch.dict(state["CONFIG"], {"written_files": set(), "error": False})


@pytest.fixture
def make_run_dir(tmp_path: Path) -> Callable[..., Path]:
    """
    Create a synthetic run directory.

    ``payload`` is put into every device string field, a file name, a log
    message, the run directory name and the configuration name.
    """

    def _make(
        *,
        scan: bool = True,
        pull: bool = True,
        parse: bool = False,
        logs: bool = True,
        meta: bool = True,
        payload: str | None = None,
        name: str = RUN_NAME,
        parent: Path | None = None,
    ) -> Path:
        run_name = f"{name}{payload}" if payload else name
        run_dir = (parent or tmp_path) / run_name
        run_dir.mkdir(parents=True)
        text = payload or ""

        device = {
            "id": PULLED_IP,
            "ip": PULLED_IP,
            "mac": "00:60:78:00:00:00",
            "name": f"relay1{text}",
            "type": f"Protective Relay{text}",
            "serial_number": f"SN-1234{text}",
            "description": {"vendor": {"id": "SEL", "name": f"Schweitzer{text}"}, "model": "351"},
            "firmware": {"version": f"R123{text}"},
            "interface": [
                {
                    "type": "ethernet",
                    "ip": PULLED_IP,
                    "mac": "00:60:78:00:00:00",
                    "subnet_mask": "255.255.255.0",
                    "services": [{"port": 21, "protocol": "ftp", "transport": "tcp"}],
                }
            ],
            "service": [
                {"port": 21, "protocol": f"ftp{text}", "transport": "tcp", "enabled": True},
                {"port": 502, "protocol": "modbus_tcp", "transport": "tcp"},
            ],
            "extra": {"note": f"extra{text}", "password": SECRET},
        }

        if scan:
            _write_json(
                run_dir / "summaries" / "scan-summary.json",
                {
                    "peat_version": "2.9.0",
                    "peat_run_id": "179343190989",
                    "scan_duration": 1.5,
                    "scan_modules": ["SELRelay"],
                    "scan_type": "unicast_ip",
                    "scan_targets": [PULLED_IP, FAILED_IP, ONLINE_IP, "192.0.2.99"],
                    "scan_original_targets": ["192.0.2.0/24"],
                    "num_hosts_active": 3,
                    "num_hosts_online": 1,
                    "num_hosts_verified": 2,
                    "hosts_online": [ONLINE_IP],
                    "hosts_verified": [
                        {
                            **{k: v for k, v in device.items() if k != "extra"},
                            "peat_module": "SELRelay",
                        },
                        {
                            "id": FAILED_IP,
                            "ip": FAILED_IP,
                            "type": "PLC",
                            "peat_module": "SELRelay",
                        },
                    ],
                },
            )
        if pull:
            _write_json(
                run_dir / "summaries" / "pull-summary.json",
                {
                    "peat_version": "2.9.0",
                    "peat_run_id": "179343190989",
                    "pull_duration": 12.25,
                    "pull_modules": ["SELRelay"],
                    "pull_targets": [PULLED_IP, FAILED_IP],
                    "pull_original_targets": ["192.0.2.0/24"],
                    "pull_devices": [PULLED_IP, FAILED_IP],
                    "pull_comm_type": "unicast_ip",
                    "num_pull_results": 1,
                    "pull_results": [device],
                },
            )
        if parse:
            _write_json(
                run_dir / "summaries" / "parse-summary.json",
                {
                    "peat_version": "2.9.0",
                    "parse_duration": 0.5,
                    "parse_modules": ["SELRelay"],
                    "input_paths": ["./set_all.txt"],
                    "files_parsed": ["/data/set_all.txt", "/data/bad.txt"],
                    "num_files_parsed": 2,
                    "num_parse_successes": 1,
                    "num_parse_failures": 1,
                    "parse_failures": [
                        {"name": "bad.txt", "path": "/data/bad.txt", "module": "SELRelay"}
                    ],
                    "parse_results": [
                        {
                            "name": "set_all.txt",
                            "path": "/data/set_all.txt",
                            "module": "SELRelay",
                            "results": {"id": "192.0.2.200", "ip": "192.0.2.200", "type": "Relay"},
                        }
                    ],
                },
            )

        dev_dir = run_dir / "devices" / PULLED_IP
        _write_json(dev_dir / "device-data-summary.json", device)
        _write_json(dev_dir / "device-data-full.json", device)
        (dev_dir / "ftp").mkdir(parents=True)
        artifact = dev_dir / "ftp" / f"config{text.replace('/', '_')}.txt"
        artifact.write_text(ARTIFACT_TEXT, encoding="utf-8")
        (dev_dir / "device-data-event.jsonl").write_text(
            "\n".join(
                json.dumps({"dataset": ds, "created": ts, "message": f"event{text}"})
                for ds, ts in [
                    ("ser", "2026-10-01T00:00:00"),
                    ("ser", "2026-10-02T00:00:00"),
                    ("login", "2026-09-30T12:00:00"),
                ]
            ),
            encoding="utf-8",
        )
        (dev_dir / "device-data-files.jsonl").write_text(
            json.dumps(
                {
                    "path": f"/SETTINGS/set_all.txt{text}",
                    "size": 1234,
                    "local_path": "/somewhere/else/devices/192.0.2.55/ftp/set_all.txt",
                    "hash": {"sha256": "AB" * 32, "md5": "CD" * 16},
                    "original": "raw-file-contents-must-not-appear",
                    "device_id": PULLED_IP,
                }
            ),
            encoding="utf-8",
        )
        (dev_dir / "ftp" / "set_all.txt").write_text("set all", encoding="utf-8")

        if logs:
            lines = [
                _log(
                    "INFO",
                    "Starting PEAT",
                    "2026-10-31T13:08:59.000Z",
                    process={
                        "args": [
                            "/usr/bin/peat",
                            "pull",
                            "-i",
                            "192.0.2.0/24",
                            "-e",
                            f"https://elastic:{SECRET}@192.0.2.5:9200",
                        ],
                        "start": "2026-10-31T13:08:58.500Z",
                    },
                    observer={"hostname": "analyst-laptop", "os": {"full": "Linux 6.1"}},
                    peat={"python_version": "3.12.1"},
                ),
                _log("DEBUG", "Some debug message", "2026-10-31T13:09:00.000Z"),
                _log(
                    "WARNING", f"Slow response from {PULLED_IP}{text}", "2026-10-31T13:09:01.000Z"
                ),
                _log(
                    "ERROR",
                    f"Failed to pull {FAILED_IP} via https://admin:{SECRET}@{FAILED_IP}/",
                    "2026-10-31T13:09:02.000Z",
                    error={"type": "CommError", "message": f"timed out{text}"},
                ),
                '{"@timestamp":"2026-10-31T13:09:03.000Z","message":"trunc',
                _log("INFO", "Finished run", "2026-10-31T13:09:10.000Z"),
            ]
            (run_dir / "logs").mkdir()
            (run_dir / "logs" / "json-log.jsonl").write_text("\n".join(lines) + "\n")
            (run_dir / "logs" / "peat.log").write_text("text log\n")

        if meta:
            (run_dir / "peat_metadata").mkdir()
            (run_dir / "peat_metadata" / "peat_configuration.yaml").write_text(
                "metadata:\n"
                f"  name: {json.dumps('site-a' + text)}\n"
                "  description: ''\n"
                "  author: ''\n"
                "  created: ''\n"
                "  updated: ''\n"
                f"elastic_server: https://elastic:{SECRET}@192.0.2.5:9200\n"
                "default_timeout: 9.0\n"
                "dry_run: false\n"
                "debug: 0\n"
                f"device_dir: {(run_dir / 'devices').as_posix()}\n"
                "device_options:\n"
                "  sel:\n"
                f"    pass: {SECRET}\n"
                "  ftp:\n"
                "    user: admin\n"
                "hosts:\n"
                "- label: relay1\n"
                "  identifiers:\n"
                f"    ip: {PULLED_IP}\n"
                "  peat_module: SELRelay\n"
                "  options:\n"
                "    sel:\n"
                f"      pass: {SECRET}\n",
                encoding="utf-8",
            )
            (run_dir / "peat_metadata" / "peat_state.yaml").write_text(
                "error: false\n"
                "raw_socket_capable: true\n"
                "local_interface_details:\n"
                "  eth0:\n"
                "    af_inet:\n"
                "    - addr: 192.0.2.2\n"
                "      netmask: 255.255.255.0\n"
                "written_files:\n"
                f"- {(run_dir / 'devices' / PULLED_IP / 'device-data-full.json').as_posix()}\n"
                "- /outside/peat_results/README.md\n",
                encoding="utf-8",
            )
        return run_dir

    return _make
