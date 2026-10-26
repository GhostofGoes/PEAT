import json
import shutil
import sys
from pathlib import Path

import pytest

import peat.api.scan_api
from peat import __version__


@pytest.mark.slow
def test_cli_parse_non_existing_file(exec_peat, tmp_path, assert_meta_files):
    bad_filename = "INVALIDFILE.TXT.PS.INVALID"
    args = [
        "parse",
        "--print-results",
        "-d",
        "m340",
        "--run-dir",
        tmp_path.as_posix(),
        bad_filename,
    ]

    result = exec_peat(args)

    assert result.returncode == 1
    assert not result.stdout  # no output from failed parse

    output = result.stderr.decode()
    assert bad_filename in output
    assert "ERROR" in output
    assert "Path doesn't exist" in output
    assert_meta_files()


@pytest.mark.slow
def test_cli_push_non_existing_file(exec_peat, tmp_path, assert_meta_files):
    bad_filename = "INVALIDFILE.TXT.PS.INVALID"
    args = [
        "push",
        "--print-results",
        "--timeout",
        "0.01",
        "-d",
        "controllogix",
        "-i",
        "localhost",
        "--run-dir",
        tmp_path.as_posix(),
        bad_filename,
    ]

    result = exec_peat(args)

    assert result.returncode == 1
    assert not result.stdout  # no output from failed push

    output = result.stderr.decode()
    assert bad_filename in output
    assert "ERROR" in output
    assert "bad input source" in output
    assert_meta_files()


@pytest.mark.slow
def test_cli_pull_results_file_localhost(
    exec_peat, datapath, tmp_path, assert_meta_files, assert_no_criticals
):
    path = datapath("test-scan-results-localhost-clx.json")
    args = [
        "pull",
        "-q",
        "--print-results",
        "--timeout",
        "0.01",
        "-f",
        path.as_posix(),
        "--run-dir",
        tmp_path.as_posix(),
    ]

    result = exec_peat(args)

    assert result.returncode == 1
    assert not result.stderr  # There should be no log output (-q)
    assert not result.stdout  # There should be no results for localhost
    assert_meta_files()
    assert_no_criticals()


@pytest.mark.slow
@pytest.mark.parametrize(
    "device_name", ["m340", "controllogix", "siprotec", "selrelay", "micronet"]
)
def test_cli_pull_devices_localhost(
    exec_peat,
    tmp_path,
    device_name,
    assert_meta_files,
    assert_no_criticals,
):
    args = [
        "pull",
        "-q",
        "--print-results",
        "--timeout",
        "0.01",
        "-d",
        device_name,
        "-i",
        "localhost",
        "--run-dir",
        tmp_path.as_posix(),
    ]

    result = exec_peat(args)

    assert result.returncode == 1
    assert not result.stderr  # There should be no log output (-q)
    assert not result.stdout  # There should be no results for localhost
    assert_meta_files()
    assert_no_criticals()


@pytest.mark.slow
def test_cli_pull_fake_subnet(exec_peat, tmp_path, assert_meta_files, assert_no_criticals):
    """
    RFC 5737 - IPv4 Address Blocks Reserved for Documentation
    https://tools.ietf.org/html/rfc5737
    """
    args = [
        "pull",
        "-q",
        "--print-results",
        "--timeout",
        "0.01",
        "-d",
        "controllogix",
        "-i",
        "192.0.2.0/24",
        "--run-dir",
        tmp_path.as_posix(),
    ]

    result = exec_peat(args)

    assert result.returncode == 1
    assert not result.stderr  # There should be no log output (-q)
    assert not result.stdout  # There should be no results for fake subnet
    assert_meta_files()
    assert_no_criticals()


@pytest.mark.slow
def test_cli_scan_results_file_localhost(
    run_peat,
    datapath,
    tmp_path,
    assert_meta_files,
    assert_no_criticals,
):
    path = datapath("test-scan-results-localhost-clx.json")
    args = [
        "scan",
        "-q",
        "--print-results",
        "--timeout",
        "0.01",
        "-f",
        path.as_posix(),
        "--run-dir",
        tmp_path.as_posix(),
    ]

    output = json.loads(run_peat(args)[0])

    assert "hosts_verified" in output
    assert output["scan_type"] == "unicast_ip"
    assert "ControlLogix" in output["scan_modules"]
    assert output["peat_version"] == __version__
    assert_meta_files()
    assert_no_criticals()


@pytest.mark.slow
@pytest.mark.parametrize("device_name", ["m340", "controllogix", "siprotec", "selrelay", "sel"])
def test_cli_scan_devices_short_timeout(
    run_peat,
    tmp_path,
    device_name,
    assert_meta_files,
    assert_no_criticals,
):
    args = [
        "scan",
        "-q",
        "--print-results",
        "--timeout",
        "0.01",
        "-d",
        device_name,
        "-i",
        "localhost",
        "--run-dir",
        tmp_path.as_posix(),
    ]

    output = json.loads(run_peat(args)[0])

    assert "hosts_verified" in output
    assert output["scan_type"] == "unicast_ip"
    assert output["peat_version"] == __version__
    assert device_name in str(output["scan_modules"]).lower()
    assert_meta_files()
    assert_no_criticals()


@pytest.mark.slow
def test_cli_scan_all_devices_short_timeout(
    run_peat,
    tmp_path,
    assert_meta_files,
    assert_no_criticals,
):
    args = [
        "scan",
        "-q",
        "--print-results",
        "--timeout",
        "0.01",
        "-i",
        "localhost",
        "--run-dir",
        tmp_path.as_posix(),
    ]

    output = json.loads(run_peat(args)[0])

    assert not output["hosts_verified"]
    assert output["scan_type"] == "unicast_ip"
    assert output["peat_version"] == __version__
    assert_meta_files()
    assert_no_criticals()


@pytest.mark.slow
def test_cli_scan_all_devices_short_timeout_duplicate_host(run_peat, tmp_path, assert_meta_files):
    args = [
        "scan",
        "-q",
        "--print-results",
        "--timeout",
        "0.01",
        "-i",
        "localhost",
        "127.0.0.1",
        "--run-dir",
        tmp_path.as_posix(),
    ]

    output = json.loads(run_peat(args)[0])

    assert not output["hosts_verified"]
    assert output["scan_type"] == "unicast_ip"
    assert output["peat_version"] == __version__
    assert_meta_files()


@pytest.mark.slow
def test_cli_dry_run(run_peat, tmp_path, mocker, assert_meta_files, assert_no_errors):
    mocker.patch("peat.api.scan_api.scan", return_value=None)

    args = [
        "scan",
        "--dry-run",
        "--print-results",
        "--timeout",
        "0.01",
        "-i",
        "localhost",
        "127.0.0.1",
        "--run-dir",
        tmp_path.as_posix(),
    ]

    output = run_peat(args)[1]

    assert "finished" in output.lower()
    assert "dry run" in output.lower()
    assert "num_hosts_verified" not in output
    # Ensure scan() wasn't called during the dry run
    assert not peat.api.scan_api.scan.called
    assert_meta_files()
    assert_no_errors()


@pytest.mark.slow
def test_cli_scan_localhost_subnet(run_peat, tmp_path, assert_meta_files):
    args = [
        "scan",
        "-q",
        "--print-results",
        "--timeout",
        "0.01",
        "-d",
        "clx",
        "-i",
        "127.0.0.0/28",
        "--run-dir",
        tmp_path.as_posix(),
    ]

    output = json.loads(run_peat(args)[0])

    assert not output["hosts_verified"]
    assert output["scan_type"] == "unicast_ip"
    assert output["peat_version"] == __version__
    assert_meta_files()


@pytest.mark.slow
def test_cli_config_encryption(run_peat, tmp_path, examples_dir, read_text, datapath):
    testing_path = tmp_path / "config"
    testing_path.mkdir()
    path_to_config = f"{testing_path.as_posix()}/example_config.yaml"
    sys.stdin = "password"
    args = [
        "encrypt",
        "-f",
        path_to_config,
        "-p",
        "testpass",
        "--run-dir",
        tmp_path.as_posix(),
    ]
    config_original = f"{examples_dir.as_posix()}/encryption/example_config.yaml"
    shutil.copy(src=config_original, dst=path_to_config)
    run_peat(args)[0]

    assert read_text(datapath(f"{testing_path.as_posix()}/encrypted_example_config.yaml"))


@pytest.mark.slow
def test_cli_config_decryption(run_peat, tmp_path, examples_dir, read_text, datapath):
    testing_path = tmp_path / "config"
    testing_path.mkdir()
    # create a path to the encrypted file in tmp_path we'll attempt to decrypt
    path_to_config = f"{testing_path.as_posix()}/encrypted_config.yaml"
    # create a path to the original config in /examples/encryption
    config_original = f"{examples_dir.as_posix()}/encryption/encrypted_config.yaml"

    args = [
        "decrypt",
        "-f",
        path_to_config,
        "-p",
        "a",  # 'a' is just the password used to encrypt the original encrypted_config.yaml
        "-w",
        testing_path,
        "--run-dir",
        tmp_path.as_posix(),
    ]
    shutil.copy(src=config_original, dst=path_to_config)
    run_peat(args)[0]

    assert read_text(datapath(f"{testing_path.as_posix()}/decrypted_config.yaml"))


@pytest.mark.slow
def test_cli_results_encryption(run_peat, tmp_path, mock_peat_results):
    args = [
        "encrypt-results",
        "-f",
        mock_peat_results,
        "-p",
        "secret",
        "-w",
        tmp_path,
    ]
    run_peat(args)[0]

    assert tmp_path / "encrypted_mock_peat_results.zip"


@pytest.mark.slow
def test_cli_results_decryption(run_peat, tmp_path, mock_encrypted_peat_results):
    args = [
        "decrypt-results",
        "-f",
        mock_encrypted_peat_results,
        "-p",
        "testpass",
        "-w",
        tmp_path / "unencrypted",
    ]
    run_peat(args)[0]

    assert tmp_path / "unencrypted" / "mock_peat_results.zip"


SECRET_MARKER = "Marker-PW-c0ffee"


def _files_with_text(path: Path, text: str) -> list[str]:
    return [
        f.as_posix() for f in path.rglob("*") if f.is_file() and text.encode() in f.read_bytes()
    ]


@pytest.mark.slow
def test_cli_results_do_not_contain_secrets(exec_peat, tmp_path, assert_meta_files):
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        f"""
device_options:
  ssh:
    pass: "{SECRET_MARKER}"
  snmp:
    communities: ["{SECRET_MARKER}"]
  sel:
    creds: [["acc", "{SECRET_MARKER}"]]
heat_elastic_server: "http://heat:{SECRET_MARKER}@127.0.0.1:1/"
""",
        encoding="utf-8",
    )
    run_dir = tmp_path / "run"
    args = ["parse", "-d", "m340", "-c", config_file.as_posix(), "--run-dir", run_dir.as_posix()]

    result = exec_peat([*args, "nonexistent-file.apx"])
    assert result.returncode == 1  # the file doesn't exist
    assert_meta_files(run_dir)
    assert (run_dir / "peat_metadata" / "config.yaml").is_file()  # copy of config file
    assert not _files_with_text(run_dir, SECRET_MARKER)
    assert SECRET_MARKER not in result.stdout.decode() + result.stderr.decode()

    # The command line is recorded in the logs, even when PEAT fails to start
    es_dir = tmp_path / "run-es"
    es_url = f"http://elastic:{SECRET_MARKER}@127.0.0.1:1/"  # nothing is listening
    args = ["parse", "-d", "m340", "-e", es_url, "--run-dir", es_dir.as_posix()]

    result = exec_peat([*args, "nonexistent-file.apx"])
    assert result.returncode == 1
    assert (es_dir / "logs" / "json-log.jsonl").is_file()
    assert (es_dir / "logs" / "debug-info.txt").is_file()
    assert not _files_with_text(es_dir, SECRET_MARKER)
    assert SECRET_MARKER not in result.stdout.decode() + result.stderr.decode()


@pytest.mark.slow
def test_cli_config_encryption_no_results(run_peat, tmp_path, examples_dir):
    config_file = tmp_path / "example_config.yaml"
    shutil.copy(src=examples_dir / "encryption" / "example_config.yaml", dst=config_file)
    run_dir = tmp_path / "run"

    args = ["encrypt", "-f", config_file.as_posix(), "-p", SECRET_MARKER]
    stdout, stderr = run_peat([*args, "--run-dir", run_dir.as_posix()])

    encrypted = tmp_path / "encrypted_example_config.yaml"
    assert encrypted.is_file()
    # No results (e.g. logs with the command line) are saved
    assert not run_dir.exists()
    assert not _files_with_text(tmp_path, SECRET_MARKER)
    assert SECRET_MARKER not in stdout + stderr

    decrypted_dir = tmp_path / "decrypted"
    decrypted_dir.mkdir()
    args = ["decrypt", "-f", encrypted.as_posix(), "-p", SECRET_MARKER, "-w", decrypted_dir]
    run_peat([*args, "--run-dir", run_dir.as_posix()])

    assert (decrypted_dir / "decrypted_config.yaml").is_file()
    assert not run_dir.exists()
    assert not _files_with_text(tmp_path, SECRET_MARKER)
