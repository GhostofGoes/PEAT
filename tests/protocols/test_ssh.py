from pathlib import Path

from peat.protocols.ssh import SSH


class _FakeSFTP:
    """Stands in for paramiko.SFTPClient, writing fixed data for every get()."""

    def __init__(self):
        self.fetched = []

    def get(self, remotepath, localpath):
        self.fetched.append(remotepath)
        Path(localpath).write_bytes(b"sftp data")


def test_sftp_download_files_contained(tmp_path):
    local_dir = tmp_path / "out" / "sftp_files"
    ssh = SSH("127.0.0.1")
    ssh.sftp_conn = _FakeSFTP()
    # Listing entries as built from a hostile listdir_attr() response
    files = [
        {"path": "/../../sftp_escape.txt"},
        {"path": "/flash/../../../../sftp_escape2.txt"},
        {"path": "/flash/config.xml"},
    ]

    assert ssh.sftp_download_files(local_dir, files) is True
    assert len(ssh.sftp_conn.fetched) == 3

    written = sorted(p for p in tmp_path.rglob("*") if p.is_file())
    assert len(written) == 3
    for path in written:
        assert path.is_relative_to(local_dir), path
    assert (local_dir / "flash" / "config.xml").is_file()
