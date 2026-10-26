import pytest

from peat import DeviceData, config
from peat.modules.schneider.sage.sage_commands import SageCommands, save_memory_reads_to_disk


@pytest.fixture
def dev(mocker, tmp_path) -> DeviceData:
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path / "devices"})
    return DeviceData(ip="127.0.0.1")


def _files_under(path):
    return sorted(p for p in path.rglob("*") if p.is_file())


def test_save_memory_reads_to_disk_contained(dev, tmp_path):
    # Task NAME column from a hostile checkStack response
    tasks = {
        "0x1b2c3d": {
            "NAME": "../../../../../sage_escape",
            "TID": "0x1b2c3d",
            "d_response": "0x00000000:  6869  *hi*\nvalue = 0 = 0x0",
            "memory_hex": "6869",
            "memory_bytes": b"hi",
        }
    }
    save_memory_reads_to_disk(dev, tasks)

    mem_dir = dev.get_sub_dir("memory_reads")
    written = _files_under(tmp_path)
    assert len(written) == 4
    for path in written:
        assert path.is_relative_to(mem_dir), path
        assert path.parent.parent == mem_dir


class _StubSage(SageCommands):
    TYPE = "telnet"

    def __init__(self, dev: DeviceData, response: str) -> None:
        self.dev = dev
        self.resp_dir = None
        self._response = response

    def write(self, command: str) -> None:
        self.last_command = command

    def read_until(self, until: str) -> str:  # noqa: ARG002
        return self._response


@pytest.mark.parametrize("command", ["d ../../../../../../../sage_resp_escape", "ver /../../x"])
def test_query_response_file_contained(dev, tmp_path, command):
    sage = _StubSage(dev, "some response\n->")
    assert sage.query(command) == "some response"

    written = _files_under(tmp_path)
    assert len(written) == 1
    assert written[0].is_relative_to(dev.get_sub_dir("telnet_responses"))
