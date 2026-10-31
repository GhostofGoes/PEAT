import pytest

from peat import exit_handler


def test_run_and_unregister(mocker):
    mocker.patch.dict(exit_handler.REGISTRY, {"CONNECTION": [], "FILE": []})
    calls = []

    def _close(name):
        calls.append(name)

    def _fail():
        raise OSError("connection reset")

    def _save():
        calls.append("save")

    exit_handler.register(_close, "CONNECTION", args=("plc",))
    exit_handler.register(_fail, "CONNECTION")
    exit_handler.register(_save, "FILE")

    exit_handler.run_and_unregister("CONNECTION")  # Errors are ignored
    assert calls == ["plc"]
    assert exit_handler.REGISTRY["CONNECTION"] == []
    assert exit_handler.REGISTRY["FILE"] == [(_save, ())]

    # Not run again at exit
    exit_handler.run_handlers()
    assert calls == ["plc", "save"]


def test_run_and_unregister_invalid_type():
    with pytest.raises(ValueError, match="invalid handler type"):
        exit_handler.run_and_unregister("SOCKETS")  # type: ignore[arg-type]
