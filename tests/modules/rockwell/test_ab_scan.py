from peat.modules.rockwell import ab_scan
from peat.protocols.enip.enip_packets import ENIP, EncapData, GetAttributesAllResponse


def _slot_reply(product_name: bytes) -> bytes:
    attributes = GetAttributesAllResponse(
        productName=product_name, productNameLength=len(product_name)
    )
    return bytes(
        ENIP(commandCode="SendRRData", data=bytes(EncapData(data=b"\x00" * 4 + bytes(attributes))))
    )


class _FakeSocket:
    def __init__(self, replies):
        self.replies = list(replies)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def settimeout(self, _timeout):
        pass

    def connect(self, _address):
        pass

    def send(self, data):
        return len(data)

    def recv(self, _size):
        return self.replies.pop(0)


def test_extract_info_response_non_utf8_name():
    info = ab_scan.extract_info_response(
        GetAttributesAllResponse(productName=b"\xff1756-L71", productNameLength=9)
    )
    assert info["product_name"] == "�1756-L71"


def test_enumerate_device_modules_bad_slot_reply(mocker):
    replies = [
        bytes(ENIP(commandCode="RegisterSession", sessionHandle=0x1234)),
        _slot_reply(b"1756-L71"),
        b"\x6f",  # Truncated reply for slot 1
        _slot_reply(b"1756-EN2T"),
    ]
    mocker.patch.object(ab_scan.socket, "socket", return_value=_FakeSocket(replies))

    slots = ab_scan.enumerate_device_modules("192.0.2.1", chassis_size=3)
    assert sorted(slots) == [0, 2]
    assert slots[0]["product_name"] == "1756-L71"
    assert slots[2]["product_name"] == "1756-EN2T"
