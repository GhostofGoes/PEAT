from peat import DeviceData
from peat.modules.ge.ge_relay import parse_ge_html, process_header_data


def test_parse_ge_html_table_name_last_row():
    # A table name in the last row, with no header row after it
    html = (
        "<table>"
        "<tr><td>Points</td></tr>"
        "<tr><td>Name</td><td>Value</td></tr>"
        "<tr><td>a</td><td>1</td></tr>"
        "<tr><td>b</td><td>2</td></tr>"
        "<tr><td>Trailing</td></tr>"
        "</table>"
    )
    # Previously, IndexError
    results = parse_ge_html(html)
    assert results["points"] == [{"name": "a", "value": "1"}, {"name": "b", "value": "2"}]
    assert results["trailing"] == []


def test_process_header_data_short_header():
    dev = DeviceData(ip="192.0.2.1")
    # Previously, IndexError
    process_header_data(dev, ["UR Relay Revision 7.40"])
    assert dev.firmware.version == "7.40"
    assert dev.ip == "192.0.2.1"
