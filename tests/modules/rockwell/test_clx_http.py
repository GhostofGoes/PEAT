from datetime import timedelta

from peat.modules.rockwell.clx_http import ClxHTTP


def test_clxhttp_clean_data():
    assert ClxHTTP._clean_data({}) == {}
    assert ClxHTTP._clean_data({" some key ": "   evil \t   value     "}) == {
        "some key": "evil value"
    }


def test_clxhttp_add_padding():
    assert ClxHTTP.add_padding("01") == "00000001"
    assert ClxHTTP.add_padding("1034") == "00001034"
    assert ClxHTTP.add_padding("b9d29221") == "b9d29221"


def test_clxhttp_parse_uptime():
    assert ClxHTTP._parse_uptime("") is None
    assert ClxHTTP._parse_uptime("bogus string") is None
    assert ClxHTTP._parse_uptime("28 days, 15h:43m:33.775s") == timedelta(
        days=28, hours=15, minutes=43, seconds=33, milliseconds=775
    )
    assert ClxHTTP._parse_uptime("28 days, 16h:53m:45s") == timedelta(
        days=28, hours=16, minutes=53, seconds=45
    )


def test_clxhttp_extract_no_table():
    # Previously, AttributeError ("find" returned None) and IndexError (no rows)
    assert ClxHTTP._extract_rows("<html><p>no table</p></html>", 0) == []
    assert ClxHTTP._extract_list("<html><p>no table</p></html>") == []
    assert ClxHTTP._extract_list("<table><tr><td>only</td></tr></table>") == []
    assert ClxHTTP._extract_tabular("<html></html>") == {}
    assert ClxHTTP._extract_list(
        "<table><tr><td>t</td></tr><tr><td>a</td><td>b</td></tr><tr><td>1</td><td>2</td></tr></table>"
    ) == [{"a": "1", "b": "2"}]
