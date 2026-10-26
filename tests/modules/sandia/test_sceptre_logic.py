import pytest

from peat import SCEPTRE, datastore
from peat.modules.sandia.sceptre_fcd import parse_logic


def test_parse_logic_reads():
    # Longest names match first, and a name followed by a letter or digit doesn't match
    statements = parse_logic(
        "\n  foo = foobar + foo-bar * foo2\n\n  bar = !(foo >= 500.55)\n",
        {"foo": "analog", "foobar": "analog", "foo-bar": "analog", "bar": "analog"},
    )
    assert statements == [
        {
            "line": 1,
            "text": "foo = foobar + foo-bar * foo2",
            "target": "foo",
            "expression": "foobar + foo-bar * foo2",
            "reads": ["foo-bar", "foobar"],
            "ignored": False,
        },
        {
            "line": 2,
            "text": "bar = !(foo >= 500.55)",
            "target": "bar",
            "expression": "!(foo >= 500.55)",
            "reads": ["foo"],
            "ignored": False,
        },
    ]


def test_parse_logic_binary_before_analog():
    # bennu replaces the binary "breaker" before the longer analog "breaker-current"
    (statement,) = parse_logic(
        "trip = breaker-current > 5",
        {"trip": "binary", "breaker": "binary", "breaker-current": "analog"},
    )
    assert statement["reads"] == ["breaker"]
    assert not statement["ignored"]


def test_parse_logic_target_replaced():
    # bennu replaces "breaker" in the assigned tag too, then ignores the line
    (statement,) = parse_logic(
        "load-breaker = power > 5",
        {"load-breaker": "analog", "breaker": "binary", "power": "analog"},
    )
    assert statement["target"] == "load-breaker"
    assert statement["reads"] == ["power"]
    assert statement["ignored"]
    assert "load-True" in statement["errors"][0]


@pytest.mark.parametrize("tag_type", ["string", ""])
def test_parse_logic_not_binary_or_analog(tag_type):
    # bennu only has binary and analog tags, so it doesn't know these
    (statement,) = parse_logic("a = b + c", {"a": tag_type, "b": tag_type, "c": "analog"})
    assert statement["reads"] == ["c"]
    assert statement["ignored"]


@pytest.mark.parametrize(
    ("line", "delay", "error", "ignored"),
    [
        ("a = b,delay:10", 10, False, False),
        ("a = b,delay: 10", 10, False, False),
        ("a = b,delay:10abc", 10, False, False),
        ("a = b,delay:0", None, False, False),
        # bennu treats a negative delay as 0
        ("a = b,delay:-5", None, False, False),
        # bennu ignores these delays
        ("a = b, delay:10", None, True, False),
        ("a = b,delay:abc", None, True, False),
        ("a = b,wait:10", None, True, False),
        ("a = b,delay:1:2", None, True, False),
        ("a = b,delay:1,delay:2", None, True, False),
        # std::stoi throws, and bennu doesn't catch it
        ("a = b,delay:99999999999", None, True, True),
    ],
)
def test_parse_logic_delay(line, delay, error, ignored):
    (statement,) = parse_logic(line, {"a": "analog", "b": "analog"})
    assert statement["expression"] == "b"
    assert statement.get("delay_cycles") == delay
    assert ("errors" in statement) is error
    assert statement["ignored"] is ignored


@pytest.mark.parametrize("line", ["not an assignment", "= b"])
def test_parse_logic_not_assignment(line):
    assert parse_logic(line, {"b": "analog"}) == [
        {"line": 1, "text": line, "errors": ["not an assignment"], "ignored": True}
    ]


def test_parse_logic_many_tags():
    tags = {f"tag-{i}": "analog" for i in range(2000)}
    logic = "\n".join(f"tag-{i} = tag-{i + 1} + 1" for i in range(1999))
    statements = parse_logic(logic, tags)
    assert statements[-1]["reads"] == ["tag-1999"]


CONFIG = """<SCEPTRE>
    <field-device>
        <name>relay-1</name>
        {cycle_time}
        <tags>
            <external-tag><name>power</name><io>I0</io><type>analog</type></external-tag>
            <external-tag><name>breaker</name><io>O0</io><type>binary</type></external-tag>
            <internal-tag><name>tripped</name><status>false</status></internal-tag>
        </tags>
        <comms/>
        <logic><![CDATA[
            tripped = power > 500
            breaker = !tripped,delay:4
            unknown = power
        ]]></logic>
    </field-device>
</SCEPTRE>"""


@pytest.mark.parametrize(
    ("cycle_time", "delay_ms"),
    [
        ("<cycle-time>500</cycle-time>", 2000),
        # bennu uses 1000 ms if the cycle time is missing
        ("", 4000),
    ],
)
def test_parse_config_logic(mocker, cycle_time, delay_ms):
    mocker.patch.object(datastore, "objects", [])
    config = CONFIG.format(cycle_time=cycle_time)
    dev = SCEPTRE.parse_config(config)

    statements = dev.logic.extra["statements"]
    assert [s["target"] for s in statements] == ["tripped", "breaker", "unknown"]
    assert statements[1]["delay_cycles"] == 4
    assert statements[1]["delay_ms"] == delay_ms
    assert statements[2]["ignored"]

    # Parsing again doesn't duplicate the line numbers
    dev = SCEPTRE.parse_config(config, dev)

    tags = {tag.name: tag.extra for tag in dev.tag}
    # Line 3 is ignored, since "unknown" isn't a tag
    assert tags["power"] == {"read_by_logic": [1]}
    assert tags["breaker"] == {"written_by_logic": [2]}
    assert tags["tripped"] == {
        "initial_value": False,
        "written_by_logic": [1],
        "read_by_logic": [2],
    }
    assert "unknown" not in tags
