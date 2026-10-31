import pytest

from peat.parsing.ieee_c37_2 import (
    ACRONYMS,
    DEVICE_NUMBERS,
    SUFFIXES,
    describe_device_function,
    parse_device_code,
)


def test_device_numbers_complete():
    assert sorted(DEVICE_NUMBERS) == list(range(1, 100))
    assert all(
        isinstance(name, str) and name.strip() == name and name for name in DEVICE_NUMBERS.values()
    )
    assert {DEVICE_NUMBERS[n] for n in range(95, 100)} == {"Used only for specific applications"}


@pytest.mark.parametrize(
    ("number", "name"),
    [
        # Names that changed in the 2008 edition, or that older lists get wrong
        (13, "Synchronous-Speed Device"),
        (16, "Data Communications Device"),
        (51, "AC Inverse Time Overcurrent Relay"),
        (53, "Field Excitation Relay"),
        (64, "Ground Protective Relay"),
        (68, "Blocking or Out-of-Step Relay"),
        (78, "Phase-Angle Measuring Relay"),
        (80, "Flow Switch"),
        (82, "DC Load-Measuring Reclosing Relay"),
        (85, "Pilot Communications, Carrier, or Pilot-Wire Relay"),
        (86, "Lockout Relay"),
        (94, "Tripping or Trip-Free Relay"),
    ],
)
def test_device_numbers_2008_names(number, name):
    assert DEVICE_NUMBERS[number] == name


def test_acronyms_and_suffixes():
    assert len(ACRONYMS) == 17
    assert ACRONYMS["PMU"] == "Phasor measurement unit"
    assert SUFFIXES["BF"] == "breaker failure"
    assert all(key.isupper() and key.isalpha() for key in [*ACRONYMS, *SUFFIXES])


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("51", {"number": 51, "letters": "", "instance": None}),
        (51, {"number": 51, "letters": "", "instance": None}),
        ("51G", {"number": 51, "letters": "G", "instance": None}),
        (" 51g ", {"number": 51, "letters": "G", "instance": None}),
        ("87T2", {"number": 87, "letters": "T", "instance": 2}),
        ("87T-2", {"number": 87, "letters": "T", "instance": 2}),
        ("51-2", {"number": 51, "letters": "", "instance": 2}),
        ("16ESM", {"number": 16, "letters": "ESM", "instance": None}),
        ("05", {"number": 5, "letters": "", "instance": None}),
        ("99", {"number": 99, "letters": "", "instance": None}),
    ],
)
def test_parse_device_code(code, expected):
    assert parse_device_code(code) == expected


@pytest.mark.parametrize(
    "code", ["100", "511", "0", "00", "", "PMU", "50/51", "G51", "5.1", "51_2"]
)
def test_parse_device_code_invalid(code):
    assert parse_device_code(code) is None


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("21", "Distance Relay"),
        ("21P", "Distance Relay (phase or pump)"),
        ("50BF", "Instantaneous Overcurrent Relay (breaker failure)"),
        ("51G", "AC Inverse Time Overcurrent Relay (ground or generator)"),
        ("59N", "Overvoltage Relay (neutral or network)"),
        ("64G", "Ground Protective Relay (ground or generator)"),
        # Q isn't a standard suffix letter, it's what SEL uses for negative sequence
        ("67Q", "AC Directional Overcurrent Relay (suffix Q)"),
        ("81R", "Frequency Relay (reactor, rectifier or room)"),
        ("87T", "Differential Protective Relay (transformer or thyratron)"),
        ("16ESM", "Data Communications Device (Ethernet: switch, network managed)"),
        ("16SS", "Data Communications Device (serial: switch)"),
        ("16ER", "Data Communications Device (Ethernet: router)"),
        ("16SCT", "Data Communications Device (serial: security processing, telephone component)"),
        ("16E", "Data Communications Device (Ethernet)"),
        ("16X", "Data Communications Device (auxiliary)"),
        ("27S", "Undervoltage Relay (synchronizing, secondary, strainer, sump or suction)"),
        ("94", "Tripping or Trip-Free Relay"),
        ("97", "Used only for specific applications"),
        ("51G2", "AC Inverse Time Overcurrent Relay (ground or generator) #2"),
        ("51-1", "AC Inverse Time Overcurrent Relay #1"),
        ("50EF", "Instantaneous Overcurrent Relay (suffix EF)"),
        ("pmu", "Phasor measurement unit"),
        ("50/51", "Instantaneous Overcurrent Relay / AC Inverse Time Overcurrent Relay"),
        ("27TN/59N", "Undervoltage Relay (suffix TN) / Overvoltage Relay (neutral or network)"),
        ("100", None),
        ("0", None),
        ("XYZ", None),
        ("", None),
        ("50/100", None),
    ],
)
def test_describe_device_function(code, expected):
    assert describe_device_function(code) == expected


def test_describe_device_function_overrides():
    overrides = {"27S": "Synchronism channel undervoltage", "51g": "Ground time-overcurrent"}

    assert describe_device_function("27s", overrides) == "Synchronism channel undervoltage"
    # The longest leading part of the letters that has an override
    assert describe_device_function("51GT", overrides) == (
        "Ground time-overcurrent (transformer or thyratron)"
    )
    assert describe_device_function("51G3", overrides) == "Ground time-overcurrent #3"
    assert describe_device_function("51", overrides) == "AC Inverse Time Overcurrent Relay"


def test_describe_device_function_suffixes():
    suffixes = {"Q": "negative sequence", "G": "residual ground"}

    assert describe_device_function("67Q", suffixes=suffixes) == (
        "AC Directional Overcurrent Relay (negative sequence)"
    )
    assert describe_device_function("51G", suffixes=suffixes) == (
        "AC Inverse Time Overcurrent Relay (residual ground)"
    )
    # Not used for device 16
    assert describe_device_function("16ES", suffixes=suffixes) == (
        "Data Communications Device (Ethernet: switch)"
    )
