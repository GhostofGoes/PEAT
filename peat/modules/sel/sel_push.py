"""
Push (upload) settings to SEL relays with ``peat push``.

The input can be a SEL QuickSet database (``*.rdb``), a ``SET_ALL.TXT``, an
individual settings file (e.g. ``SET_1.TXT``), or a directory of settings files.
It's converted into the individual settings files that are writable on the relay
(``SET_1.TXT``, ``SET_P1.TXT``, etc.), which are saved in the device results
and hashed before PEAT connects to the relay, so they're kept even if the push fails.

The files are uploaded via FTP, following the procedure in the "Virtual File
Interface" section of the SEL-351S and SEL-421 instruction manuals: read
``CFG.TXT``, write one ``SET_<class>.TXT`` file at a time, and read ``ERR.TXT``
after each file. ``ERR.TXT`` is empty if the relay accepted the settings,
otherwise it lists the errors. ``SET_ALL.TXT``, ``CFG.TXT``, and ``ERR.TXT``
are read-only and are never written.

:meth:`~peat.modules.sel.sel_relay.SELRelay._push` connects to the relay and
calls the functions in this module.
"""

import csv
import ftplib
import re
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path, PurePosixPath
from time import monotonic, sleep
from typing import Final, NamedTuple

import olefile

from peat import DeviceData, File, log
from peat.protocols import FTP

from .relay_parse import (
    NON_CLASS_SECTION_NAMES,
    SECTION_HEADER_RE,
    SETTINGS_FILENAME_RE,
    clean_settings_text,
    combine_settings_files,
    normalize_settings_file,
    parse_config_data,
    rdb_relay_settings_files,
    rdb_relay_to_set_all,
    read_rdb_streams,
    settings_class_files,
    sort_settings_filenames,
    split_set_all,
)
from .sel_files import (
    SOURCE_DERIVED,
    SOURCE_DOWNLOAD,
    SOURCE_PUSH,
    record_downloaded_file,
    write_and_record_file,
)

#: Directory in the device results with the settings files prepared for the push
PUSH_FILES_DIR: Final = "push_files"

#: Name of the file in the device results with the settings being pushed, in the ``SET_ALL`` format
PUSH_SET_ALL_FILENAME: Final = "push_SET_ALL.txt"

#: Files on relays that are read-only, or that PEAT must never write
NEVER_PUSH_FILES: Final = ("SET_ALL.TXT", "CFG.TXT", "CFG.XML", "ERR.TXT")

#: File where the relay lists the errors in the most recently written settings file
ERR_FILENAME: Final = "ERR.TXT"

#: Seconds to wait after uploading a file, before reading ``ERR.TXT``
UPLOAD_DELAY: Final = 2.0

#: The SEL-700 series instruction manuals (e.g. SEL-710, SEL-751A, and SEL-700G,
#: "Port 1" settings) say that after Port 1 or Logic settings are changed, it may
#: take up to two minutes before the relay accepts another settings change.
SEL700_SETTINGS_WAIT: Final = 120.0

#: Seconds between retries of an upload the relay refused (the ``STOR`` failed)
#: while waiting for a SEL-700 series relay
RETRY_INTERVAL: Final = 10.0

#: Most times a file the relay rejected (``ERR.TXT`` listed errors) is uploaded
#: again while waiting for a SEL-700 series relay. It's uploaded again once the
#: wait is over, so a real error in the settings isn't written over and over.
MAX_REJECTED_RETRIES: Final = 1

#: Most characters of ``ERR.TXT`` to include in the push status (the full file is saved)
MAX_MESSAGE_LENGTH: Final = 1000

# Status of the push, and of each file
STATUS_PREPARED: Final = "prepared"  # Saved in the device results, not uploaded
STATUS_UPLOADING: Final = "uploading"
STATUS_ACCEPTED: Final = "accepted"  # Uploaded, and ERR.TXT was empty
STATUS_UNVERIFIED: Final = "unverified"  # Uploaded, but ERR.TXT couldn't be read
STATUS_REJECTED: Final = "rejected"  # Uploaded, and ERR.TXT listed errors
STATUS_FAILED: Final = "failed"
STATUS_SUCCESS: Final = "success"  # Every file was uploaded (push status only)

#: Placeholder parts of the FID in QuickSet templates, e.g. ``RXXX``, ``VX``, and ``DXXXXXXXX``
_PLACEHOLDER_RE: Final = re.compile(r"(?:^|-)[RVD]X+(?=-|$)", re.IGNORECASE)

#: Settings version in a FID, e.g. ``Z008004``
_SETTINGS_VERSION_RE: Final = re.compile(r"(?:^|-)(Z\d+)(?=-|$)", re.IGNORECASE)

_LOGIC_FILE_RE: Final = re.compile(r"^SET_L\d+\.TXT$")


class PushInputError(Exception):
    """The push input can't be pushed, e.g. it has no settings or is for another relay."""


@dataclass
class PushFile:
    """
    A settings file to upload to the relay.
    """

    #: Name of the file on the relay (uppercase), e.g. ``SET_P1.TXT``
    name: str
    #: Contents of the file, from the push input
    data: bytes
    #: Where the file is from, e.g. the input file or the stream in a RDB
    origin: str
    #: Contents uploaded to the relay. This is ``data``, unless PEAT
    #: replaced a placeholder ``[INFO]`` section with the relay's.
    upload_data: bytes = b""
    status: str = STATUS_PREPARED
    message: str = ""
    attempts: int = 0
    #: The recorded files: the prepared file, and the uploaded file if it's different
    files: list[File] = field(default_factory=list)


@dataclass
class PushPlan:
    """
    The settings files to push to a relay, and the status of the push.
    """

    #: Path of the push input
    source: Path
    #: ``rdb``, ``set_all``, or ``settings_files``
    input_type: str
    files: list[PushFile]
    #: The settings being pushed, in the ``SET_ALL`` format
    set_all: str
    #: Name of the relay in the RDB file, if the input is a RDB file
    rdb_relay: str = ""
    status: str = STATUS_PREPARED
    message: str = ""

    @property
    def started(self) -> bool:
        """If the upload started, or the push failed or was refused after connecting."""
        return self.status != STATUS_PREPARED

    def summary(self) -> dict:
        return {
            "input": self.source.as_posix(),
            "input_type": self.input_type,
            "rdb_relay": self.rdb_relay,
            "status": self.status,
            "message": self.message,
            "files": [
                {
                    "name": pf.name,
                    "status": pf.status,
                    "message": pf.message,
                    "attempts": pf.attempts,
                    "origin": pf.origin,
                }
                for pf in self.files
            ],
        }

    def update(self, dev: DeviceData) -> None:
        """
        Save the status of the push in ``dev.extra["push"]``, and the
        status of each file in ``File.extra["push"]`` of its recorded files.
        """
        dev.extra["push"] = self.summary()

        for pf in self.files:
            for file_obj in pf.files:
                file_obj.extra["push"] = {
                    "status": pf.status,
                    "message": pf.message,
                    "attempts": pf.attempts,
                }

    def set_file_status(
        self, dev: DeviceData, pf: PushFile, status: str, message: str = ""
    ) -> None:
        pf.status = status
        pf.message = message[:MAX_MESSAGE_LENGTH]
        self.update(dev)

    def fail(self, dev: DeviceData, message: str) -> bool:
        log.error(f"Push to {dev.get_id()} failed: {message}")
        self.status = STATUS_FAILED
        self.message = message[:MAX_MESSAGE_LENGTH]
        self.update(dev)
        return False


# ---------------------------------------------------------------------------
# Helpers for settings file data (bytes)
# ---------------------------------------------------------------------------


def _decode(data: bytes) -> str:
    # Latin-1 maps every byte to a character, so encoding
    # the text as Latin-1 gives back the original bytes.
    return data.removeprefix(b"\xef\xbb\xbf").decode("latin-1")


def _lines(data: bytes) -> list[str]:
    return re.split(r"\r\n|\r|\n", _decode(data))


def _section_names(data: bytes) -> list[str]:
    """
    Names of the settings class sections in a settings file
    (not ``[INFO]``, ``[IOBOARDS]``, ``[COMCARDS]``, etc.).
    """
    names = []
    for line in _lines(data):
        header = SECTION_HEADER_RE.match(line)
        if header and header.group(1).strip().upper() not in NON_CLASS_SECTION_NAMES:
            names.append(header.group(1).strip())
    return names


def _section_lines(data: bytes, section: str) -> list[str] | None:
    """Lines in the first section with the (uppercase) name, or :obj:`None` if there isn't one."""
    found = None  # type: list[str] | None

    for line in _lines(data):
        header = SECTION_HEADER_RE.match(line)
        if header:
            if found is not None:
                break
            if header.group(1).strip().upper() == section:
                found = []
        elif found is not None and line.strip():
            found.append(line)

    return found


def _info_values(data: bytes) -> dict[str, str]:
    """Values in the ``[INFO]`` section, e.g. ``{"RELAYTYPE": "SEL-710", "FID": "..."}``."""
    values = {}
    for line in _section_lines(data, "INFO") or []:
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip().upper()] = value.strip()
    return values


def _setting_value(data: bytes, setting: str) -> str | None:
    """Value of a setting in a settings file, e.g. ``IPADDR``, or :obj:`None` if it's not set."""
    for line in _lines(data):
        if setting not in line.upper():
            continue
        for row in csv.reader([line]):
            if len(row) > 1 and row[0].strip().upper() == setting:
                return row[1].strip()
    return None


def _model(info: dict[str, str]) -> str:
    """
    Relay model from the ``[INFO]`` section, normalized the same as
    :func:`~peat.modules.sel.relay_parse.process_info_into_dev`
    (``SEL-710`` => ``710``, ``0351S`` => ``351S``, ``SEL-487E-3`` => ``487E``).

    ``RELAYTYPE`` is used if it has a model number. Otherwise (e.g. ``RELAYTYPE=SEL``,
    as in the SEL-421 manual's "Direct Networking Example"), the model is from the
    FID (``FID=SEL-421-...`` => ``421``). If neither has a model, it's an empty string.
    """
    relaytype = info.get("RELAYTYPE", "").strip().upper()
    model = relaytype.removeprefix("SEL-").split("-")[0].lstrip("0")
    if any(c.isdigit() for c in model):
        return model

    fid = re.match(r"^SEL-([A-Z0-9]+)", info.get("FID", "").strip().upper())
    return fid.group(1).lstrip("0") if fid else ""


def _settings_version(fid: str) -> str:
    match = _SETTINGS_VERSION_RE.search(fid.strip())
    return match.group(1).upper() if match else ""


def has_placeholder_info(data: bytes) -> bool:
    """
    If the ``[INFO]`` section of a settings file has the placeholder FID or BFID
    from a QuickSet template, e.g. ``FID=SEL-710-RXXX-VX-Z008004-DXXXXXXXX``.
    """
    info = _info_values(data)
    return any(_PLACEHOLDER_RE.search(info.get(key, "")) for key in ["FID", "BFID"])


def replace_info_section(data: bytes, info_lines: list[str]) -> bytes:
    """
    Replace the lines in the ``[INFO]`` section of a settings file,
    or add an ``[INFO]`` section at the beginning if there isn't one.

    Args:
        data: The settings file, cleaned with
            :func:`~peat.modules.sel.relay_parse.normalize_settings_file`
        info_lines: The new lines for the ``[INFO]`` section

    Returns:
        The settings file with the new ``[INFO]`` section
    """
    output = []  # type: list[str]
    in_info = False
    replaced = False

    for line in _lines(normalize_settings_file(data)):
        if not line:
            continue

        header = SECTION_HEADER_RE.match(line)
        if header:
            in_info = header.group(1).strip().upper() == "INFO" and not replaced
            output.append(line)
            if in_info:
                output.extend(info_lines)
                replaced = True
        elif not in_info:
            output.append(line)

    if not replaced:
        output = ["[INFO]", *info_lines, *output]

    return ("\r\n".join(output) + "\r\n").encode("latin-1")


def is_port_file(name: str) -> bool:
    """If a settings file is for a port (``SET_P1.TXT``, ``SET_PF.TXT``, etc.)."""
    return name.upper().startswith("SET_P")


def order_for_upload(files: list[PushFile]) -> list[PushFile]:
    """
    Order the files for uploading: the port settings (``SET_P*``) go last,
    since changing the settings of the port PEAT is connected through ends
    the connection. Ports with an IP address (Ethernet) go after the other ports.
    Otherwise, the order is kept.
    """

    def _group(pf: PushFile) -> int:
        if not is_port_file(pf.name):
            return 0
        if _setting_value(pf.data, "IPADDR") is None:
            return 1
        return 2

    return sorted(files, key=_group)  # sorted() is stable


# ---------------------------------------------------------------------------
# Preparing the push input
# ---------------------------------------------------------------------------


def _relay_identifiers(set_all: str) -> dict[str, set[str]]:
    """IP addresses, names (RID/TID), part number, and model in a relay's settings."""
    ids = {"ip": set(), "name": set(), "part_number": set(), "model": set()}

    configs = parse_config_data(set_all)
    info = configs.get("INFO") if isinstance(configs.get("INFO"), dict) else {}

    if info.get("PARTNO"):
        ids["part_number"].add(info["PARTNO"].strip().upper())

    model = _model({k.upper(): str(v) for k, v in info.items()})
    if model:
        ids["model"].add(model)

    for section, settings in configs.items():
        if not isinstance(settings, dict) or section.upper() in NON_CLASS_SECTION_NAMES:
            continue

        for key, raw_value in settings.items():
            value = raw_value.get("value", "") if isinstance(raw_value, dict) else raw_value
            value = str(value).strip()
            if not value:
                continue

            if key.upper() == "IPADDR":
                ids["ip"].add(value.split("/")[0].strip())
            elif key.upper() in ["RID", "TID"]:
                ids["name"].add(value.upper())

    return ids


def _device_identifiers(dev: DeviceData) -> dict[str, set[str]]:
    names = [dev.name, dev.extra.get("relay_id"), dev.extra.get("terminal_id")]
    model = dev.description.model.strip().upper().removeprefix("SEL-").lstrip("0")
    return {
        "ip": {dev.ip} if dev.ip else set(),
        "name": {str(n).strip().upper() for n in names if n and str(n).strip()},
        "part_number": {dev.part_number.strip().upper()} if dev.part_number else set(),
        # Not a model without a number, e.g. "SEL" from "RELAYTYPE=SEL" (refer to _model())
        "model": {model} if any(c.isdigit() for c in model) else set(),
    }


def select_rdb_relay(
    dev: DeviceData, relays: dict[str, dict[str, bytes]], wanted: str = ""
) -> str:
    """
    Select the relay in a RDB file to push to a device.

    #. If ``wanted`` is set (the ``sel.push_rdb_relay`` option), the relay with that
       name (case-insensitive if there isn't an exact match).
    #. If there's only one relay in the file, that relay.
    #. Otherwise, the relay with the most settings that match the device: the
       IP address (``IPADDR``), relay or terminal ID (``RID``/``TID``) and the
       part number (``PARTNO``). Relays for a different model than the device
       are never selected. If no relay matches, or several relays match equally
       well, no relay is selected.

    Args:
        dev: The device being pushed to
        relays: Streams for each relay, keyed by the relay name,
            from :func:`~peat.modules.sel.relay_parse.read_rdb_streams`
        wanted: Name of the relay to push, if specified by the user

    Returns:
        Name of the selected relay

    Raises:
        PushInputError: A relay couldn't be selected
    """
    names = list(relays)

    if wanted:
        if wanted in relays:
            return wanted

        matches = [name for name in names if name.casefold() == wanted.strip().casefold()]
        if len(matches) == 1:
            return matches[0]

        raise PushInputError(
            f"there's no relay named '{wanted}' (option 'sel.push_rdb_relay') "
            f"in the RDB file. The relays in the file are: {', '.join(names)}"
        )

    if len(names) == 1:
        return names[0]

    dev_ids = _device_identifiers(dev)
    matched = {}  # type: dict[str, list[str]]

    for name, streams in relays.items():
        relay_ids = _relay_identifiers(rdb_relay_to_set_all(streams))

        if dev_ids["model"] and relay_ids["model"] and not dev_ids["model"] & relay_ids["model"]:
            log.debug(f"RDB relay '{name}' is for a different model than {dev.get_id()}")
            continue

        matched[name] = [
            kind for kind in ["ip", "name", "part_number"] if dev_ids[kind] & relay_ids[kind]
        ]

    best = max((len(kinds) for kinds in matched.values()), default=0)
    best_names = [name for name, kinds in matched.items() if len(kinds) == best]

    if best and len(best_names) == 1:
        name = best_names[0]
        log.info(
            f"Selected relay '{name}' in the RDB file for {dev.get_id()}, "
            f"its settings match the device's {', '.join(matched[name])}"
        )
        return name

    reason = "several relays match it equally well" if best else "no relay matches it"
    raise PushInputError(
        f"there are {len(names)} relays in the RDB file and PEAT can't tell which one "
        f"to push to {dev.get_id()} ({reason}). Set the 'sel.push_rdb_relay' option to "
        f"the name of the relay to push. The relays in the file are: {', '.join(names)}"
    )


def _check_sections(name: str, data: bytes, origin: str, class_files: dict[str, str]) -> None:
    """Check that a settings file has a single settings class, and that it matches the name."""
    sections = _section_names(data)

    if len(sections) != 1:
        raise PushInputError(
            f"{origin} has {len(sections)} settings sections, a settings file must have one"
        )

    code = sections[0].upper()
    if name not in [f"SET_{code}.TXT", class_files.get(code)]:
        raise PushInputError(
            f"{origin} has the settings for class [{sections[0]}], which aren't "
            f"the settings for {name}. Rename the file, or check it's the right file."
        )


def _from_rdb(dev: DeviceData, source: Path, rdb_relay: str) -> PushPlan:
    try:
        streams_by_relay = read_rdb_streams(source.read_bytes())
    except Exception as ex:
        raise PushInputError(f"failed to read the RDB file {source.name}: {ex}") from ex

    relays = {name: streams for name, streams in streams_by_relay.items() if name}
    if not relays:
        raise PushInputError(
            f"{source.name} doesn't have the settings for relays in a 'Relays' storage, "
            f"which is how QuickSet saves them. Extract the settings files for the relay "
            f"and push those instead."
        )

    relay_name = select_rdb_relay(dev, relays, rdb_relay)
    streams = relays[relay_name]

    stream_paths = {PurePosixPath(path).name.upper(): path for path in streams}
    settings = rdb_relay_settings_files(streams)
    if not settings:
        raise PushInputError(f"no settings files for relay '{relay_name}' in {source.name}")

    log.info(f"Pushing {len(settings)} settings files from relay '{relay_name}' in {source.name}")

    return PushPlan(
        source=source,
        input_type="rdb",
        files=[
            PushFile(
                name=name,
                data=data,
                origin=f"{source.name}: Relays/{relay_name}/{stream_paths[name]}",
            )
            for name, data in settings.items()
        ],
        set_all=rdb_relay_to_set_all(streams),
        rdb_relay=relay_name,
    )


def _from_text_file(source: Path) -> PushPlan:
    name = source.name.upper()

    if name in NEVER_PUSH_FILES and name != "SET_ALL.TXT":
        raise PushInputError(f"{name} is read-only on relays, it can't be pushed")

    raw = source.read_bytes()
    sections = _section_names(raw)
    if not sections:
        raise PushInputError(f"{source.name} doesn't have any settings sections (e.g. [1])")

    # A single settings file, e.g. "SET_1.TXT" with the [1] settings
    if len(sections) == 1 and SETTINGS_FILENAME_RE.match(name) and name != "SET_ALL.TXT":
        _check_sections(name, raw, source.name, {})
        return PushPlan(
            source=source,
            input_type="settings_files",
            files=[PushFile(name=name, data=normalize_settings_file(raw), origin=source.name)],
            set_all=combine_settings_files({name: raw}),
        )

    # Settings for multiple classes, e.g. SET_ALL.TXT, are split into the individual files
    split = split_set_all(_decode(raw))
    if not split:
        raise PushInputError(f"no settings classes in {source.name}")

    log.info(f"Splitting {source.name} into {len(split)} settings files: {', '.join(split)}")

    files = []
    for filename, text in split.items():
        data = normalize_settings_file(text.encode("latin-1"))
        files.append(
            PushFile(name=filename, data=data, origin=f"{source.name} [{_section_names(data)[0]}]")
        )

    return PushPlan(
        source=source,
        input_type="set_all",
        files=files,
        set_all=clean_settings_text(raw),
    )


def _from_directory(source: Path) -> PushPlan:
    paths = [p for p in source.iterdir() if p.is_file()]
    for sub_dir in source.iterdir():
        # Directory structure on the 300 and 400 series, e.g. "relay_files" from a pull
        if sub_dir.is_dir() and sub_dir.name.upper() == "SETTINGS":
            paths.extend(p for p in sub_dir.iterdir() if p.is_file())

    settings = {}  # type: dict[str, Path]
    set_all_path = None  # type: Path | None
    cfg_path = None  # type: Path | None

    for path in sorted(paths):
        # Filenames are case-insensitive, e.g. "set_1.txt" extracted from a RDB
        name = path.name.upper()

        if name == "SET_ALL.TXT":
            set_all_path = set_all_path or path
        elif name == "CFG.TXT":
            cfg_path = cfg_path or path
        elif SETTINGS_FILENAME_RE.match(name):
            if name in settings:
                raise PushInputError(f"{settings[name]} and {path} are both {name}")
            settings[name] = path

    if not settings:
        if set_all_path:
            log.info(f"Only a SET_ALL.TXT in {source}, pushing it")
            return _from_text_file(set_all_path)
        raise PushInputError(f"couldn't find any settings files (SET_*.TXT) in {source}")

    if set_all_path:
        log.warning(
            f"Ignoring {set_all_path.name} in {source}, "
            f"pushing the individual settings files (SET_*.TXT) instead"
        )

    class_files = {}  # type: dict[str, str]
    raw_files = {}  # type: dict[str, bytes]
    if cfg_path:
        raw_files["CFG.TXT"] = cfg_path.read_bytes()
        class_files = settings_class_files(
            _section_lines(normalize_settings_file(raw_files["CFG.TXT"]), "CLASSES") or []
        )

    files = []
    for name in sort_settings_filenames(list(settings), class_files):
        path = settings[name]
        raw = path.read_bytes()
        origin = path.relative_to(source).as_posix()
        _check_sections(name, raw, origin, class_files)
        raw_files[name] = raw
        files.append(PushFile(name=name, data=normalize_settings_file(raw), origin=origin))

    log.info(f"Pushing {len(files)} settings files from {source}: {', '.join(settings)}")

    return PushPlan(
        source=source,
        input_type="settings_files",
        files=files,
        set_all=combine_settings_files(raw_files),
    )


def _check_input(dev: DeviceData, plan: PushPlan) -> None:
    """Checks of the push input that don't need a connection to the relay."""
    for pf in plan.files:
        if pf.name in NEVER_PUSH_FILES or not SETTINGS_FILENAME_RE.match(pf.name):
            raise PushInputError(f"{pf.name} isn't a writable settings file")

    models = {}  # type: dict[str, str]
    for pf in plan.files:
        info = _info_values(pf.data)
        if not info:
            log.warning(f"{pf.name} doesn't have an [INFO] section, the relay may reject it")
        if _model(info):
            models.setdefault(_model(info), pf.name)

    if len(models) > 1:
        raise PushInputError(
            f"the settings files are for different relay models: "
            f"{', '.join(f'{name} is for a SEL-{model}' for model, name in models.items())}"
        )

    dev_model = _device_identifiers(dev)["model"]
    if models and dev_model and not dev_model & set(models):
        raise PushInputError(
            f"the settings are for a SEL-{next(iter(models))}, but "
            f"{dev.get_id()} is a SEL-{next(iter(dev_model))}"
        )

    # Warn about changes to the IP address PEAT is connected to
    for pf in plan.files:
        new_ip = _setting_value(pf.data, "IPADDR")
        if is_port_file(pf.name) and new_ip and dev.ip and new_ip.split("/")[0] != dev.ip:
            log.warning(
                f"{pf.name} sets the IP address (IPADDR) to {new_ip}, but PEAT is "
                f"connected to {dev.ip}. If that's the port PEAT is connected through, "
                f"the connection will end after {pf.name} is uploaded, and the relay "
                f"will be at the new address. {pf.name} is uploaded last."
            )


def _input_failed(dev: DeviceData, source: Path, message: str) -> None:
    # Record why there's nothing to push, with the same keys as a push plan
    PushPlan(source=source, input_type="", files=[], set_all="").fail(dev, message)


def prepare_push(dev: DeviceData, source: Path, rdb_relay: str = "") -> PushPlan | None:
    """
    Read the push input and prepare the settings files to upload. Nothing is
    sent to the relay. Errors are logged, and saved in ``dev.extra["push"]``.

    The plan must be checked with :func:`check_push_input` before it's pushed.

    Args:
        dev: The device being pushed to
        source: Path of the push input: a RDB file, ``SET_ALL.TXT``, an
            individual settings file, or a directory of settings files
        rdb_relay: Name of the relay in a RDB file to push
            (the ``sel.push_rdb_relay`` option)

    Returns:
        The files to push in the order to upload them, or :obj:`None` if
        the input can't be read or converted into settings files
    """
    try:
        if source.is_dir():
            plan = _from_directory(source)
        else:
            # NOTE: isOleFile interprets data shorter than 1536 bytes
            # as a filename, so it's always passed a file pointer.
            with source.open("rb") as fp:
                is_rdb = olefile.isOleFile(fp)

            plan = _from_rdb(dev, source, rdb_relay) if is_rdb else _from_text_file(source)
    except PushInputError as ex:
        return _input_failed(dev, source, str(ex))
    except Exception as ex:
        log.exception(f"Unhandled exception while reading the push input {source}")
        return _input_failed(dev, source, f"unable to read {source}: {ex}")

    plan.files = order_for_upload(plan.files)
    for pf in plan.files:
        pf.upload_data = pf.data

    log.debug(f"Settings files to push, in order: {', '.join(pf.name for pf in plan.files)}")

    return plan


def check_push_input(dev: DeviceData, plan: PushPlan) -> bool:
    """
    Checks of the push input that don't need a connection to the relay: the
    files are writable settings files, and they're for the same model as each
    other and as the device (if its model is known). If a check fails, the push
    status in ``dev.extra["push"]`` is set to ``failed``, with the reason.

    Args:
        dev: The device being pushed to
        plan: The files to push, from :func:`prepare_push`

    Returns:
        If the files can be pushed to the device
    """
    try:
        _check_input(dev, plan)
    except PushInputError as ex:
        return plan.fail(dev, f"{ex}. Nothing was uploaded.")

    return True


def save_push_files(dev: DeviceData, plan: PushPlan, peat_module: str = "SELRelay") -> None:
    """
    Save the settings being pushed in the device results, and hash and record them.
    This is done before connecting to the relay, so the files are kept
    if the push fails.

    - ``push_SET_ALL.txt``: the settings, in the ``SET_ALL`` format
    - ``push_files/<name>``: each settings file to upload (e.g. ``push_files/SET_1.TXT``)
    """
    derived_from = {"derived_from": [plan.source.name]}
    if plan.rdb_relay:
        derived_from["rdb_relay_name"] = plan.rdb_relay

    write_and_record_file(
        dev=dev,
        data=plan.set_all,
        filename=PUSH_SET_ALL_FILENAME,
        source=SOURCE_DERIVED,
        peat_module=peat_module,
        description=(
            f"Settings pushed to the relay from {plan.source.name}, in the SET_ALL.TXT "
            f"format (created by PEAT, not a file on the relay)"
        ),
        extra=derived_from,
    )

    for pf in plan.files:
        file_obj = write_and_record_file(
            dev=dev,
            data=pf.data,
            filename=f"{PUSH_FILES_DIR}/{pf.name}",
            source=SOURCE_PUSH,
            peat_module=peat_module,
            description=f"Settings file prepared by PEAT to push to the relay, from {pf.origin}",
            extra=derived_from,
        )
        if file_obj is not None:
            pf.files.append(file_obj)

    plan.update(dev)


# ---------------------------------------------------------------------------
# Uploading the files
# ---------------------------------------------------------------------------


def _retrieve(relay: FTP, filename: str) -> bytes:
    """Download a file without saving it (and without warning if it's empty, like ERR.TXT)."""
    buffer = BytesIO()
    relay.ftp.retrbinary(f"RETR {filename}", buffer.write)
    return buffer.getvalue()


def _read_relay_cfg(dev: DeviceData, relay: FTP, peat_module: str) -> bytes:
    """Read CFG.TXT from the root directory of the relay, and save it in the device results."""
    try:
        data = _retrieve(relay, "CFG.TXT")
    except ftplib.all_errors as ex:
        log.warning(f"Failed to read CFG.TXT from {dev.get_id()} before pushing: {ex}")
        return b""

    write_and_record_file(
        dev=dev,
        data=data,
        filename=f"{PUSH_FILES_DIR}/from_relay/CFG.TXT",
        name="CFG.TXT",
        device_path="/CFG.TXT",
        transport="ftp",
        source=SOURCE_DOWNLOAD,
        peat_module=peat_module,
        description="CFG.TXT read from the relay before pushing settings",
        extra={"file_transfer": "ftp"},
    )

    return normalize_settings_file(data)


def _check_relay(dev: DeviceData, plan: PushPlan, relay_cfg: bytes) -> str:
    """
    Check the files to push against the relay's ``CFG.TXT``.

    Returns:
        An error message if the files must not be pushed, otherwise an empty string
    """
    relay_info = _info_values(relay_cfg)
    relay_model = _model(relay_info)
    relay_z = _settings_version(relay_info.get("FID", ""))

    if not relay_model:
        log.warning(
            f"The relay model of {dev.get_id()} isn't in its CFG.TXT, "
            f"PEAT can't check that the settings are for this model"
        )

    other_versions = {}  # type: dict[str, list[str]]
    for pf in plan.files:
        info = _info_values(pf.data)
        file_model = _model(info)

        if relay_model and file_model and file_model != relay_model:
            return (
                f"{pf.name} is for a SEL-{file_model}, but the relay is a SEL-{relay_model} "
                f"(RELAYTYPE in its CFG.TXT). Nothing was uploaded."
            )

        file_z = _settings_version(info.get("FID", ""))
        if relay_z and file_z and relay_z != file_z:
            other_versions.setdefault(file_z, []).append(pf.name)

    for file_z, names in other_versions.items():
        log.warning(
            f"{', '.join(names)} have settings version {file_z}, but the relay's firmware "
            f"has settings version {relay_z} (the Z-number in the FID). The relay "
            f"may reject settings that differ between the versions."
        )

    return ""


def _prepare_uploads(dev: DeviceData, plan: PushPlan, relay_cfg: bytes, peat_module: str) -> None:
    """
    Replace placeholder ``[INFO]`` sections from QuickSet templates
    with the relay's ``[INFO]`` section from its ``CFG.TXT``.
    """
    relay_info_lines = _section_lines(relay_cfg, "INFO")

    for pf in plan.files:
        pf.upload_data = pf.data

        if not relay_info_lines or not has_placeholder_info(pf.data):
            continue

        pf.upload_data = replace_info_section(pf.data, relay_info_lines)
        log.info(f"Replacing the placeholder [INFO] in {pf.name} with the relay's [INFO]")

        file_obj = write_and_record_file(
            dev=dev,
            data=pf.upload_data,
            filename=f"{PUSH_FILES_DIR}/uploaded/{pf.name}",
            source=SOURCE_PUSH,
            peat_module=peat_module,
            description=(
                f"{pf.name} as uploaded to the relay: the settings from {pf.origin}, with "
                f"the relay's [INFO] section instead of the placeholder from the RDB file"
            ),
            extra={"derived_from": [pf.name, "CFG.TXT"]},
        )
        if file_obj is not None:
            pf.files.append(file_obj)


class _UploadResult(NamedTuple):
    status: str
    message: str
    #: If the connection to the relay ended
    disconnected: bool = False
    #: Contents of ERR.TXT, if the relay rejected the file
    errors: bytes = b""


def _record_upload(dev: DeviceData, pf: PushFile, device_path: str, peat_module: str) -> None:
    """
    Record the path on the relay of the file that was uploaded, like the
    files downloaded from relays (``path`` is the path on the relay and
    ``local_path`` is the copy saved by PEAT).
    """
    if not pf.files:
        pf.files.append(
            record_downloaded_file(
                dev=dev,
                data=pf.upload_data,
                name=pf.name,
                device_path=device_path,
                transport="ftp",
                source=SOURCE_PUSH,
                peat_module=peat_module,
                description=f"Settings file uploaded to the relay by PEAT, from {pf.origin}",
                extra={"file_transfer": "ftp"},
            )
        )
        return

    # The last file is the one with the data that was uploaded
    file_obj = pf.files[-1]
    file_obj.path = PurePosixPath(device_path)
    file_obj.directory = ""  # Set from the path by annotate()
    file_obj.extra.update({"transport": "ftp", "file_transfer": "ftp"})
    file_obj.annotate(dev)


def _upload_one(
    dev: DeviceData, relay: FTP, pf: PushFile, device_path: str, peat_module: str
) -> _UploadResult:
    """
    Upload a settings file, then read ``ERR.TXT`` to check if the relay accepted it.
    """
    log.info(
        f"Uploading {pf.name} to {dev.get_id()} ({len(pf.upload_data)} bytes, "
        f"attempt {pf.attempts})"
    )

    # Port settings with an IP address are for the port PEAT is likely
    # connected through, and the relay may end the connection after they change.
    ends_connection = (
        is_port_file(pf.name) and _setting_value(pf.upload_data, "IPADDR") is not None
    )

    try:
        relay.upload_text(pf.name, BytesIO(pf.upload_data))
    except ftplib.Error as ex:
        # The relay replied with an error, e.g. "550 Permission denied"
        return _UploadResult(STATUS_FAILED, f"The relay refused the upload: {ex}")
    except (OSError, EOFError) as ex:
        if not ends_connection:
            return _UploadResult(
                STATUS_FAILED, f"The connection ended while uploading: {ex}", disconnected=True
            )

        _record_upload(dev, pf, device_path, peat_module)
        return _UploadResult(
            STATUS_UNVERIFIED,
            f"The connection ended while uploading the port settings ({ex}). This is "
            f"expected if they're the settings for the port PEAT is connected through.",
            disconnected=True,
        )

    _record_upload(dev, pf, device_path, peat_module)

    sleep(UPLOAD_DELAY)

    try:
        errors = _retrieve(relay, ERR_FILENAME)
    except ftplib.Error as ex:
        return _UploadResult(
            STATUS_UNVERIFIED,
            f"Uploaded, but {ERR_FILENAME} couldn't be read to check the settings ({ex})",
        )
    except (OSError, EOFError) as ex:
        return _UploadResult(
            STATUS_UNVERIFIED,
            f"Uploaded, but the connection ended before {ERR_FILENAME} was read ({ex})",
            disconnected=True,
        )

    error_text = clean_settings_text(errors).strip()
    if error_text:
        return _UploadResult(STATUS_REJECTED, error_text, errors=errors)

    return _UploadResult(STATUS_ACCEPTED, "")


def _save_errors(
    dev: DeviceData, pf: PushFile, errors: bytes, device_path: str, peat_module: str
) -> None:
    """Save the ERR.TXT for a rejected file in the device results."""
    write_and_record_file(
        dev=dev,
        data=errors,
        filename=f"{PUSH_FILES_DIR}/from_relay/ERR_{pf.name}",
        name=ERR_FILENAME,
        device_path=str(PurePosixPath(device_path).with_name(ERR_FILENAME)),
        transport="ftp",
        source=SOURCE_DOWNLOAD,
        peat_module=peat_module,
        description=f"{ERR_FILENAME} read from the relay after uploading {pf.name}",
        extra={"file_transfer": "ftp", "push_file": pf.name},
    )


def _may_need_settings_wait(model: str) -> bool:
    # SEL-700 series (700G, 710, 751, ...). If the model isn't known, there's no
    # wait and no retries, so a failed or rejected file stops the push.
    return model.startswith("7")


def _retry_pause(result: _UploadResult, remaining: float, rejected_retries: int) -> float | None:
    """
    Seconds to wait before uploading a file again, while waiting for a SEL-700 series
    relay after Port 1 or Logic settings changed, or :obj:`None` if it's not uploaded again.

    Args:
        result: Result of the last upload of the file
        remaining: Seconds until the wait is over (zero or less if there's no wait)
        rejected_retries: Times the file was uploaded again after the relay rejected it
    """
    if result.disconnected or remaining <= 0:
        return None

    # The relay replied to the upload (STOR) with an error, so it likely didn't take the settings
    if result.status == STATUS_FAILED:
        return min(RETRY_INTERVAL, remaining)

    # The relay checked the settings and listed errors. That may be because of the wait,
    # or a real error, so the file is only uploaded again once the wait is over.
    if result.status == STATUS_REJECTED and rejected_retries < MAX_REJECTED_RETRIES:
        return remaining

    return None


def upload_settings_files(
    dev: DeviceData,
    relay: FTP,
    plan: PushPlan,
    allow_unlisted: bool = False,
    peat_module: str = "SELRelay",
) -> bool:
    """
    Upload the settings files in a push plan to a relay via FTP.

    #. Read ``CFG.TXT`` and check that the settings are for the relay's model.
    #. Check that every file is on the relay (in the file listing or
       ``CFG.TXT``), unless ``allow_unlisted`` is set. Nothing is
       uploaded if a file isn't on the relay.
    #. Replace placeholder ``[INFO]`` sections from QuickSet templates with
       the relay's ``[INFO]`` section.
    #. Upload each file and read ``ERR.TXT``. If the relay rejects a file, or
       an upload fails, the push stops and the remaining files aren't uploaded.
       On SEL-700 series relays, in the two minutes after Port 1 or Logic
       settings were accepted, an upload the relay refuses (the ``STOR`` fails)
       is retried every :data:`RETRY_INTERVAL` seconds until the two minutes are
       up, and a file the relay rejects (``ERR.TXT`` lists errors) is uploaded
       again once, when the two minutes are up.

    The FTP session must be logged in, in the root directory, and
    ``dev.extra["file_listing"]`` must be populated.

    Args:
        dev: The device being pushed to
        relay: FTP session with the relay
        plan: The files to push, from :func:`prepare_push`
        allow_unlisted: Upload files that aren't on the relay
            (the ``sel.push_unlisted_files`` option)
        peat_module: Name of the PEAT module, for the recorded files

    Returns:
        If every file was uploaded, and the relay didn't reject any of them
    """
    try:
        return _upload_settings_files(dev, relay, plan, allow_unlisted, peat_module)
    except Exception as ex:
        plan.fail(dev, f"Unhandled exception while uploading: {ex}")
        raise


def _upload_settings_files(
    dev: DeviceData, relay: FTP, plan: PushPlan, allow_unlisted: bool, peat_module: str
) -> bool:
    settings_root = dev.extra.get("settings_root_directory", "/")
    listing = {
        str(name).upper() for name in dev.extra.get("file_listing", {}).get(settings_root, [])
    }

    relay_cfg = _read_relay_cfg(dev, relay, peat_module)
    problem = _check_relay(dev, plan, relay_cfg)
    if problem:
        return plan.fail(dev, problem)

    # Files the relay has, from the file listing and the classes in CFG.TXT
    on_relay = listing | set(
        settings_class_files(_section_lines(relay_cfg, "CLASSES") or []).values()
    )

    not_on_relay = [pf.name for pf in plan.files if pf.name not in on_relay]
    if not_on_relay:
        if not allow_unlisted:
            return plan.fail(
                dev,
                f"{len(not_on_relay)} of the settings files aren't on the relay: "
                f"{', '.join(not_on_relay)}. Nothing was uploaded. Ensure you're pushing "
                f"the right settings to the right relay. To upload them anyway, set "
                f"the 'sel.push_unlisted_files' option to true.",
            )
        log.warning(
            f"{len(not_on_relay)} files being pushed aren't currently on the relay "
            f"(they're new files). Ensure you are pushing the right files to the "
            f"appropriate device! List of files: {not_on_relay}"
        )

    on_relay_not_pushed = sorted(
        name
        for name in on_relay
        if SETTINGS_FILENAME_RE.match(name)
        and name not in NEVER_PUSH_FILES
        and name not in {pf.name for pf in plan.files}
    )
    if on_relay_not_pushed:
        log.debug(
            f"{len(on_relay_not_pushed)} settings files on the relay aren't being pushed. "
            f"This is expected if you're pushing a subset of the settings "
            f"(e.g. just SET_1.TXT). List of files: {on_relay_not_pushed}"
        )

    _prepare_uploads(dev, plan, relay_cfg, peat_module)

    # If the settings are in a "SETTINGS" directory, then change
    # directories before transferring configs ("cd SETTINGS").
    # ERR.TXT for the settings files is in the same directory.
    if settings_root == "SETTINGS":
        log.info("Changing directory to 'SETTINGS' before pushing configs")
        if not relay.cd("/SETTINGS"):
            return plan.fail(dev, "Failed to change to the SETTINGS directory on the relay")
        device_dir = "/SETTINGS"
    else:
        device_dir = ""

    model = _model(_info_values(relay_cfg)) or next(iter(_device_identifiers(dev)["model"]), "")
    may_need_wait = _may_need_settings_wait(model)
    wait_until = 0.0

    plan.status = STATUS_UPLOADING
    log.info(
        f"Uploading {len(plan.files)} settings files to {dev.get_id()}: "
        f"{', '.join(pf.name for pf in plan.files)}. This will take at least "
        f"{UPLOAD_DELAY * len(plan.files):.0f} seconds."
    )

    for index, pf in enumerate(plan.files):
        device_path = f"{device_dir}/{pf.name}"

        rejected_retries = 0
        while True:
            pf.attempts += 1
            plan.set_file_status(dev, pf, STATUS_UPLOADING)

            result = _upload_one(dev, relay, pf, device_path, peat_module)

            pause = _retry_pause(result, wait_until - monotonic(), rejected_retries)
            if pause is None:
                break

            if result.status == STATUS_REJECTED:
                rejected_retries += 1
                retry_msg = f"Uploading it again in {pause:.0f} seconds, when that time is up"
            else:
                retry_msg = f"Retrying in {pause:.0f} seconds"

            log.warning(
                f"{pf.name} was {result.status} ({result.message}). SEL-700 series relays "
                f"may not accept settings for up to {SEL700_SETTINGS_WAIT:.0f} seconds after "
                f"Port 1 or Logic settings change. {retry_msg}."
            )
            sleep(pause)

        plan.set_file_status(dev, pf, result.status, result.message)

        if result.status == STATUS_ACCEPTED:
            log.info(f"{pf.name} was accepted by {dev.get_id()}")
        elif result.status == STATUS_UNVERIFIED:
            log.warning(
                f"{pf.name} was uploaded to {dev.get_id()}, but not checked: {result.message}"
            )
        elif result.status == STATUS_REJECTED:
            _save_errors(dev, pf, result.errors, device_path, peat_module)
            return plan.fail(
                dev,
                f"The relay rejected {pf.name}, the remaining files weren't uploaded. "
                f"Errors in {ERR_FILENAME}: {result.message}",
            )
        else:
            return plan.fail(
                dev,
                f"Failed to upload {pf.name}, the remaining files weren't uploaded: "
                f"{result.message}",
            )

        if result.disconnected and index < len(plan.files) - 1:
            return plan.fail(
                dev,
                f"The connection to the relay ended after {pf.name} was uploaded, "
                f"{len(plan.files) - index - 1} files weren't uploaded",
            )

        if may_need_wait and (pf.name == "SET_P1.TXT" or _LOGIC_FILE_RE.match(pf.name)):
            wait_until = monotonic() + SEL700_SETTINGS_WAIT

    plan.status = STATUS_SUCCESS
    unverified = [pf.name for pf in plan.files if pf.status == STATUS_UNVERIFIED]
    plan.message = (
        f"{len(unverified)} files were uploaded but not checked: {', '.join(unverified)}"
        if unverified
        else ""
    )
    plan.update(dev)

    log.info(f"Uploaded {len(plan.files)} settings files to {dev.get_id()}")
    return True


__all__ = [
    "PushFile",
    "PushInputError",
    "PushPlan",
    "check_push_input",
    "has_placeholder_info",
    "order_for_upload",
    "prepare_push",
    "replace_info_section",
    "save_push_files",
    "select_rdb_relay",
    "upload_settings_files",
]
