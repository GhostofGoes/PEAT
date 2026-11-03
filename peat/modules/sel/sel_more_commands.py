"""
Run the additional read-only SEL ASCII commands on a relay
(``sel.attempt_more_commands``), and put their output into the device data model.

:meth:`~peat.modules.sel.sel_relay.SELRelay.pull_more_commands` uses
:class:`MoreCommands` to run the commands in the registry
(:data:`~peat.modules.sel.sel_commands.COMMANDS`) in the same order over
Telnet and serial, and :func:`process_outputs` to parse them. Every command
is read-only (refer to :mod:`peat.modules.sel.sel_commands`).

The order:

#. Discovery, at access level 1: ``ID`` (only if the FID isn't known yet, e.g. a
   pull without a scan), ``HELP`` (the commands at the present level), and ``CAS``
   (the Compressed ASCII commands).
#. On SEL-400 series relays, ``STA``, ``STA S``, and ``STA A``, before PEAT
   elevates to level 2: ``STA`` at level 2 may ask "Accept new hardware
   configuration (Y/N)?" (SEL-421 IM 20130627, Table 9.125). PEAT never answers
   ``Y`` to a question it doesn't expect (it answers ``N``).
#. Elevate to level 2, as PEAT did before (not on the SEL-2030/2032).
#. The other commands, in :data:`~peat.modules.sel.sel_commands.RELAY_ORDER`,
   and then the ``SHO`` commands (``sel.show_settings``).

``CSE`` is used instead of ``SER`` if ``CAS`` lists it, with ``SER`` as the
fallback. ``HIS`` is run as before, and ``CHI`` only if ``HIS`` failed and ``CAS``
lists it. ``HELP`` only filters the commands that were added with the registry:
the commands PEAT ran before (``legacy`` in
:class:`~peat.modules.sel.sel_commands.ReadCommand`) are always run.
"""

from datetime import datetime
from typing import Any, Final

from peat import CommError, DeviceData, log, utils

from .relay_command_parse import (
    help_lists_commands,
    parse_cascii_names,
    parse_cst_output,
    parse_eth_output,
    parse_goose_output,
    parse_help_output,
    parse_selogic_usage,
    parse_status_details,
    parse_time_quality,
    parse_ver_output,
    process_eth_info,
    process_goose_info,
    process_status_details,
    process_time_quality,
    process_ver_info,
)
from .relay_parse import (
    extract_date_format,
    get_date_format,
    parse_and_process_events,
    parse_show_output,
    parse_status_output,
    process_info_into_dev,
)
from .sel_ascii import SELAscii, SELResponse, SELSessionHalted
from .sel_cascii import ETX, STX, is_compressed_ascii, is_no_data, parse_cas
from .sel_commands import (
    COMMANDS,
    COMMANDS_2030,
    RELAY_ORDER,
    SHOW_SETTINGS_DEFAULT,
    ReadCommand,
    listed,
    normalize_command,
    show_settings_commands,
)
from .sel_default_creds import FAMILY_2030, model_family
from .sel_files import SOURCE_COMMAND_OUTPUT, write_and_record_file

#: Key in ``DeviceData._cache`` for the settings from the ``SHO`` commands,
#: which are parsed as the relay's settings if no settings file was pulled
SHOW_SETTINGS_CACHE_KEY: Final = "sel_show_settings"

#: Directory (in the device's output directory) for the output of each command
COMMAND_OUTPUT_DIR: Final = "ascii_commands"

#: Prefix of the names of the results of ``SHO`` commands, e.g. ``sho_g``
SHOW_RESULT_PREFIX: Final = "sho_"


def show_result_name(command: str) -> str:
    """Name of the result of a ``SHO`` command, e.g. ``"SHO L 1"`` => ``"sho_l_1"``."""
    words = normalize_command(command).lower().split()[1:]
    return SHOW_RESULT_PREFIX + "_".join(words) if words else "sho"


def _output_text(response: SELResponse) -> str:
    """The output of a command (without the prompt), without STX and ETX."""
    return response.body.replace(STX, "").replace(ETX, "")


class MoreCommands:
    """
    Runs the additional commands on a relay (refer to the module docstring).
    """

    def __init__(
        self,
        dev: DeviceData,
        comms: SELAscii,
        creds: dict | None = None,
        show_settings: list[str] | tuple[str, ...] | None = SHOW_SETTINGS_DEFAULT,
    ) -> None:
        """
        Args:
            dev: The device
            comms: SEL ASCII session (Telnet or serial), at level 1
            creds: Configured access level passwords, for the level 2 login
            show_settings: Settings classes to show with ``SHO``
                (refer to :func:`~peat.modules.sel.sel_commands.show_settings_commands`)
        """
        self.dev = dev
        self.comms = comms
        self.creds = creds or {}
        self.show_settings = list(show_settings or [])
        self.log = log.bind(target=comms.address)

        #: Results of the commands, keyed by name, as they're saved in
        #: ``additional-command-outputs.json``
        self.outputs: dict[str, dict] = {}
        #: Responses to the commands of each result
        self.responses: dict[str, list[SELResponse]] = {}
        #: Commands that weren't sent, and why
        self.skipped: dict[str, str] = {}
        #: Errors from the device (e.g. "Invalid Command"), keyed by name
        self.errors: dict[str, str] = {}
        #: Commands that ``HELP`` lists, or :obj:`None` if they aren't known
        self.help_commands: list[str] | None = None
        #: Compressed ASCII commands that ``CAS`` lists, or :obj:`None` if not known
        self.cas_commands: dict[str, dict] | None = None
        #: Number of commands that were sent
        self.attempted = 0
        #: Why PEAT stopped running commands (e.g. the connection was lost), or
        #: an empty string. Refer to ``comms.halted`` too.
        self.stopped = ""

    @property
    def model(self) -> str:
        return self.dev.description.model or self.comms.model

    @property
    def family(self) -> str:
        return model_family(self.model)

    def run(self) -> dict[str, dict]:
        """
        Run the commands.

        Returns:
            The results (:attr:`outputs`). If the session halted
            (``comms.halted``), the results so far.
        """
        if self.family == FAMILY_2030:
            # NOTE: the SEL-2032 is no longer supported by SEL, so how PEAT
            # accesses it shouldn't need to change (this is only used with
            # sel.legacy_ascii_timing).
            self.comms.POST_WRITE_SLEEP = 4.0
            order = list(COMMANDS_2030.values())
        else:
            self._discover()
            order = [COMMANDS[name] for name in RELAY_ORDER]

        # Commands that must run below level 2 (e.g. STA on the 400 series)
        early = {spec.name for spec in order if self.family in spec.below_level_2}
        for spec in order:
            if spec.name in early:
                self._run(spec)

        if self.family != FAMILY_2030 and not self.comms.halted and not self.stopped:
            # As before, elevate to level 2 for the other commands. If the
            # elevation fails, continue anyway (unless nothing can be sent).
            self.comms.elevate(2, self.creds)

        for spec in order:
            if self.comms.halted:
                # e.g. the relay asked a question and didn't show its prompt after N
                self.log.error(f"Stopped running commands on {self.comms.address}: halted")
                break
            if self.stopped:
                break
            if spec.name in early:
                continue
            if spec.name == "ser" and self.family != FAMILY_2030:
                self._run_events("cse", "ser")
            elif spec.name == "his":
                self._run_history()
            else:
                self._run(spec)

        if self.family != FAMILY_2030 and not self.comms.halted and not self.stopped:
            self._run_show_settings()

        return self.outputs

    def _discover(self) -> None:
        if not self.dev.firmware.id:
            # The device wasn't verified (e.g. a pull without a scan)
            self._run(COMMANDS["id"])
            info = self.outputs.get("id", {}).get("result")
            if isinstance(info, dict) and info.get("FID"):
                process_info_into_dev(info, self.dev)

        response = self._run(COMMANDS["help"])
        if response is not None and not response.error:
            names = parse_help_output(response.body)
            if help_lists_commands(names):
                self.help_commands = names
            elif names:
                self.log.debug(f"'HELP' output doesn't look like a list of commands: {names}")

        response = self._run(COMMANDS["cas"])
        if response is not None and not response.error:
            commands = parse_cas(response.body)
            if commands:
                self.cas_commands = commands

    def _skip_reason(self, spec: ReadCommand, command: str) -> str:
        if self.family not in spec.families:
            return f"not sent to the {self.family or 'unknown'} family"
        if spec.compressed and (
            self.cas_commands is None or not listed(command, self.cas_commands)
        ):
            return "CAS doesn't list it"
        # Compressed ASCII commands are checked with CAS instead, and the
        # commands PEAT ran before are always run (the HELP layout is a guess)
        if (
            spec.min_level >= 1
            and not spec.compressed
            and not spec.legacy
            and self.help_commands is not None
            and not listed(command, self.help_commands)
        ):
            return "HELP doesn't list it"
        if self.comms.is_unsupported(command):
            return "the device answered 'Invalid Command' to it before"
        return ""

    def _run(self, spec: ReadCommand, command: str = "", name: str = "") -> SELResponse | None:
        """
        Run a command, and save its result in :attr:`outputs`.

        Returns:
            The last response to the command, or :obj:`None` if it wasn't sent
            or nothing was received
        """
        name = name or spec.name
        command = command or spec.command_for(self.model)

        if self.comms.halted or self.stopped:
            return None

        reason = self._skip_reason(spec, command)
        if reason:
            self.log.debug(f"Not running '{command}' on {self.comms.address}: {reason}")
            self.skipped[name] = reason
            return None

        self.attempted += 1
        start = len(self.comms.responses)
        func = getattr(self.comms, spec.method) if spec.method else None
        result: Any = None

        try:
            if func is not None:
                result = func()
            else:
                response = self.comms.run_read_command(
                    command, long=spec.long, legacy_delay=spec.legacy_delay
                )
                result = response.lines
        except SELSessionHalted as ex:
            self.log.error(f"Stopped running commands on {self.comms.address}: {ex}")
            return None
        except (CommError, OSError, EOFError) as ex:
            # Every other command would fail too (and wait for the timeout)
            self.stopped = f"connection error: {ex}"
            self.log.error(f"Stopped running commands on {self.comms.address}: {self.stopped}")
        except Exception as ex:
            self.log.warning(f"Failed to run '{command}' ({name}) on {self.comms.address}: {ex}")

        responses = self.comms.responses[start:]
        if any(r.eof for r in responses) and not self.stopped:
            self.stopped = "the connection was closed"
            self.log.error(f"Stopped running commands on {self.comms.address}: {self.stopped}")
        # The last response is the outcome, e.g. "SER" after "SER 1000" failed
        error = responses[-1].error if responses else ""

        if result or responses:
            self.responses[name] = responses
        if error:
            self.errors[name] = error
            self.log.info(f"'{command}' ({name}) failed on {self.comms.address}: {error}")
        elif not result:
            self.log.warning(f"No output from '{command}' ({name}) on {self.comms.address}")

        if result:
            entry = {
                "cmd": name,
                "command": command,
                "func": repr(func) if func is not None else f"run_read_command({command!r})",
                # Timestamp of when the command was run
                "timestamp": utils.utc_now(),
                "result": result,
            }
            if error:
                entry["error"] = error
            self.outputs[name] = entry

        return responses[-1] if responses else None

    def _run_events(self, compressed: str, text: str) -> None:
        """
        Run the Compressed ASCII command for events (``CSE``) if ``CAS`` lists it,
        otherwise (or if it fails) the text command (``SER``).
        """
        response = self._run(COMMANDS[compressed])
        if response is not None and not response.error:
            body = _output_text(response)
            if is_compressed_ascii(body) or is_no_data(body):
                return
            self.log.warning(
                f"'{response.command}' output from {self.comms.address} isn't "
                f"Compressed ASCII, using '{COMMANDS[text].command_for(self.model)}'"
            )
            self.outputs.pop(compressed, None)
        self._run(COMMANDS[text])

    def _run_history(self) -> None:
        """
        Run ``HIS``, as before, and ``CHI`` only if ``HIS`` failed (an error or
        no output) and ``CAS`` lists it.
        """
        self._run(COMMANDS["his"])
        if "his" in self.outputs and "his" not in self.errors:
            return
        self._run(COMMANDS["chi"])

    def _run_show_settings(self) -> None:
        group = self.outputs.get("active_group", {}).get("result")
        group = str(group) if isinstance(group, (str, int)) and str(group).isdigit() else ""

        for command in show_settings_commands(self.show_settings, group):
            spec = ReadCommand(
                show_result_name(command), command, long=True, description="Settings"
            )
            self._run(spec)


def _show_settings_text(collector: MoreCommands) -> str:
    """
    The output of the ``SHO`` commands, each with a line with the command
    (``=>>SHO G``) so the settings class is known (refer to
    :func:`~peat.modules.sel.relay_parse.parse_show_output`).
    """
    parts = []
    for name, responses in collector.responses.items():
        if not name.startswith(SHOW_RESULT_PREFIX) or name in collector.errors:
            continue
        for response in responses:
            lines = _output_text(response).replace("\r\n", "\n").split("\n")
            # The relay's echo of the command is replaced by the command
            if lines and lines[0].strip().upper() == response.command.strip().upper():
                lines = lines[1:]
            parts.append("\n".join([f"=>>{response.command}", *lines]))
    return "\n\n".join(parts)


def save_command_outputs(collector: MoreCommands, transport: str, peat_module: str) -> None:
    """
    Save and hash the output of each command, as it was received (with the
    echo of the command, framing, and prompt), in ``ascii_commands/<name>.txt``.
    """
    for name, responses in collector.responses.items():
        raw = "".join(r.raw for r in responses if not r.skipped)
        if not raw:
            continue
        write_and_record_file(
            dev=collector.dev,
            data=raw,
            filename=f"{COMMAND_OUTPUT_DIR}/{name}.txt",
            transport=transport,
            source=SOURCE_COMMAND_OUTPUT,
            peat_module=peat_module,
            description=f"Output of the SEL ASCII command '{responses[0].command}'",
            extra={"commands": [r.command for r in responses]},
        )


def _body(collector: MoreCommands, name: str) -> str:
    """
    The output of a command, as received. If it wasn't recorded (e.g. with
    ``sel.legacy_ascii_timing``, older methods read the output without a
    response), the lines of the result are used.
    """
    responses = collector.responses.get(name, [])
    if responses:
        return "\r\n".join(_output_text(r) for r in responses)

    result = collector.outputs.get(name, {}).get("result")
    if isinstance(result, list):
        return "\r\n".join(str(line) for line in result)
    return ""


def process_outputs(collector: MoreCommands) -> dict[str, dict]:
    """
    Parse the results of the commands into the device data model.

    Returns:
        The results that weren't parsed, for ``extra.additional_command_outputs``
    """
    dev = collector.dev
    results = {name: entry for name, entry in collector.outputs.items() if "error" not in entry}
    unparsed = dict(results)

    def parsed(name: str) -> None:
        unparsed.pop(name, None)

    def step(name: str, func) -> None:
        if name not in results:
            return
        try:
            if func(results[name]) is not False:
                parsed(name)
        except Exception:
            # The output is kept in extra.additional_command_outputs
            log.exception(
                f"Failed to process the output of '{results[name]['command']}' from {dev.get_id()}"
            )

    if collector.help_commands:
        dev.extra["ascii_commands"] = collector.help_commands
    if "help" in results:
        parsed("help")
    if collector.cas_commands:
        dev.extra["compressed_ascii_commands"] = {
            cmd: info.get("access_level") for cmd, info in collector.cas_commands.items()
        }
    if "cas" in results:
        parsed("cas")

    # Processed when it was run (refer to MoreCommands._discover)
    if "id" in results:
        parsed("id")

    # The settings first, so the date format (DATE_F) is known for the events
    show_text = _show_settings_text(collector)
    if show_text:
        configs = parse_show_output(show_text)
        date_format = extract_date_format(configs)
        if date_format and not dev.extra.get("date_format"):
            dev.extra["date_format"] = date_format
        if any(key != "INFO" and value for key, value in configs.items()):
            dev._cache[SHOW_SETTINGS_CACHE_KEY] = show_text
        for name in list(unparsed):
            if name.startswith(SHOW_RESULT_PREFIX):
                parsed(name)

    def _sta(entry: dict) -> None:
        if isinstance(entry["result"], dict):
            process_info_into_dev(entry["result"], dev)
        process_status_details(parse_status_details(_body(collector, "sta")), dev)

    step("sta", _sta)

    def _sta_all(entry: dict) -> None:
        process_info_into_dev(parse_status_output(entry["result"], get_date_format(dev)), dev)
        process_status_details(parse_status_details(_body(collector, "sta_all")), dev)

    step("sta_all", _sta_all)

    def _device_time(entry: dict) -> bool:
        if not isinstance(entry["result"], datetime):
            return False
        dev.extra["device_time"] = entry["result"]
        return True

    step("device_time", _device_time)

    step(
        "ser",
        lambda entry: parse_and_process_events("\n".join(entry["result"]), "SER", dev),
    )
    step("cse", lambda _: parse_and_process_events(_body(collector, "cse"), "CSE", dev))
    step(
        "his",
        lambda entry: parse_and_process_events("\n".join(entry["result"]), "HIS", dev),
    )
    step("chi", lambda _: parse_and_process_events(_body(collector, "chi"), "CHI", dev))

    def _mac(entry: dict) -> None:
        for mac_name, mac_value in entry["result"].items():
            dev.related.mac.add(mac_value)
            dev.extra[mac_name] = mac_value

    step("mac", _mac)

    def _active_group(entry: dict) -> None:
        dev.extra["active_settings_group"] = entry["result"]

    step("active_group", _active_group)

    def _eth(_entry: dict) -> bool:
        info = parse_eth_output(_body(collector, "eth"))
        if not any(value for key, value in info.items() if key != "statistics"):
            return False
        process_eth_info(info, dev)
        return True

    step("eth", _eth)

    def _ver(_entry: dict) -> bool:
        info = parse_ver_output(_body(collector, "ver"))
        if not info:
            return False
        process_ver_info(info, dev)
        return True

    step("ver", _ver)

    def _time_quality(_entry: dict) -> bool:
        info = parse_time_quality(_body(collector, "time_quality"), get_date_format(dev))
        if not info:
            return False
        process_time_quality(info, dev)
        return True

    step("time_quality", _time_quality)

    def _goose(_entry: dict) -> bool:
        info = parse_goose_output(_body(collector, "goose"))
        if not info["transmit"] and not info["receive"]:
            return False
        process_goose_info(info, dev)
        return True

    step("goose", _goose)

    def _selogic_usage(_entry: dict) -> bool:
        usage = parse_selogic_usage(_body(collector, "status"))
        if not usage:
            return False  # e.g. SELOGIC errors on the 400 series, kept as-is
        dev.extra["selogic_usage"] = usage
        return True

    if collector.family != FAMILY_2030:
        step("status", _selogic_usage)

    for name, key in (
        ("sns", "ser_element_names"),
        ("dna", "fast_meter_relay_word_bits"),
        ("bna", "fast_meter_status_bits"),
    ):

        def _names(_entry: dict, name: str = name, key: str = key) -> bool:
            names = parse_cascii_names(_body(collector, name))
            if not names:
                return False
            dev.extra[key] = names
            return True

        step(name, _names)

    def _cst(_entry: dict) -> bool:
        values = parse_cst_output(_body(collector, "cst"))
        if not values:
            return False
        dev.extra["compressed_status"] = values
        return True

    step("cst", _cst)

    if collector.skipped:
        dev.extra["skipped_commands"] = dict(collector.skipped)
    if collector.errors:
        dev.extra["command_errors"] = dict(collector.errors)

    return unparsed


__all__ = [
    "COMMAND_OUTPUT_DIR",
    "SHOW_RESULT_PREFIX",
    "SHOW_SETTINGS_CACHE_KEY",
    "MoreCommands",
    "process_outputs",
    "save_command_outputs",
    "show_result_name",
]
