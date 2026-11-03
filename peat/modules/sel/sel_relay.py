"""
Core functionality for interrogating SEL relays.

Supported relay models (not an exhaustive list)

- 300G (Generator Relay)
- 311C (Transmission Protection System)
- 311L (Line Current Differential Protection and Automation System)
- 351 (Protection System)
- 351S (Protection Relay)
- 387 (Current Differential and Overcurrent Relay)
- 411L (Advanced Line Differential Protection, Automation, and Control System)
- 451 (Protection Automation Control)
- 487E (Transformer Protection Relay)
- 587Z (High-Impedance Differential Relay)
- 700G (Generator Protection Relay)
- 710 (Motor Protection Relay)
- 751 (Feeder Protection Relay)
- 2032 (Communications Processor)
- 2411 (Programmable Automation Controller)

.. note::
   700G FTP server port check will cause errno 11,
   "Resource temporarily unavailable". We fix this
   by resetting the connection after an ack, which
   is exactly what nmap does. While it's not as "kind",
   it's probably less likely to trigger an issue than
   hitting a device's application code and exiting in
   a non-standard way for the protocol.

.. note::
   PEAT is explicitly NOT checking FTP during identify.

   - The common case is that relays are configured with Telnet+other things
     It is highly unusual for a relay to have FTP enabled but not Telnet.
   - FTP requires login
     - Many other device types listen on FTP (network load)
     - login bans after 3-5 attempts by default
     - we're essentially brute forcing the device
   - FTP login triggers a software alarm

.. note::
   On most relays the FTP password is set by default to
   the Level 2 password. If the L2 password changes, so
   does the FTP password, unless configured otherwise.

.. warning::
   Software alarms will trigger the alarm contact on the relay! Software alarms
   are generated when elevating to level 2 in Telnet/Serial ("2ac"), logging
   into FTP, and possibly elevating to 2ac in the web interface (untested).

Listening network services (services available vary by device)

- FTP (TCP 21) (Not enabled by default)
- Telnet (TCP 23) (usually relays)
- HTTP (TCP 80) (some devices)
- HTTPS (TCP 443) (switches, some other devices)
- SNMP (UDP 161) (switches, some other devices)

Known Tested FIDs.
Not exhaustive, PEAT has been run on many others not documented here.
Also, not all functionality is working or has been tested for these FIDs.
Some may be parsing only, others may only be scan, etc.

- SEL-311C-2-R508-V0-Z104101-D20150219
- SEL-311L-7-R502-V0-Z106006-D20141106
- SEL-351-5-R510-V0-Z103103-D20110429
- SEL-351S-7-R516-V2-Z106105-D20190111
- SEL-411L-1-R124-V0-Z015003-D20190130
- SEL-451-5-R322-V0-Z025013-D20180630
- SEL-487E-3-R317-V1-Z110102-D20190211
- SEL-700G-R200-V0-Z006003-D20180629
- SEL-710-R411-V0-Z007004-D20170623
- SEL-751-R201-V1-Z007003-D20180921
- SEL-751-R300-V3-Z008004-D20210104
- SEL-2032-R115-V1-Z003001-D20151028

Authors

- Christopher Abate
- Christopher Goes
- George Thompson
- Jordan Henry
- Rachel Glockenmeier
- Taegan Williams
"""

import functools
import time
import timeit
from fnmatch import fnmatchcase
from pathlib import Path
from pprint import pformat
from typing import Any, Final, Literal

import olefile
import serial

from peat import (
    CommError,
    DeviceData,
    DeviceError,
    DeviceModule,
    Interface,
    IPMethod,
    SerialMethod,
    Service,
    config,
    consts,
    datastore,
    state,
    utils,
)
from peat.file_signature import FileSignature
from peat.protocols import FTP, check_tcp_port

from .relay_parse import (
    SER_DEVICE_TIME_KEY,
    SETTINGS_FILENAME_RE,
    apply_uptime,
    clean_settings_text,
    combine_settings_files,
    create_dev_from_configs,
    event_data_present,
    has_settings_sections,
    is_event_filename,
    looks_like_show_output,
    parse_and_process_events,
    parse_cfg_txt,
    parse_config_data,
    parse_rdb_relays,
    parse_set_all,
    process_cid_file,
    process_info_into_dev,
    read_rdb_streams,
)
from .sel_ascii import RestartResult, SELAscii
from .sel_commands import SHOW_SETTINGS_DEFAULT
from .sel_comms import populate_file_listing, pull_files
from .sel_default_creds import (
    MAX_DEFAULT_FTP_ATTEMPTS,
    Credential,
    configured_option,
    ftp_candidates,
    normalize_model,
    resolve_level_passwords,
    web_candidates,
)
from .sel_files import (
    SOURCE_COMMAND_OUTPUT,
    SOURCE_DERIVED,
    SOURCE_PARSE_INPUT,
    SOURCE_RDB_STREAM,
    annotate_settings_classes,
    record_downloaded_file,
    write_and_record_file,
)
from .sel_http import SELHTTP
from .sel_more_commands import (
    SHOW_SETTINGS_CACHE_KEY,
    MoreCommands,
    process_outputs,
    save_command_outputs,
)
from .sel_serial import SELSerial
from .sel_telnet import SELTelnet

#: Names of files on relays, parsed by SELRelay._parse_relay_files().
#: Individual settings files (SET_*.TXT) and *.CID files are also included.
RELAY_FILENAMES: Final = (
    "SET_ALL.TXT",
    "CFG.TXT",
    "SER.TXT",
    "CSER.TXT",
    "HISTORY.TXT",
    "CHISTORY.TXT",
)

#: Event files, in the order they're parsed. The compressed files (CSER, CHISTORY)
#: are only parsed if the other file of the same kind (SER, HISTORY) has no events.
EVENT_FILES: Final = (
    ("ser", ("SER.TXT", "CSER.TXT")),
    ("history", ("HISTORY.TXT", "CHISTORY.TXT")),
)

#: Directories on relays, and "Misc" in RDB files.
#: Files in these belong to the relay in the parent directory.
RELAY_DIRNAMES: Final = (
    "SETTINGS",
    "EVENTS",
    "REPORTS",
    "SER",
    "HMI",
    "DIAGNOSTICS",
    "STATUS",
    "MISC",
)

# TODO: support parse input files:
#   CFG.XML
#   VEC_D.TXT, VEC_E.TXT
#   *.CEV

# TODO: get BADPASS and other auth events from TAR.TXT
#   Refer to section 7.35 in the SEL351S manual.
#   ACCESS: Asserts while any user is logged in at Access Level B or higher
#   Row SALARM ACCESS ALRMOUT * HALARMA HALARMP HALARML HALARM
#   98 0 0 1 0 0 0 0 0
#   Row * * PASNVAL ACCESSP GRPSW SETCHG CHGPASS BADPASS

# TODO: .CEV file parsing
#   https://github.com/engineerjoe440/pycev
#   https://pycev.readthedocs.io/en/latest/
#       Associate with DNP3/Modbus registers?
#       Create event entries?
#       record.fid => Get FID information
#       record.trigger_time
#       record.frequency
#       record.*_channel_ids (analog, digital, status)
#       record.settings
#       record.group
#       record.*_count

# TODO: improve logic/settings parsing: https://github.com/danyill/sel-settings-terminal/


class SELRelay(DeviceModule):
    """
    Shared functionality for interrogating SEL relays.
    """

    device_type = "Relay"
    vendor_id = "SEL"
    vendor_name = "Schweitzer Engineering Laboratories"
    brand = "SEL"
    # NOTE: filename patterns are case-insensitive
    filename_patterns = [
        "*.rdb",
        # SET_ALL.TXT and individual settings files (SET_1.TXT, SET_P5.TXT, etc.)
        "*SET_*.TXT",
        "*CFG.TXT",
        # SER and CSER
        "*SER.TXT",
        # HISTORY and CHISTORY
        "*HISTORY.TXT",
        # *.CID (e.g. SET_61850.CID)
        "*.CID",
    ]

    # Directories of relay files, e.g. "relay_files" from a pull
    can_parse_dir = True

    # Targeted function for file_signatures custom_check usage
    def is_cid(data):
        """
        Take zlib compressed data and test if contains expected CID data
        """
        import zlib

        try:
            decompressed_bytes = zlib.decompress(data.read())
            sig = FileSignature(
                default_filename="",
                xml_tags=("{http://www.iec.ch/61850/2003/SCL}SCL",),
                substrings=("IEC 61850",),
            )
            return sig.matches(decompressed_bytes)
        except zlib.error:
            return False

    file_signatures = [
        FileSignature(
            default_filename="sel_relay.rdb",
            magic_number=olefile.MAGIC.hex(),  # "d0cf11e0a1b11ae1"
        ),
        FileSignature(
            default_filename="cfg.txt",
            substrings=(
                "[INFO]",
                "FID",
            ),
        ),
        FileSignature(
            default_filename="SET_61850.CID",
            magic_number="7801",  # zlib---no compression, no preset dictionary
            custom_check=is_cid,  # examine decompressed content
        ),
    ]

    # These are what's known to work. Others may work as well
    supported_models = [
        "300g",
        "311c",
        "311l",
        "351",
        "351s",
        "387",
        "411l",
        "451",
        "487e",
        "587",
        "587z",
        "700g",
        "710",
        "751",
        "2032",
        "2411",
    ]

    # Add aliases for specific models, e.g. "sel-300g"
    module_aliases = [f"sel-{x}" for x in supported_models]

    # For descriptions of options, refer to examples/peat-config.yaml
    default_options = {
        "ftp": {
            "user": "",
            "pass": "",
            "creds": [
                # NOTE: default lockout is 5 attempts
                ("FTPUSER", "TAIL"),  # 351S, 700G, 710, 751
                ("2AC", "TAIL"),  # 451, 411L, 487E (uses L2 password)
                ("FTP", "TAIL"),  # 351
                # ("ACC", "OTTER"),  # 451, 411L, 487E (uses L1 password)
                # If anonymous access is enabled in settings on some devices
                ("anonymous", "anonymous"),
                ("anonymous", "anonymous@"),
                # ("2ac", "TAIL"),
                # ("FTP", "OTTER"),
                # ("BAC", "OTTER"),
                # ("acc", "OTTER"),
                # ("bac", "OTTER"),
            ],
            "pull_delay": 0.5,
        },
        "web": {
            "user": "",
            "pass": "",
        },
        "sel": {
            "pull_methods": [
                "http",
                "ftp",
                "telnet",
            ],
            "attempt_more_commands": False,
            # SHO commands run with attempt_more_commands ("{group}" is the active group)
            "show_settings": list(SHOW_SETTINGS_DEFAULT),
            "allow_telnet_file_download": True,
            "force_telnet_file_download": False,
            "force_serial_pull": False,
            "force_ymodem": False,
            "only_download_files": [],  # ["SET_6.TXT"]
            "only_download_dirs": [],  # ["SETTINGS", "EVENTS"]
            "never_download_files": [],  # ["CFG.XML", "SWCFG.ZIP"]
            "never_download_dirs": [],  # ["EVENTS", "HMI"]
            "restart_after_push": False,
            "restart_timeout": 300.0,
            "restart_verify": True,
            "legacy_ascii_timing": False,
            "ascii_idle_timeout": 30.0,
            "cal_clarke_fallback": False,
            "old_ftp": False,
            "handle_download_errors": True,
            # These are PEAT's generic defaults. Unless credentials are configured,
            # the defaults for the model are used (refer to sel_default_creds.py).
            "creds": {
                "acc": "OTTER",
                # bac: "BREAKER" access level (present on 351S and others)
                "bac": "EDITH",
                "2ac": "TAIL",
                # SEL-451 'cal' default: "Sel-1"
                #   "Sel-1" also seen on: SEL-451-5-R324-V1-Z027013-D20201009
                "cal": "CLARKE",
            },
        },
    }

    # 57600 used by ymodem and by 351 by default
    sel_fallback_baudrates = [9600, 57600, 19200]

    # How often the relay's port is checked while it restarts, and how long to wait
    # for it to go down (a fast restart may be missed), in seconds
    restart_poll_interval = 5.0
    restart_down_timeout = 60.0
    # Seconds to wait for the confirmation question after STA C, and
    # for the relay to respond after it's answered (refer to restart_device())
    restart_confirm_timeout = 10.0
    restart_reboot_timeout = 10.0

    @classmethod
    def _ascii_options(cls, dev: DeviceData) -> dict:
        """Arguments for SELTelnet and SELSerial from the device options."""
        return {
            "legacy_timing": bool(dev.options["sel"]["legacy_ascii_timing"]),
            "idle_timeout": float(dev.options["sel"]["ascii_idle_timeout"]),
        }

    @classmethod
    def _prepare_ascii(cls, dev: DeviceData, comm: SELTelnet | SELSerial) -> None:
        """Give a SEL ASCII session what it needs to pick the default passwords."""
        if dev.description.model:
            comm.model = dev.description.model
        comm.cal_fallback = bool(dev.options["sel"]["cal_clarke_fallback"])

    @classmethod
    def _configured_ascii_creds(cls, dev: DeviceData) -> dict:
        """
        Access level passwords set in the configuration (``sel.creds``). Levels
        that aren't set use the defaults for the model, in SELAscii.elevate().
        """
        return configured_option(dev, "sel", "creds") or {}

    @classmethod
    def _forget_ascii_passwords(cls, dev: DeviceData) -> None:
        """
        SEL ASCII sessions remember which passwords failed on a device for the
        whole process (refer to SELAscii.forget_passwords), and which commands
        it answered with "Invalid Command" (refer to
        SELAscii.forget_unsupported_commands). Forget them at the start of a pull
        or restart, so a password that was fixed on the device (or configured
        again) is tried again, and a command that was rejected once (e.g. garbled
        on a noisy serial line) is sent again, when PEAT runs as a library or service.
        """
        for address in (dev.ip, dev.serial_port):
            if address:
                SELAscii.forget_passwords(address)
                SELAscii.forget_unsupported_commands(address)

    @classmethod
    def _level_passwords(cls, dev: DeviceData) -> dict[str, list[Credential]]:
        return resolve_level_passwords(
            dev.description.model,
            cls._configured_ascii_creds(dev),
            cal_fallback=bool(dev.options["sel"]["cal_clarke_fallback"]),
        )

    @classmethod
    def _verify_serial(cls, dev: DeviceData) -> bool:
        """
        Verify a device is a SEL Relay via commands sent over a serial connection.
        """
        baudrates = dev.options["baudrates"]  # type: list[int]
        if not baudrates:
            baudrates = cls.sel_fallback_baudrates

        # If baudrate is specified in config, then use it and don't enumerate all baudrates
        if dev.options["serial"]["baudrate"]:
            baudrates = [dev.options["serial"]["baudrate"]]

        timeout = dev.options["serial"]["timeout"]  # type: float

        cls.log.debug(f"Verifying Serial for {dev.serial_port} (timeout: {timeout})")

        for baudrate in baudrates:
            try:
                # TODO: don't use with statement, rely on atexit for cleanup on exit
                with SELSerial(
                    serial_port=dev.serial_port,
                    baudrate=baudrate,
                    timeout=timeout,
                    **cls._ascii_options(dev),
                ) as ser:
                    if not ser.test_connection():
                        cls.log.debug(
                            f"Serial connection test failed on "
                            f"{dev.serial_port} with baud {baudrate}"
                        )
                        continue

                    # Mark serial port as active
                    dev._is_active = True

                    if not cls._selascii_get_id(dev, ser):
                        cls.log.warning(f"Baudrate {baudrate} didn't work for {dev.serial_port}")
                        continue

                    iface = Interface(
                        type="rs_232",
                        serial_port=dev.serial_port,
                        baudrate=baudrate,
                        parity="none",
                        stop_bits=1,
                        flow_control="none",
                    )

                    dev.store("interface", iface, lookup="serial_port")

                    if not dev.options["serial"]["baudrate"]:
                        if not dev._runtime_options.get("serial"):
                            dev._runtime_options["serial"] = {}
                        dev._runtime_options["serial"]["baudrate"] = baudrate

                    if not cls._selascii_verify_post_process(dev, ser):
                        return False

                    if not dev.id:
                        dev.id = dev.serial_port

                    return True
            except serial.SerialException as ex:
                # This is needed on Windows to handle several cases
                raise ex
            except Exception as ex:
                cls.log.warning(
                    f"Failed verify of serial port {dev.serial_port} at baudrate {baudrate}: {ex}"
                )
                continue

        return False

    @classmethod
    def _verify_telnet(cls, dev: DeviceData) -> bool:
        """
        Verify a device is a SEL Relay via Telnet commands.
        """
        port = dev.options["telnet"]["port"]  # type: int
        timeout = dev.options["telnet"]["timeout"]  # type: float

        cls.log.debug(f"Verifying Telnet for {dev.ip}:{port} (timeout: {timeout})")

        try:
            with SELTelnet(dev.ip, port, timeout, **cls._ascii_options(dev)) as tn:
                if not cls._selascii_get_id(dev, tn):
                    return False

                if not cls._selascii_verify_post_process(dev, tn):
                    return False

                return True
        except Exception as ex:
            cls.log.trace(f"Telnet verify failed for {dev.ip} due to exception: {ex}")

        return False

    @classmethod
    def _selascii_get_id(cls, dev: DeviceData, comm: SELTelnet | SELSerial) -> bool:
        id_info = comm.get_id()

        if not id_info:
            cls.log.debug(f"{comm.type} verify failed for {comm.address}: no 'id' data")
            return False

        fid = id_info.get("FID")
        if not fid:
            cls.log.debug(
                f"{comm.type} verify failed for {comm.address}: "
                f"no FID in 'id' command output"
                f"\nRaw output: {id_info}"
            )
            return False

        # Process info from the "id" command, including the FID
        process_info_into_dev(id_info, dev)

        return True

    @classmethod
    def _selascii_verify_post_process(cls, dev: DeviceData, comm: SELTelnet | SELSerial) -> bool:
        # Close the connection cleanly
        try:
            comm.disconnect()
        except Exception as ex:
            cls.log.warning(f"Unclean disconnect during {comm.type} verify: {ex}")

        # Attempt to get RID, TID, and current time from
        # data the relay dumps when "quit" command is run
        # TODO: output is sometimes shown on login (also after certain commands)
        #   Make a generic parser
        #   Check if in output after login (do a read())
        #   Check if in output after exit
        exit_info = {}
        exit_output = comm.exit_output or (comm.all_output[-1] if comm.all_output else "")
        if "exit" in exit_output or "quit" in exit_output:
            try:
                exit_info.update(comm.parse_exit_info(exit_output))
            except Exception as ex:
                cls.log.error(f"Failed to parse {comm.type} exit info: {ex}")

        if exit_info:
            # list so it gets appended if multiple exits occur
            dev.write_file([exit_info], "raw-exit-info.json", merge_existing=True)

            # Set device name to the Relay ID or Terminal ID if present
            if not dev.name:
                for id_candidate in ["RID", "TID"]:
                    if exit_info.get(id_candidate):
                        dev.name = exit_info[id_candidate]
                        break

            process_info_into_dev(exit_info, dev)

        if not dev.name and dev.extra.get("iedName"):
            dev.name = dev.extra["iedName"]

        if dev.description.model:
            cls._check_model(dev.description.model, dev.ip)

        cls.log.info(
            f"Verified {comm.type} for {comm.address}!"
            f"\nModel: {dev.description.model}"
            f"\nName:  {dev.name}"
            f"\nFID:   {dev.firmware.id}"
        )

        return True

    @classmethod
    def _verify_http(cls, dev: DeviceData, protocol: Literal["http", "https"] = "http") -> bool:
        """
        Verify a device is a SEL Relay via the HTTP web interface.
        """
        port = dev.options[protocol]["port"]
        timeout = dev.options[protocol]["timeout"]

        cls.log.debug(
            f"Verifying Relay HTTP for {dev.ip}:{port} using {protocol} (timeout: {timeout})"
        )

        session = SELHTTP(dev.ip, port, timeout)
        logged_in = False

        if dev._cache.get("verified_web_user") and dev._cache.get("verified_web_pass"):
            logged_in = session.login(
                dev._cache["verified_web_user"],
                dev._cache["verified_web_pass"],
                protocol,
            )
        else:
            if dev.options["web"]["user"] and dev.options["web"]["pass"]:
                web = dev.options["web"]
                creds = [Credential(web["user"], web["pass"], "configured")]
            else:
                # Levels 1 and 2, with their configured or default passwords
                creds = web_candidates(cls._level_passwords(dev))

            for cred in creds:
                cls.log.debug(f"Attempting SEL Relay HTTP login to {dev.ip} with user {cred}")

                logged_in = session.login(cred.user, cred.password, protocol)

                if logged_in:
                    dev._cache["verified_web_user"] = cred.user
                    dev._cache["verified_web_pass"] = cred.password
                    dev.related.user.add(cred.user)
                    break

        if logged_in:
            # Pull info about device including the model number
            if not session.get_device_features(dev):
                cls.log.warning(
                    f"Failed to pull additional HTTP info from "
                    f"{dev.ip}:{port} after successful login"
                )

            if dev.description.model:
                cls._check_model(dev.description.model, dev.ip)

            # Cache the session using this protocol
            if not dev._cache.get("web_session"):
                dev._cache["web_session"] = session
                dev._cache["web_protocol"] = protocol
            else:
                session.disconnect()

            cls.log.info(f"HTTP verification successful for {dev.ip}:{port}")
            return True

        session.disconnect()
        cls.log.debug(f"Relay HTTP verification failed for {dev.ip}:{port}")

        return False

    @classmethod
    def _check_model(cls, model: str, dev_id: str) -> bool:
        """
        Emit a warning if the model is not supported by PEAT.
        Return false if not supported, return true if it is.
        """
        if model.lower() not in cls.supported_models:
            cls.log.warning(
                f"{dev_id} is a SEL device, however the model '{model}' is not "
                f"familiar to PEAT and has not been tested, so your mileage "
                f"may vary. Please report this signature to the PEAT team! "
                f"(peat@sandia.gov)"
            )
            return False
        return True

    @classmethod
    def pull_configs(cls, dev: DeviceData, comms: FTP | SELTelnet | SELSerial) -> bool:
        if getattr(comms, "halted", ""):
            cls.log.error(f"Not downloading files from {dev.address}: {comms.halted}")
            return False

        all_files = pull_files(dev, comms)

        if not all_files:
            return False

        # All of the files, including ones with the same name in different directories
        all_files_by_path = dev._cache.get("all_files_by_path") or all_files

        successful = True

        # Parse CFG.TXT, if it's present
        if (
            all_files.get("CFG.TXT")
            and all_files["CFG.TXT"]["data"].strip()
            and all_files["CFG.TXT"]["data"].strip() != "=>"
        ):
            try:
                cfg_configs = parse_cfg_txt(all_files["CFG.TXT"]["data"], dev)
            except Exception as ex:
                cls.log.warning(f"Failed to parse CFG.TXT pulled from {dev.address}: {ex}")
                successful = False
            else:
                # Add the settings class checksums to the settings files
                annotate_settings_classes(
                    cfg_configs.get("CLASSES"),
                    [info["file"] for info in all_files_by_path.values() if info.get("file")],
                )

        # Some relays don't have SET_ALL.TXT (or it failed to download),
        # reconstruct it from the individual settings files (SET_*.TXT).
        if not (all_files.get("SET_ALL.TXT") and all_files["SET_ALL.TXT"]["data"].strip()):
            settings_files = {
                name: info["data"]
                for name, info in all_files.items()
                if info.get("data")
                and (name.upper() == "CFG.TXT" or SETTINGS_FILENAME_RE.match(name))
            }
            combined = combine_settings_files(settings_files)

            if has_settings_sections(combined):
                cls.log.info(
                    f"SET_ALL.TXT wasn't pulled from {dev.address}, using settings "
                    f"combined from the individual settings files (SET_*.TXT)"
                )
                cls._write_combined_set_all(dev, combined, list(settings_files))
                all_files["SET_ALL.TXT"] = {
                    "name": "SET_ALL.TXT",
                    "data": combined,
                    "device_path": None,
                    "local_path": None,
                }

        if all_files.get("SET_ALL.TXT") and all_files["SET_ALL.TXT"]["data"].strip():
            set_all = all_files["SET_ALL.TXT"]

            # Path on the device (PurePosixPath)
            if set_all["device_path"]:
                dev.logic.file.path = set_all["device_path"]

            # Path locally where PEAT is running (Path)
            if set_all["local_path"]:
                dev.logic.file.local_path = set_all["local_path"]

            # Populate the "file" fields with the downloaded file
            dev.populate_fields()

            parse_res = cls.parse_config(set_all["data"], dev)
            if not parse_res:
                cls.log.error(f"Failed to parse SET_ALL.TXT pulled from {dev.address}")
                successful = False

            cls.update_dev(dev)  # Populate any fields that are unset
        else:
            cls.log.warning(
                f"SET_ALL.TXT was not pulled from {dev.address} and so logic "
                f"parsing was skipped. The file may not exist on this device model."
            )

        # Parse the events after the settings, so the date format (DATE_F) is known.
        # NOTE: on SEL-400 series relays, reading SER.TXT with FILE READ (YMODEM)
        # does a "SER CV" (clears the SER records viewed from that port), so a
        # later read of SER.TXT or CSER.TXT from the same port has no new records.
        cls._parse_event_files(
            dev, {name.upper(): info["data"] for name, info in all_files.items()}
        )
        cls._apply_uptime(dev, live=True)

        for filename, file_info in all_files.items():
            if filename.upper().endswith(".CID") and file_info["data"]:
                process_cid_file(
                    data=file_info["data"], filepath=file_info["device_path"], dev=dev
                )

        return successful

    @classmethod
    def _parse_event_files(
        cls, dev: DeviceData, files: dict[str, bytes | str | Path]
    ) -> dict[str, list[dict]]:
        """
        Parse the event files from a relay (:data:`EVENT_FILES`): ``SER.TXT``,
        falling back to ``CSER.TXT``, and ``HISTORY.TXT``, falling back to
        ``CHISTORY.TXT``. This is used by pulls and when parsing files.

        Args:
            dev: Device to add the events to
            files: Data (or the path to a file) of the files, keyed by
                their uppercase name. Other files are ignored.

        Returns:
            The events that were parsed, keyed by ``ser`` and ``history``
        """
        results = {}

        for kind, names in EVENT_FILES:
            results[kind] = []
            for name in names:
                if results[kind] or not files.get(name):
                    continue

                data = files[name]
                if isinstance(data, Path):
                    data = data.read_bytes()

                if not event_data_present(data):
                    cls.log.debug(f"No events in {name} from {dev.get_id()}")
                    continue

                try:
                    results[kind] = parse_and_process_events(data, name, dev)[0]
                except Exception:
                    cls.log.exception(f"Failed to parse {name} from {dev.get_id()}")

        return results

    @classmethod
    def _apply_uptime(cls, dev: DeviceData, live: bool) -> None:
        """
        Calculate the uptime of the relay from its SER events
        (refer to :func:`~peat.modules.sel.relay_parse.apply_uptime`).

        The relay's current time is the time in the header of the SER report,
        since it's from the same clock as the SER records and the SER was just
        read, or if there wasn't a header, ``device_time`` (e.g. from the
        information the relay sends when logging out, or the ``date`` and
        ``time`` commands).

        Args:
            dev: The device
            live: If the events were pulled from the relay (instead of parsed
                from files), so the relay's current time
                can be used to calculate the uptime
        """
        device_now = None
        if live:
            device_now = dev._cache.get(SER_DEVICE_TIME_KEY) or dev.extra.get("device_time")

        try:
            apply_uptime(dev, device_now=device_now)
        except Exception as ex:
            cls.log.warning(f"Failed to calculate the uptime of {dev.get_id()}: {ex}")

    @classmethod
    def _write_combined_set_all(cls, dev: DeviceData, combined: str, names: list[str]) -> None:
        """
        Save and record the ``SET_ALL.TXT`` that PEAT reconstructed
        from ``CFG.TXT`` and the individual settings files.
        """
        write_and_record_file(
            dev=dev,
            data=combined,
            filename="combined_SET_ALL.txt",
            source=SOURCE_DERIVED,
            peat_module=cls.__name__,
            description=(
                "SET_ALL.TXT reconstructed by PEAT from CFG.TXT and the "
                "individual settings files (not a file on the relay)"
            ),
            extra={"derived_from": sorted(n for n in names if n.upper() != "SET_ALL.TXT")},
        )

    @classmethod
    def _record_parse_input(cls, dev: DeviceData, path: Path, data: bytes | None = None) -> None:
        """
        Hash and record a file that's being parsed (e.g. by ``peat parse``).
        """
        try:
            record_downloaded_file(
                dev=dev,
                data=path.read_bytes() if data is None else data,
                name=path.name,
                local_path=path,
                source=SOURCE_PARSE_INPUT,
                peat_module=cls.__name__,
                description="File parsed by PEAT",
            )
        except Exception as ex:
            cls.log.warning(f"Failed to record parsed file {path}: {ex}")

    @classmethod
    def pull_more_commands(cls, dev: DeviceData, comms: SELTelnet | SELSerial) -> bool:
        """
        Run more read-only SEL ASCII commands (``sel.attempt_more_commands``),
        and parse their output into the data model.

        The commands, and the order they're run in (the same for Telnet and
        serial), are in :mod:`peat.modules.sel.sel_more_commands`, and every
        command is checked by :mod:`peat.modules.sel.sel_commands`, so nothing
        that changes the state of the relay is sent. The output of each command
        is saved and hashed (``ascii_commands/<name>.txt``), and all results are
        saved in ``additional-command-outputs.json``, as before. Results that
        weren't parsed are in ``extra.additional_command_outputs``.

        Returns:
            If any of the commands were successful (:obj:`False` if the session
            halted, refer to :attr:`~peat.modules.sel.sel_ascii.SELAscii.halted`)
        """
        cls._prepare_ascii(dev, comms)
        if dev.firmware.id and not comms.fid:
            comms.fid = dev.firmware.id

        comms.elevate(1, cls._configured_ascii_creds(dev))
        if comms.halted:
            cls.log.error(f"Not running SEL terminal commands on {dev.address}: {comms.halted}")
            return False

        collector = MoreCommands(
            dev,
            comms,
            creds=cls._configured_ascii_creds(dev),
            show_settings=dev.options["sel"]["show_settings"],
        )
        cls.log.info(f"Attempting to run SEL terminal commands on {dev.address}")
        results = collector.run()

        if not results:
            cls.log.error(f"No commands were successful on {dev.address}")
            return False

        successful = [name for name, entry in results.items() if "error" not in entry]
        cls.log.info(
            f"{len(successful)} commands successful on {dev.address} "
            f"(total attempted: {collector.attempted})"
        )

        transport = "telnet" if isinstance(comms, SELTelnet) else "serial"

        # Dump all of the commands to disk for debugging or investigation
        write_and_record_file(
            dev=dev,
            data=results,
            filename="additional-command-outputs.json",
            transport=transport,
            source=SOURCE_COMMAND_OUTPUT,
            peat_module=cls.__name__,
            description="Output of the SEL ASCII commands run by PEAT",
        )
        save_command_outputs(collector, transport=transport, peat_module=cls.__name__)

        # Parse the results
        try:
            unparsed = process_outputs(collector)
        except Exception:
            cls.log.exception(f"Unexpected error processing command results from {dev.address}")
            dev.extra["additional_command_outputs"] = results
            return False

        # NOTE: on SEL-400 series relays, PEAT asks for the 1000 newest SER
        # records ("SER 1000"), or uses CSE, since "SER" without arguments
        # only returns the 20 newest records.
        cls._apply_uptime(dev, live=True)

        # Only add to Extra what wasn't parsed or used
        if unparsed:
            dev.extra["additional_command_outputs"] = unparsed

        if comms.halted:
            return False

        return bool(successful)

    @classmethod
    def _use_show_settings(cls, dev: DeviceData) -> None:
        """
        If no settings file (e.g. ``SET_ALL.TXT``) was pulled from the relay, parse
        the settings from the ``SHO`` commands (``sel.attempt_more_commands``),
        e.g. from a relay without FTP or ``FILE SHOW``.
        """
        show_text = dev._cache.pop(SHOW_SETTINGS_CACHE_KEY, "")
        if not show_text or dev.logic.original:
            return

        cls.log.info(
            f"No settings file was pulled from {dev.address}, using the "
            f"settings from the SHO commands"
        )
        if cls.parse_config(show_text, dev):
            dev.extra["settings_source"] = "sho_commands"
            cls.update_dev(dev)

    @classmethod
    def pull_telnet(cls, dev: DeviceData, pull_files: bool = True) -> bool:
        """
        Pull and parse configuration file(s) from the relay via Telnet.
        """
        with SELTelnet(
            ip=dev.ip,
            port=dev.options["telnet"]["port"],
            timeout=dev.options["telnet"]["timeout"],
            **cls._ascii_options(dev),
        ) as tn:
            if not tn.test_connection():
                cls.log.error(f"Failed Telnet pull from {dev.ip}: failed to connect")
                return False

            cls._prepare_ascii(dev, tn)
            if not tn.elevate(1, cls._configured_ascii_creds(dev)):
                cls.log.error(f"Failed Telnet pull from {dev.ip}: login failed")
                return False

            dev.related.user.update(tn.successful_usernames)
            successful = True

            # Get more info via terminal commands (get_sta, show_eth, show_status, etc.)
            if dev.options["sel"]["attempt_more_commands"]:
                # At least one command should succeed
                if not cls.pull_more_commands(dev=dev, comms=tn):
                    cls.log.error("Failed to pull more Telnet commands")
                    successful = False

            if pull_files:
                if not cls.pull_configs(dev, tn):
                    cls.log.warning(f"There were issues downloading files via Telnet for {dev.ip}")
                    successful = False
            else:
                cls.log.debug(f"Skipping file pull via Telnet for {dev.ip}")

            cls._use_show_settings(dev)
            return successful

    @classmethod
    def pull_serial(cls, dev: DeviceData) -> bool:
        """
        Pull and parse configuration file(s) from the relay via serial.
        """
        # TODO: cache the serial object between verify and pull,
        #   to avoid closing and reopening connection for no reason
        if not dev.options["serial"]["baudrate"]:
            if not cls._verify_serial(dev):
                cls.log.error(
                    f"Failed pull from {dev.serial_port}: _verify_serial() failed "
                    f"(verify was run because no baudrate was specified for the "
                    f"device in the PEAT YAML configuration file)"
                )
                return False

        with SELSerial(
            serial_port=dev.serial_port,
            baudrate=dev.options["serial"]["baudrate"],
            timeout=dev.options["timeout"],
            force_ymodem=dev.options["sel"]["force_ymodem"],
            **cls._ascii_options(dev),
        ) as ser:
            if not ser.test_connection():
                cls.log.error(f"Failed pull from {dev.serial_port}: connection failed")
                return False

            cls._prepare_ascii(dev, ser)
            if not ser.elevate(1, cls._configured_ascii_creds(dev)):
                cls.log.error(f"Failed pull from {dev.serial_port}: login failed")
                return False

            dev.related.user.update(ser.successful_usernames)

            if dev.options["sel"]["force_ymodem"]:
                # YMODEM only works on Linux or OSX (or any system with rz/sz commands)
                if consts.WINDOWS:
                    raise DeviceError(
                        f"YMODEM pulls do not work on Windows "
                        f"(sel.force_ymodem was configured for {dev.serial_port})"
                    )
                cls.log.warning(f"Forcing use of YMODEM for serial pull from {dev.serial_port}")

            successful = True

            # Get more info via terminal commands (get_sta, show_eth, show_status, etc.).
            # The commands are run before the files are downloaded, as with Telnet:
            # on SEL-400 series relays, reading SER.TXT with FILE READ clears the
            # SER records viewed from this port ("SER CV").
            if dev.options["sel"]["attempt_more_commands"]:
                # At least one command should succeed
                if not cls.pull_more_commands(dev=dev, comms=ser):
                    cls.log.error("Failed to pull more serial commands")
                    successful = False

            if not cls.pull_configs(dev, ser):
                cls.log.warning(
                    f"There were issues downloading files via Serial for {dev.serial_port}"
                )
                successful = False

            cls._use_show_settings(dev)
            return successful

    @classmethod
    def pull_ftp(cls, dev: DeviceData) -> bool:
        """
        Pull and parse configuration file(s) from the relay via FTP.
        """
        if not cls._setup_ftp(dev):
            cls.log.error(f"FTP pull failed for {dev.ip}: failed setup")
            return False

        try:
            with FTP(
                ip=dev.ip,
                port=dev.options["ftp"]["port"],
                timeout=dev.options["ftp"]["timeout"],
            ) as ftp:
                username = dev.options["ftp"]["user"]
                if not ftp.login(username, dev.options["ftp"]["pass"]):
                    cls.log.error(
                        f"Failed to pull config from {dev.ip}: FTP login "
                        f"failed (user: '{username}')"
                    )
                    return False

                dev.related.user.add(username)

                delay = dev.options["ftp"]["pull_delay"]
                cls.log.info(
                    f"FTP logged in to {dev.ip} as '{username}', sleeping for "
                    f"{delay} seconds before running 'getwelcome()'..."
                )
                time.sleep(delay)

                if not ftp.getwelcome():
                    cls.log.error(
                        f"Failed to pull FTP from {dev.ip}: "
                        f"'getwelcome' failed after login succeeded"
                    )
                    return False

                # Download files
                if not cls.pull_configs(dev, ftp):
                    cls.log.error(f"Failed to pull FTP from {dev.ip}: no files were downloaded")
                    return False

                return True
        except CommError as ex:
            cls.log.warning(f"Failed FTP pull from {dev.ip}: connection failed")
            cls.log.trace(f"Exception: {ex}")
        except Exception as ex:
            cls.log.warning(f"Failed FTP pull from {dev.ip} due to an unhandled exception: {ex}")

        return False

    @classmethod
    def pull_http(cls, dev: DeviceData, protocol: Literal["http", "https"] = "http") -> bool:
        """
        Pull configuration and other data from the relay via HTTP.
        """
        port = dev.options[protocol]["port"]
        timeout = dev.options[protocol]["timeout"]

        cls.log.info(f"Pulling data via HTTP from {dev.ip}:{port} (timeout: {timeout})")

        if not dev._cache.get("web_session"):
            cls.log.debug(
                f"No web session cached in pull_http() for "
                f"{dev.ip}:{port}, creating new session..."
            )
            dev._cache["web_session"] = SELHTTP(dev.ip, port, timeout)
            dev._cache["web_protocol"] = protocol
        else:
            cls.log.debug(f"Using existing web session for {dev.ip}:{port}")

        session = dev._cache["web_session"]

        if not session.relay_logged_in:
            cls.log.debug(f"Session not logged in, logging in to {dev.ip}:{port}")

            username = dev._cache.get("verified_web_user")
            if not username:
                username = dev.options["web"]["user"]

            password = dev._cache.get("verified_web_pass")
            if not password:
                password = dev.options["web"]["pass"]

            if not username or not password:
                # The level 1 user and its configured or default password
                default = web_candidates(cls._level_passwords(dev))[0]
                username = username or default.user.upper()
                password = password or default.password

            if not session.login(username, password, protocol):
                cls.log.error(
                    f"Failed to login to web interface on {dev.ip}:{port} with user '{username}'"
                )

                session.disconnect()
                if dev._cache.get("web_session"):
                    del dev._cache["web_session"]
                if dev._cache.get("web_protocol"):
                    del dev._cache["web_protocol"]

                return False

            dev.related.user.add(username)
            dev._cache["verified_web_user"] = username
            dev._cache["verified_web_pass"] = password

        web_methods = [
            session.get_status,
            session.get_communications,
            session.get_port_settings,
            session.get_front_panel_settings,
            session.get_sequential_events,
            session.get_historical_events,
            session.get_meter_automation,
            session.get_meter_protection,
            session.get_meter_energy,
            session.get_output_data,
        ]

        # This gets called during verify, no reason to call it again.
        # However, if it HASN'T been called yet, then it needs to be
        # called BEFORE the other methods. Thus, insert(0).
        if not dev._is_verified:
            web_methods.insert(0, session.get_device_features)

        cls.log.info(
            f"Beginning web pull from {dev.ip}:{port} using {len(web_methods)} web methods"
        )

        # Note the number of successful methods somewhere
        dev._cache["num_successful_methods"] = 0
        was_successful = True

        for method in web_methods:
            time.sleep(0.2)  # attempt to avoid overloading web server

            cls.log.info(f"Running '{method.__name__}' for {dev.ip}:{port}")
            try:
                method_result = method(dev)  # type: bool

                if not method_result:
                    cls.log.warning(
                        f"No data from HTTP method '{method.__name__}' on {dev.ip}:{port}"
                    )
                else:
                    dev._cache["num_successful_methods"] += 1
            except Exception:
                cls.log.exception(f"'{method.__name__}' failed on {dev.ip}:{port}")
                was_successful = False
                continue

        # Uptime from the SER page ("get_sequential_events")
        cls._apply_uptime(dev, live=True)

        cls.log.info(
            f"Finished pulling data via web interface from {dev.ip}:{port} "
            f"({dev._cache['num_successful_methods']} methods were "
            f"successful out of {len(web_methods)} methods attempted)"
        )

        return was_successful

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        """
        Pull and parse all configuration files and data from the SEL relay.
        """
        # Passwords that failed in an earlier pull are tried again
        cls._forget_ascii_passwords(dev)

        # If the user hasn't specified a protocol to use, there's a
        # serial port configured for the host, and the type of operation
        # is serial, then do a serial pull.
        if dev.options["sel"]["force_serial_pull"] or (
            dev.serial_port and state.comm_type == "serial"
        ):
            return cls.pull_serial(dev)

        if not dev.options["sel"]["pull_methods"]:
            cls.log.error(f"The 'sel.pull_methods' option is empty or null for {dev.ip}")
            return False

        for method in dev.options["sel"]["pull_methods"]:
            if method not in cls.default_options["sel"]["pull_methods"]:
                cls.log.error(
                    f"Invalid 'sel.pull_methods' method '{method}' for {dev.ip}, it must "
                    f"be one of {cls.default_options['sel']['pull_methods']}"
                )
                return False

        pull_results = {}  # type: dict[str, bool]
        files_pulled = False
        for method in dev.options["sel"]["pull_methods"]:
            if dev.service_status({"protocol": method}) == "closed":
                cls.log.warning(f"Failed to pull {method} on {dev.ip}: {method} port is closed")
                continue

            # TODO: handle case where dev._is_verified is False,
            # e.g. if pull() is called directly without a scan.

            if method == "telnet":
                pull_files = False

                if (
                    not files_pulled and dev.options["sel"]["allow_telnet_file_download"]
                ) or dev.options["sel"]["force_telnet_file_download"]:
                    pull_files = True

                pull_results[method] = cls.pull_telnet(dev, pull_files=pull_files)

                if pull_results[method] and pull_files:
                    files_pulled = True

            elif method == "ftp":
                pull_results[method] = cls.pull_ftp(dev)

                if pull_results[method]:
                    files_pulled = True

            else:
                web_protocol = None
                if dev._cache.get("web_protocol"):
                    web_protocol = dev._cache["web_protocol"]
                else:
                    for proto in ["http", "https"]:
                        s = dev.retrieve("service", {"protocol": proto})
                        if s and (s.enabled or s.status == "open"):
                            web_protocol = proto

                if web_protocol:
                    if not dev._cache.get("web_protocol"):
                        dev._cache["web_protocol"] = web_protocol
                    try:
                        # pull using the open protocol (http or https)
                        pull_results[method] = cls.pull_http(dev, web_protocol)
                    except Exception:
                        cls.log.exception(
                            f"Web pull via '{web_protocol}' of {dev.ip} "
                            f"failed due to unhandled exception"
                        )
                        pull_results[method] = False
                else:
                    cls.log.warning(
                        f"Failed to determine HTTP/HTTPS protocol for {dev.ip},"
                        f"falling back to plain 'http'."
                    )
                    pull_results[method] = cls.pull_http(dev, "http")

            if not pull_results[method]:
                cls.log.warning(f"{method} pull failed for {dev.ip}")
            else:
                cls.log.debug(f"{method} pull successful for {dev.ip}")

        return all(m for m in pull_results.values())

    @classmethod
    def _push(
        cls,
        dev: DeviceData,
        to_push: str | bytes | Path,
        push_type: consts.PushType,
    ) -> bool:
        """
        Reconfigure the SEL device by writing config files.

        .. warning::
           Modifying the port configuration (SET_P*) will kill any connections
           to that port. This can affect the port PEAT is using to push configs!

        .. note::
           Filenames must be capitalized, e.g. SET_ALL.TXT or SET_1.TXT

        Args:
            dev: Device to push to
            to_push: Path to relay configuration files to upload (SET_*.TXT)
            push_type: this should be 'config'

        Returns:
            If the push was successful
        """
        if push_type != "config":
            cls.log.critical(f"Unsupported push type {push_type}, expected 'config'")
            return False

        if not isinstance(to_push, Path):
            cls.log.error(
                f"Expected path for push, got type '{type(to_push)}'. "
                f"Ensure you specify a path to a config file or directory "
                f"with configs to upload, not raw data."
            )
            return False

        # Ensure we can connect via FTP
        # TODO: before pushing, read FTP user out of config
        #   just do: dev.lookup("service", {"protocol": "ftp"}).user
        if not cls._setup_ftp(dev):
            cls.log.error(f"FTP push failed for {dev.ip}: failed setup")
            return False

        # TODO: Ability to push using a SET_ALL to reconstruct files, e.g.
        #   peat push -d selrelay -i 192.0.2.123 -- SET_ALL.TXT
        # NOTE: I don't think we can push the actual SET_ALL.TXT,
        #   may return a permission denied error.

        # TODO: support pushing multiple configs at once, e.g.
        #   peat push -d selrelay -i 192.0.2.123 -- SET_1.TXT SET_6.TXT
        #   This will require modifying the push API and CLI args a bit
        #   to support multiple filenames as arguments.

        # TODO: rebuild connection on failures, e.g. timeout mid-push
        # TODO: if SET_P* file(s) have a different IP, they need to be
        #   done last, otherwise the subsequent configs will fail.
        #   sort config update order so SET_P* files are last, with
        #   ethernet ports at the end.
        # TODO: if SET_P in config name, then prepare ftp connection
        #  to reconnect/rebuild, and update the IP used to connect
        #  if it was changed. set a internal PEAT flag indicating
        #  a IP change occurred during the same run.
        # TODO: option to pull current configs and only push those whose hash changed

        # peat push -d selrelay -i 192.0.2.123 -- SET_1.TXT
        cls.log.info(f"Reading config(s) from {to_push}")

        if to_push.is_dir():
            config_files = sorted(to_push.glob("SET_*.TXT"))
            if "SET_ALL.TXT" in (x.name for x in config_files):
                cls.log.warning(f"Ignoring SET_ALL.TXT in config files for push to {dev.ip}.")
                config_files = [x for x in config_files if x.name != "SET_ALL.TXT"]
            if not config_files:
                cls.log.error(f"Push failed: couldn't find any configs in {to_push.as_posix()}")
                return False
            cls.log.debug(f"Using {len(config_files)} config files from dir {to_push}")
        elif to_push.is_file():
            # TODO: support pushing *.rdb files (just extract the set_all), e.g.
            #   peat push -d selrelay -i 192.0.2.123 -- sel_351.rdb
            # We'll need to implement splitting SET_ALL into separate config files
            # before implementing this.
            config_files = [to_push]
            cls.log.debug(f"Push: using config file {to_push.as_posix()}")
        else:
            cls.log.critical(f"Invalid file for push to {dev.ip}: {to_push}")
            return False

        cls.log.trace(f"config_files: {config_files}")

        try:
            with FTP(dev.ip, dev.options["ftp"]["port"], 120.0) as relay:
                if not relay.login(
                    user=dev.options["ftp"]["user"], passwd=dev.options["ftp"]["pass"]
                ):
                    cls.log.error(f"Failed to push config to {dev.ip}: FTP login failed")
                    return False

                delay = dev.options["ftp"]["pull_delay"]
                cls.log.debug(
                    f"FTP logged in to {dev.ip}, sleeping for {delay} "
                    f"seconds before running getwelcome()..."
                )
                time.sleep(delay)
                if not relay.getwelcome():
                    cls.log.error(
                        f"Failed to push config to {dev.ip}: "
                        f"getwelcome failed after login succeeded"
                    )
                    return False

                cls.log.debug(
                    f"Sleeping for {delay} seconds before pushing configs to {dev.ip}..."
                )
                time.sleep(delay)

                # Find where the configs are
                # According to the documentation, all 700-series relays
                # put their configs in the root directory. However, this
                # is not always the case, as we've seen a directory structure
                # on a 700G with the fancy front panel display.
                if not dev.extra.get("file_listing") or not dev.extra.get(
                    "settings_root_directory"
                ):
                    populate_file_listing(dev, relay)

                # Push only the files on the relay already and in
                # the order the relay displays them
                settings_root = dev.extra["settings_root_directory"]
                on_relay = [x.upper() for x in dev.extra["file_listing"][settings_root]]

                # Compare local file names with those on the device
                local_names = [x.name for x in config_files]
                local_not_on_relay = [x for x in local_names if x not in on_relay]
                if local_not_on_relay:
                    cls.log.warning(
                        f"{len(local_not_on_relay)} files being pushed are not "
                        f"currently present on the relay (they're new files). "
                        f"Ensure you are pushing the right files to the "
                        f"appropriate device! List of files: "
                        f"{local_not_on_relay}"
                    )

                on_relay_not_local = [x for x in on_relay if x not in local_names]
                if on_relay_not_local:
                    cls.log.debug(
                        f"{len(on_relay_not_local)} files exist on the relay, "
                        f"but are not present in the configs being pushed. This "
                        f"is expected if you're pushing a subset of configs "
                        f"(e.g. just SET_1.TXT). List of files: "
                        f"{on_relay_not_local}"
                    )

                # If the settings are in a "SETTINGS" directory, then change
                # directories before transferring configs ("cd SETTINGS")
                if settings_root == "SETTINGS":
                    cls.log.info("Changing directory to 'SETTINGS' before pushing configs")
                    relay.cd("/SETTINGS")

                file_delay = 2
                cls.log.info(
                    f"Preparing to transfer {len(config_files)} config "
                    f"files to {dev.ip}. This will take at least "
                    f"{file_delay * (len(config_files) + 1)} seconds."
                )
                transfer_start = timeit.default_timer()

                # Transfer all configs except communication port configs
                for conf_file in config_files:
                    if "SET_P" not in conf_file.name:
                        cls.log.info(
                            f"Transferring config '{conf_file.name}' ({conf_file.as_posix()})"
                        )
                        with conf_file.open("rb") as f:
                            relay.upload_text(conf_file.name, f)
                        cls.log.info(f"{conf_file.name} config sent")
                        cls.log.debug(f"Sleeping for {file_delay} seconds...")
                        time.sleep(file_delay)

                # Transfer configuration port configs
                for conf_file in config_files:
                    if "SET_P" in conf_file.name:
                        cls.log.info(
                            f"Transferring communication port config "
                            f"'{conf_file.name}' ({conf_file.as_posix()})"
                        )
                        with conf_file.open("rb") as f:
                            relay.upload_text(conf_file.name, f)
                        cls.log.info(f"{conf_file.name} communication port config sent")
                        cls.log.debug(f"Sleeping for {file_delay} seconds...")
                        time.sleep(file_delay)
                transfer_time = timeit.default_timer() - transfer_start
                cls.log.info(
                    f"Completed transfer of {len(config_files)} config "
                    f"files to {dev.ip} in {utils.fmt_duration(transfer_time)}"
                )
                # Prevent disconnection errors from skipping restart
                try:
                    relay.disconnect()
                except Exception:
                    pass

            cls.log.info(f"Completed configuration of relay {dev.ip} via FTP")

            # Reboot the device if 'sel.restart_after_push' is true
            if dev.options["sel"]["restart_after_push"]:
                pre_delay = 5
                cls.log.info(f"Waiting {pre_delay} seconds before restarting {dev.ip}")
                time.sleep(pre_delay)
                restarted = cls.restart_relay(dev, comm_type="telnet")
                if not restarted:
                    cls.log.error(
                        f"The configs were pushed to {dev.ip}, but the restart failed "
                        f"or wasn't verified (details are in 'restart' in the device's "
                        f"extra data)"
                    )
                return restarted
            else:
                cls.log.info(
                    "Note: the relay was NOT restarted, as most config changes "
                    "don't require a reboot to take effect. If you need to restart "
                    "the relay, re-run the push with 'sel.restart_after_push' set to true."
                )
                return True
        except CommError as ex:
            cls.log.debug(f"Failed to push config to {dev.ip}: connection failed")
            cls.log.trace(f"Exception: {ex}")
            return False
        except Exception as ex:
            cls.log.warning(
                f"Failed to push config to {dev.ip} due to an unhandled exception: {ex}"
            )
            return False

    @classmethod
    def _setup_ftp(cls, dev: DeviceData) -> bool:
        cls.log.trace2(f"_setup_ftp() for {dev.ip}")

        if dev.options["ftp"].get("user") and dev.options["ftp"].get("pass"):
            return True

        port = dev.options["ftp"]["port"]
        if not dev.retrieve("service", {"port": port}):
            if not check_tcp_port(dev.ip, port, reset=True):
                cls.log.error(f"Failed FTP setup: TCP port {port} is not open on {dev.ip}")
                return False
            else:
                svc = Service(port=port, transport="tcp", status="open")
                dev.store("service", svc, lookup="port")

        # Credentials in the configuration (ftp.creds) are used as they are.
        # Otherwise, the defaults for the model are tried (sel_default_creds.py).
        configured = configured_option(dev, "ftp", "creds")
        if configured:
            cls.log.trace(f"FTP creds for {dev.ip} are: USER PROVIDED")
            candidates = [Credential(str(c[0]), str(c[1]), "configured") for c in configured]
            if len(candidates) > MAX_DEFAULT_FTP_ATTEMPTS:
                cls.log.warning(
                    f"{len(candidates)} FTP credentials are configured for {dev.ip}. "
                    f"Many relays lock out FTP after 5 failed logins."
                )
        else:
            cls.log.trace(f"FTP creds for {dev.ip} are: INFORMED DEFAULTS")
            candidates = cls._default_ftp_candidates(dev)

        timeout = dev.options["ftp"]["timeout"]
        delay = dev.options["ftp"]["pull_delay"]
        attempts = 0

        for cred in candidates:
            attempts += 1
            cls.log.debug(f"Attempting FTP login to {dev.ip} with user {cred}")
            try:
                with FTP(dev.ip, port, timeout) as relay:
                    if not relay.login(cred.user, cred.password):
                        cls.log.trace(f"FTP login with user {cred} failed for {dev.ip}")
                        continue

                    cls.log.trace(
                        f"FTP logged in to {dev.ip}, sleeping for {delay} "
                        f"seconds before running getwelcome()..."
                    )

                    time.sleep(delay)

                    if not relay.getwelcome():
                        cls.log.warning(
                            f"FTP setup failed for {dev.ip}: "
                            f"getwelcome failed after login succeeded"
                        )
                        return False

                    cls.log.debug(f"FTP login succeeded on {dev.ip} after {attempts} attempt(s)")

                    if not dev._runtime_options.get("ftp"):
                        dev._runtime_options["ftp"] = {}
                    dev._runtime_options["ftp"]["user"] = cred.user
                    dev._runtime_options["ftp"]["pass"] = cred.password

                    dev.related.user.add(cred.user)

                    ftp_svc = Service(
                        protocol="ftp", port=port, status="verified", transport="tcp"
                    )

                    dev.store("service", ftp_svc, lookup=["protocol", "port"])

                    return True
            except CommError as ex:
                cls.log.debug(f"FTP setup failed for {dev.ip}: connection failed")
                cls.log.trace(f"Exception: {ex}")
                return False
            except Exception as ex:
                cls.log.warning(
                    f"FTP verification failed for {dev.ip} due to an unhandled exception: {ex}"
                )
                return False

        cls.log.debug(
            f"FTP setup failed for {dev.ip}: no credentials were valid ({attempts} attempts)"
        )

        return False

    @classmethod
    def _default_ftp_candidates(cls, dev: DeviceData) -> list[Credential]:
        """
        Default FTP logins for the relay, using its model, the access level
        passwords, and the FTP settings parsed before (``FTPUSER``, ``FTPANMS``).
        Refer to :func:`~peat.modules.sel.sel_default_creds.ftp_candidates`.
        """
        ftp_user = None
        anonymous = False

        services = dev.retrieve("service", {"protocol": "ftp"})
        if services and not isinstance(services, list):
            services = [services]
        for svc in services or []:
            if svc.extra.get("user") and not ftp_user:
                ftp_user = str(svc.extra["user"])
            if svc.extra.get("anonymous_login_enabled"):
                anonymous = True

        return ftp_candidates(
            dev.description.model,
            cls._level_passwords(dev),
            ftp_user=ftp_user,
            anonymous_enabled=anonymous,
        )

    @classmethod
    def _parse(cls, file: Path, dev: DeviceData | None = None) -> DeviceData | None:
        # "file" can be one of the following:
        # - a SET_ALL.TXT file or an individual settings file (SET_1.TXT, SET_P5.TXT, etc.)
        # - a *.rdb SEL QuickSet database file, with the settings for one or more relays
        # - output of the SHOW (SHO) command saved from a terminal session
        # - a directory of relay files, e.g. the "relay_files" directory from a PEAT pull
        # - CFG.TXT, SER.TXT, CSER.TXT, HISTORY.TXT, CHISTORY.TXT, *.CID
        #
        # Examples are in tests/modules/sel/data_files/relay/
        if file.is_dir():
            return cls._parse_dir(file, dev)

        raw_data = file.read_bytes()

        # NOTE: isOleFile will interpret the argument as a filename string
        # if the length of the data is smaller than 1536 bytes. To avoid this,
        # we always pass it a file pointer.
        with file.open("rb") as fp:
            is_rdb = olefile.isOleFile(fp)

        # *.rdb SEL project files use a file structure called
        # Compound File Binary (CFB) Format or Microsoft OLE2 File.
        # isOleFile() checks the file for the magic number at the
        # start of the header to determine if it is the correct format.
        if is_rdb:
            cls.log.debug("Input data is in CFB format, parsing as a RDB project")
            return cls._parse_rdb(file, raw_data, dev)

        f_name = file.name.upper()

        # CFG.TXT, SER.TXT, CSER.TXT, HISTORY.TXT, CHISTORY.TXT, *.CID
        if f_name.endswith(".CID") or f_name.endswith("CFG.TXT") or is_event_filename(f_name):
            if not dev:
                dev = datastore.get(f"selrelay_{file.stem.lower()}", "id")

            if f_name.endswith(".CID"):
                cid_extracted = process_cid_file(raw_data, file, dev)

                if not cid_extracted:
                    return None
            elif f_name.endswith("CFG.TXT"):
                parse_cfg_txt(raw_data, dev)
            else:
                if not event_data_present(raw_data):
                    cls.log.warning(f"No event data in {file.name}")
                    cls._record_parse_input(dev, file, raw_data)
                    return dev

                events, info = parse_and_process_events(raw_data, file.name, dev)

                if not events and not info:
                    return None

                cls._apply_uptime(dev, live=False)

            cls._record_parse_input(dev, file, raw_data)

            cls.update_dev(dev)  # Populate any fields that are unset

            return dev

        text = clean_settings_text(raw_data)
        if not has_settings_sections(text) and not looks_like_show_output(text):
            cls.log.warning(f"{file.name} doesn't look like a SEL relay settings file")
            return None

        cls.log.debug("Input data is text, parsing as a settings file")
        dev = cls.parse_config(set_all=text, dev=dev)

        if not dev:
            return None

        cls._record_parse_input(dev, file, raw_data)
        dev.logic.file.local_path = file

        cls.update_dev(dev)  # Populate any fields that are unset

        return dev

    @classmethod
    def _export_extra_dev(cls, dev: DeviceData) -> None:
        """
        Export a device that was parsed in addition to the device returned
        by ``_parse()``, e.g. the other relays in a RDB file.
        :meth:`~peat.device.DeviceModule.parse` only exports the device returned.
        """
        dev.purge_duplicates(force=True)

        if config.DEVICE_DIR:
            dev.export_to_files()

        if state.elastic:
            dev.export_to_elastic()

    @classmethod
    def _parse_rdb(cls, file: Path, raw_data: bytes, dev: DeviceData | None) -> DeviceData | None:
        """
        Parse the settings for the relays in a SEL QuickSet database (``*.rdb``).

        A RDB file can have settings for multiple relays. The device for the
        first relay is returned, and the other relays are parsed into their
        own devices, which are added to the datastore and exported.
        """
        relays = parse_rdb_relays(raw_data)

        if len(relays) > 1:
            cls.log.info(f"{len(relays)} relays in {file.name}: {', '.join(relays)}")

        # The streams for each relay, to hash them
        try:
            rdb_streams = read_rdb_streams(raw_data)
        except Exception as ex:
            cls.log.warning(f"Failed to read the streams in {file.name} to hash them: {ex}")
            rdb_streams = {}

        parsed_devs = []  # type: list[DeviceData]

        for relay_name, set_all in relays.items():
            relay_dev = dev if not parsed_devs else None

            if parsed_devs:
                # Relays in templates often have the same IP address or
                # name, so they'd end up as the same device. Use the name
                # of the relay in the RDB file to keep them separate.
                relay_dev = create_dev_from_configs(parse_config_data(set_all))
                if any(relay_dev is d for d in parsed_devs):
                    cls.log.warning(
                        f"Relay '{relay_name}' in {file.name} has the same identifier "
                        f"as another relay in the file ({relay_dev.get_id()}), using "
                        f"'{file.stem}_{relay_name}' as its identifier instead"
                    )
                    relay_dev = datastore.get(f"{file.stem}_{relay_name}", "id")

            relay_dev = cls.parse_config(set_all=set_all, dev=relay_dev)

            if not relay_dev:
                # Save the extracted SET_ALL data from the rdb to a temporary file
                # This is helpful if debugging an issue with parsing of rdb files
                temp_path = utils.write_temp_file(set_all, "extracted_SET_ALL.txt")
                cls.log.error(
                    f"Failed to parse settings for relay '{relay_name}' in {file.name}. "
                    f"The extracted settings were saved to {temp_path}"
                )
                continue

            if relay_name:
                relay_dev.extra["rdb_relay_name"] = relay_name

            cls._record_rdb_files(relay_dev, file, raw_data, relay_name, set_all, rdb_streams)
            relay_dev.write_file(raw_data, "raw-rdb-config.rdb")
            relay_dev.logic.file.local_path = file

            cls.update_dev(relay_dev)  # Populate any fields that are unset

            if parsed_devs:
                cls._export_extra_dev(relay_dev)

            parsed_devs.append(relay_dev)

        return parsed_devs[0] if parsed_devs else None

    @classmethod
    def _record_rdb_files(
        cls,
        dev: DeviceData,
        file: Path,
        raw_data: bytes,
        relay_name: str,
        set_all: str,
        rdb_streams: dict[str, dict[str, bytes]],
    ) -> None:
        """
        Hash and record the RDB file, the streams for the relay in it,
        and the ``SET_ALL`` extracted from the streams.
        """
        cls._record_parse_input(dev, file, raw_data)

        rdb_extra = {"derived_from": [file.name]}
        if relay_name:
            rdb_extra["rdb_relay_name"] = relay_name

        # Streams that aren't in a relay's storage are keyed by an empty relay name,
        # which is also the "relay name" used for RDBs without the usual layout.
        for stream_path, stream_data in rdb_streams.get(relay_name, {}).items():
            # Path of the stream in the RDB, e.g. "Relays/<relay name>/Misc/Cfg.txt"
            rdb_path = f"Relays/{relay_name}/{stream_path}" if relay_name else stream_path

            record_downloaded_file(
                dev=dev,
                data=stream_data,
                name=rdb_path.rsplit("/", maxsplit=1)[-1],
                device_path=rdb_path,
                source=SOURCE_RDB_STREAM,
                peat_module=cls.__name__,
                description=f"Stream in {file.name}",
                extra={"rdb_stream": stream_path, **rdb_extra},
            )

        write_and_record_file(
            dev=dev,
            data=set_all,
            filename="extracted_SET_ALL.txt",
            source=SOURCE_DERIVED,
            peat_module=cls.__name__,
            description=(
                f"SET_ALL.TXT reconstructed by PEAT from the settings in {file.name} "
                f"(not a file on the relay)"
            ),
            extra=rdb_extra,
        )

    @classmethod
    def _parse_dir(cls, directory: Path, dev: DeviceData | None = None) -> DeviceData | None:
        """
        Parse a directory of files from relays, such as the ``relay_files``
        directory from a PEAT pull, files downloaded from a relay using FTP,
        or the settings files extracted from a QuickSet RDB file.

        Files with the names used on relays (``SET_ALL.TXT``, ``CFG.TXT``,
        ``SET_*.TXT``, ``SER.TXT``, etc.) are grouped by the directory they're
        in, and each group is parsed as one relay. Files in a ``SETTINGS``
        (or other known relay directory) sub-directory belong to the parent
        directory's relay. Other files that match the module's filename
        patterns (e.g. ``*.rdb`` or ``relay1_SET_ALL.TXT``) are parsed by themselves.

        The device for the first relay is returned, and the other devices
        are exported.
        """
        groups = {}  # type: dict[Path, dict[str, Path]]
        others = []  # type: list[Path]

        for path in sorted(directory.rglob("*")):
            if not path.is_file():
                continue

            # Filenames are case-insensitive, e.g. "set_1.txt" from a RDB
            name = path.name.upper()

            is_relay_file = name in RELAY_FILENAMES or SETTINGS_FILENAME_RE.match(name)

            if is_relay_file or name.endswith(".CID"):
                root = path.parent
                if root != directory and root.name.upper() in RELAY_DIRNAMES:
                    root = root.parent

                group = groups.setdefault(root, {})
                if name in group:
                    cls.log.warning(f"Skipping {path}, {group[name]} was already found")
                else:
                    group[name] = path
            elif any(fnmatchcase(name, pat.upper()) for pat in cls.filename_patterns):
                others.append(path)

        cls.log.debug(
            f"Parsing directory {directory} ({len(groups)} relays, {len(others)} other files)"
        )

        parsed_devs = []  # type: list[DeviceData]

        for root, files in groups.items():
            relay_dev = cls._parse_relay_files(root, files, dev if not parsed_devs else None)
            if relay_dev and not any(relay_dev is d for d in parsed_devs):
                parsed_devs.append(relay_dev)

        for path in others:
            other_dev = cls._parse(path, dev if not parsed_devs else None)
            if other_dev and not any(other_dev is d for d in parsed_devs):
                parsed_devs.append(other_dev)

        if not parsed_devs:
            cls.log.error(f"No SEL relay files found in {directory}")
            return None

        for extra_dev in parsed_devs[1:]:
            cls._export_extra_dev(extra_dev)

        return parsed_devs[0]

    @classmethod
    def _parse_relay_files(
        cls, root: Path, files: dict[str, Path], dev: DeviceData | None = None
    ) -> DeviceData | None:
        """
        Parse files from a single relay, keyed by their uppercase filename.

        If there isn't a ``SET_ALL.TXT`` (or it's empty), it's reconstructed
        from ``CFG.TXT`` and the individual settings files (``SET_*.TXT``).
        Event files (``SER.TXT``, etc.) and ``*.CID`` files are parsed into
        the same device.
        """
        set_all_path = files.get("SET_ALL.TXT")
        set_all = clean_settings_text(set_all_path.read_bytes()) if set_all_path else ""

        if not has_settings_sections(set_all):
            if set_all_path:
                cls.log.warning(f"No settings in {set_all_path}, using the SET_*.TXT files")
                set_all_path = None

            set_all = combine_settings_files(
                {
                    name: path.read_bytes()
                    for name, path in files.items()
                    if name == "CFG.TXT" or SETTINGS_FILENAME_RE.match(name)
                }
            )

        has_settings = has_settings_sections(set_all)

        if has_settings:
            dev = cls.parse_config(set_all=set_all, dev=dev)
            if not dev:
                return None
            dev.logic.file.local_path = set_all_path if set_all_path else root
        elif not dev:
            dev = datastore.get(f"selrelay_{root.name.lower()}", "id")

        # Parse CFG.TXT separately, like during a pull, since
        # it's not always included in SET_ALL.TXT
        parsed_cfg = False
        cfg_configs = {}
        if "CFG.TXT" in files:
            try:
                cfg_configs = parse_cfg_txt(files["CFG.TXT"].read_bytes(), dev)
                parsed_cfg = True
            except Exception as ex:
                cls.log.warning(f"Failed to parse {files['CFG.TXT']}: {ex}")

        # Sequential Event Recorder (SER) events, falling back to CSER,
        # and the history of events, falling back to CHISTORY
        parsed_events = cls._parse_event_files(dev, files)
        events = parsed_events["ser"]
        history = parsed_events["history"]
        cls._apply_uptime(dev, live=False)

        cid_extracted = False
        for name, path in files.items():
            if name.endswith(".CID"):
                if process_cid_file(data=path.read_bytes(), filepath=path, dev=dev):
                    cid_extracted = True

        if not any([has_settings, parsed_cfg, events, history, cid_extracted]):
            cls.log.warning(f"No data parsed from the SEL relay files in {root}")
            return None

        # Hash and record the files that were parsed
        for path in files.values():
            cls._record_parse_input(dev, path)

        if has_settings and not set_all_path:
            cls._write_combined_set_all(
                dev,
                set_all,
                [
                    path.name
                    for name, path in files.items()
                    if name == "CFG.TXT" or SETTINGS_FILENAME_RE.match(name)
                ],
            )

        local_paths = {path.resolve() for path in files.values()}
        annotate_settings_classes(
            cfg_configs.get("CLASSES"), [f for f in dev.files if f.local_path in local_paths]
        )

        cls.update_dev(dev)  # Populate any fields that are unset

        return dev

    @classmethod
    def parse_config(cls, set_all: str, dev: DeviceData | None = None) -> DeviceData | None:
        try:
            parsed, dev = parse_set_all(set_all_data=set_all, dev=dev)
        except Exception:
            cls.log.exception("Failed config parsing due to a unhandled exception")
            return None

        dev.write_file(parsed, "parsed-config.json")

        if dev.description.model:
            cls._check_model(dev.description.model, dev.description.model)

        # OS information (this is inferred based on fact it's an SEL relay)
        dev.os.family = "rtos"
        dev.os.name = "ThreadX"
        dev.os.vendor.name = "Express Logic"

        # Set the device name if not already set. Key used varies
        # depending on how it's configured and the device model.
        for id_key in ["relay_id", "terminal_id", "station_id"]:
            id_val = parsed.get(id_key)
            if id_val:
                dev.extra[id_key] = id_val  # Store in extra
                if not dev.name:  # Set the name if not set
                    dev.name = parsed[id_key]

        # Only store the logic portions of the config as the "logic"
        logic_keys = ["close_logic", "output_logic", "protection_schemes", "trip_logic"]
        raw_logic = {}
        formatted_logic = {}

        for k in logic_keys:
            if k in parsed:
                raw_logic[k] = parsed[k]
                if k == "protection_schemes":
                    formatted_logic[k] = parsed[k]
                else:
                    formatted_logic[k] = {
                        group: ",".join(f"{k}={v}" for k, v in logic.items())
                        for group, logic in parsed[k].items()
                    }
            else:
                cls.log.warning(f"No logic key {k} in config, not storing in logic...")

        formatted_logic = pformat(formatted_logic)

        # Save the configuration and logic to the data model and a file
        dev.logic.original = set_all
        dev.logic.parsed = formatted_logic
        # Set again by _use_show_settings() if these are the SHO commands, e.g.
        # not if a later pull method (FTP after Telnet) downloaded a settings file
        dev.extra.pop("settings_source", None)

        dev.write_file(raw_logic, "raw-logic.json")
        dev.write_file(formatted_logic, "formatted-logic.txt")
        dev.write_file(set_all, "raw-setall-config.txt")

        return dev

    @classmethod
    def restart_relay_telnet(cls, dev: DeviceData) -> bool:
        """
        Execute a system restart on the SEL relay via Telnet.

        Refer to :meth:`restart_relay`, which this calls.
        """
        return cls.restart_relay(dev, comm_type="telnet")

    @classmethod
    def restart_relay(
        cls,
        dev: DeviceData,
        comm_type: Literal["telnet", "serial"] | None = None,
    ) -> bool:
        """
        Restart (reboot) the SEL relay with the ``STA C`` command, and check that it
        comes back.

        #. Connect via Telnet or serial (with a few retries if the connection fails),
           and elevate to access level 2. Login failures aren't retried.
        #. Run :meth:`~peat.modules.sel.sel_ascii.SELAscii.restart_device`, which
           checks the level 2 prompt, records the FID, and answers the relay's
           confirmation question.
        #. If ``sel.restart_verify`` is enabled (the default): Telnet: wait for the
           Telnet port to close (up to ``restart_down_timeout`` seconds) and then
           to open again (up to ``sel.restart_timeout`` seconds), then reconnect
           and check the FID. Serial: wait for the prompt (the relay sends it when
           it starts, if the port's AUTO setting is Y, otherwise PEAT sends a
           carriage return every few seconds) and check the FID.

        The details are saved in ``dev.extra["restart"]``.

        .. warning::
           A restart interrupts protection, and clears the relay's self-test
           warnings and failures. Never use this on a relay in service without
           the approval of the asset owner.

        Other ways to restart a relay are never used: ``L_D`` starts the firmware
        loader (SELBOOT) and disables the relay, ``R_S`` restores the factory
        settings, and a DNP3 cold or warm restart only restarts the DNP3 port on
        some relays (e.g. the SEL-421 and SEL-487B). The SEL-2030 and SEL-2032 have
        no SEL ASCII command to restart them, so they're not supported.

        Args:
            dev: The relay
            comm_type: ``"telnet"`` or ``"serial"``. If not set, serial is used
                if a serial port is configured and the run is a serial run (as in
                ``_pull()``), otherwise Telnet.

        Returns:
            If the restart was initiated and, if ``sel.restart_verify`` is
            enabled, the relay came back with the same FID
        """
        if comm_type is None:
            if dev.options["sel"]["force_serial_pull"] or (
                dev.serial_port and state.comm_type == "serial"
            ):
                comm_type = "serial"
            else:
                comm_type = "telnet"

        record: dict[str, Any] = {
            "method": comm_type,
            "requested_at": utils.utc_now().isoformat(),
            "status": "failed",
            "reason": "",
            "verified": False,
        }
        dev.extra["restart"] = record

        model = normalize_model(dev.description.model)
        if model in ("2030", "2032"):
            record["status"] = "unsupported"
            record["reason"] = f"the SEL-{model} has no SEL ASCII command to restart it"
            cls.log.error(f"Can't restart {dev.get_id()}: {record['reason']}")
            return False

        cls.log.warning(f"Restarting relay {dev.get_id()} via {comm_type} (STA C)")
        cls._forget_ascii_passwords(dev)

        if comm_type == "serial":
            return cls._restart_serial(dev, record)
        return cls._restart_telnet(dev, record)

    @classmethod
    def _record_restart(cls, record: dict, result: RestartResult) -> None:
        record.update(result.to_dict())
        record["initiated"] = result.initiated
        # "reason" is updated by the verification, this is why the restart is initiated
        record["restart_reason"] = result.reason
        if not result:
            cls.log.error(f"Restart failed ({result.status}): {result.reason}")

    @classmethod
    def _restart_telnet(cls, dev: DeviceData, record: dict) -> bool:
        port = dev.options["telnet"]["port"]
        timeout = dev.options["telnet"]["timeout"]
        result = None  # type: RestartResult | None
        halted = ""

        for attempt in range(3):
            if attempt:
                wait = cls.restart_poll_interval * attempt
                cls.log.info(f"Retrying the Telnet connection to {dev.ip} in {wait} seconds")
                time.sleep(wait)

            with SELTelnet(dev.ip, port, timeout, **cls._ascii_options(dev)) as tn:
                if not tn.test_connection():
                    record["reason"] = f"failed to connect to {dev.ip}:{port}"
                    continue

                cls._prepare_ascii(dev, tn)
                # A failed login isn't retried, so it can't cause a lockout
                if not tn.elevate(2, cls._configured_ascii_creds(dev)):
                    record["reason"] = "failed to elevate to access level 2"
                    cls.log.error(f"Failed to restart {dev.ip} via Telnet: login failed")
                    return False

                dev.related.user.update(tn.successful_usernames)
                result = tn.restart_device(
                    confirm_timeout=cls.restart_confirm_timeout,
                    reboot_timeout=cls.restart_reboot_timeout,
                )
                halted = tn.halted
                break

        if result is None:
            cls.log.error(f"Failed to restart {dev.ip} via Telnet: {record['reason']}")
            return False

        cls._record_restart(record, result)
        if not result:
            return False
        if halted:
            # e.g. the relay restarted in SELBOOT. Nothing more is sent to it,
            # so it isn't verified (no new connection).
            record["reason"] = f"the restart was initiated, but {halted}"
            cls.log.error(f"Restart of {dev.ip}: {record['reason']}")
            return False

        if not dev.options["sel"]["restart_verify"]:
            cls.log.info(f"Restart of {dev.ip} initiated (not verified, sel.restart_verify)")
            return True

        return cls._verify_restart_telnet(dev, record, result)

    @classmethod
    def _verify_restart_telnet(cls, dev: DeviceData, record: dict, result: RestartResult) -> bool:
        port = dev.options["telnet"]["port"]
        restart_timeout = float(dev.options["sel"]["restart_timeout"])
        poll = cls.restart_poll_interval
        started = time.monotonic()

        # The port closes while the relay restarts. This can be missed if the
        # relay restarts within one poll interval.
        went_down = False
        while time.monotonic() - started < cls.restart_down_timeout:
            if not check_tcp_port(dev.ip, port, timeout=poll, reset=True):
                went_down = True
                break
            time.sleep(poll)
        record["port_went_down"] = went_down

        came_back = False
        while time.monotonic() - started < restart_timeout:
            if check_tcp_port(dev.ip, port, timeout=poll, reset=True):
                came_back = True
                break
            time.sleep(poll)

        if not came_back:
            record["reason"] = (
                f"the relay's Telnet port didn't open again within {restart_timeout} seconds"
            )
            cls.log.error(f"Restart of {dev.ip}: {record['reason']}")
            return False

        record["back_at"] = utils.utc_now().isoformat()
        record["duration_s"] = round(time.monotonic() - started, 1)

        # The port can open before the relay answers commands
        fid_after = ""
        for _ in range(3):
            try:
                with SELTelnet(
                    dev.ip, port, dev.options["telnet"]["timeout"], **cls._ascii_options(dev)
                ) as tn:
                    fid_after = str(tn.get_id().get("FID", ""))
            except Exception as ex:
                cls.log.debug(f"ID after the restart of {dev.ip} failed: {ex}")
            if fid_after:
                break
            time.sleep(poll)

        return cls._check_restart_fid(dev, record, result, fid_after, went_down)

    @classmethod
    def _check_restart_fid(
        cls,
        dev: DeviceData,
        record: dict,
        result: RestartResult,
        fid_after: str,
        observed: bool,
    ) -> bool:
        record["fid_after"] = fid_after

        if not fid_after:
            record["reason"] = "the relay didn't answer the ID command after the restart"
        elif result.fid and fid_after != result.fid:
            record["reason"] = (
                f"the FID changed from '{result.fid}' to '{fid_after}', "
                f"this may not be the same device"
            )
        elif not observed:
            record["reason"] = (
                "the relay answered, but PEAT didn't see it restart (the port didn't "
                "close, or the prompt didn't change), so the restart wasn't confirmed"
            )
        else:
            record["verified"] = True
            record["reason"] = "the relay restarted and answered with the same FID"
            cls.log.info(
                f"Relay {dev.get_id()} restarted and is back after "
                f"{record.get('duration_s', '?')} seconds"
            )
            return True

        cls.log.warning(f"Restart of {dev.get_id()} wasn't verified: {record['reason']}")
        return False

    @classmethod
    def _restart_serial(cls, dev: DeviceData, record: dict) -> bool:
        if not dev.options["serial"]["baudrate"] and not cls._verify_serial(dev):
            record["reason"] = f"failed to connect to {dev.serial_port}"
            cls.log.error(f"Failed to restart {dev.serial_port}: {record['reason']}")
            return False

        with SELSerial(
            serial_port=dev.serial_port,
            baudrate=dev.options["serial"]["baudrate"],
            timeout=dev.options["timeout"],
            force_ymodem=dev.options["sel"]["force_ymodem"],
            **cls._ascii_options(dev),
        ) as ser:
            if not ser.test_connection():
                record["reason"] = f"failed to connect to {dev.serial_port}"
                cls.log.error(f"Failed to restart {dev.serial_port}: {record['reason']}")
                return False

            cls._prepare_ascii(dev, ser)
            if not ser.elevate(2, cls._configured_ascii_creds(dev)):
                record["reason"] = "failed to elevate to access level 2"
                cls.log.error(f"Failed to restart {dev.serial_port}: login failed")
                return False

            dev.related.user.update(ser.successful_usernames)
            result = ser.restart_device(
                confirm_timeout=cls.restart_confirm_timeout,
                reboot_timeout=cls.restart_reboot_timeout,
            )
            cls._record_restart(record, result)
            if not result:
                return False
            if ser.halted:
                # e.g. the relay restarted in SELBOOT
                record["reason"] = f"the restart was initiated, but {ser.halted}"
                cls.log.error(f"Restart of {dev.serial_port}: {record['reason']}")
                return False

            if not dev.options["sel"]["restart_verify"]:
                return True

            # A restarted relay starts at access level 0. With AUTO=Y, it
            # sends a power-up message and the prompt by itself.
            started = time.monotonic()
            back = ser.wait_for_prompt(
                timeout=float(dev.options["sel"]["restart_timeout"]),
                poke_interval=cls.restart_poll_interval,
            )
            if not back:
                record["reason"] = "the relay didn't show its prompt after the restart"
                cls.log.error(f"Restart of {dev.serial_port}: {record['reason']}")
                return False

            record["back_at"] = utils.utc_now().isoformat()
            record["duration_s"] = round(time.monotonic() - started, 1)
            if ser.halted:
                # e.g. the relay came back in SELBOOT
                record["reason"] = f"the relay came back, but {ser.halted}"
                cls.log.error(f"Restart of {dev.serial_port}: {record['reason']}")
                return False
            observed = ser.access_level == "0"
            fid_after = str(ser.get_id().get("FID", ""))

        return cls._check_restart_fid(dev, record, result, fid_after, observed)


def sel_port_check(dev: DeviceData, protocol: str) -> bool:
    """lambda function set the TCP RST flag for SEL scanning."""
    return check_tcp_port(dev.ip, dev.options[protocol]["port"], reset=True)


SELRelay.ip_methods = [
    # NOTE: We are explicitly NOT port checking FTP. See the note in the
    # docstring at the top of this file.
    IPMethod(
        name="SEL Relay Telnet login",
        description=str(SELRelay._verify_telnet.__doc__).strip(),
        type="unicast_ip",
        identify_function=SELRelay._verify_telnet,
        reliability=6,
        protocol="telnet",
        transport="tcp",
        default_port=23,
        port_function=functools.partial(sel_port_check, protocol="telnet"),
    ),
    IPMethod(
        name="SEL Relay HTTP login",
        description=str(SELRelay._verify_http.__doc__).strip(),
        type="unicast_ip",
        identify_function=functools.partial(SELRelay._verify_http, protocol="http"),
        # 1 higher than HTTPS's reliability so we prefer HTTP over HTTPS
        # for older or less robust devices, like the relays.
        reliability=8,
        protocol="http",
        transport="tcp",
        default_port=80,
        port_function=functools.partial(sel_port_check, protocol="http"),
    ),
    # NOTE: the SEL-2730M switch exclusively uses HTTPS and doesn't allow plain HTTP
    IPMethod(
        name="SEL Relay HTTPS login",
        description=str(SELRelay._verify_http.__doc__).strip(),
        type="unicast_ip",
        identify_function=functools.partial(SELRelay._verify_http, protocol="https"),
        reliability=7,
        protocol="https",
        transport="tcp",
        default_port=443,
        port_function=functools.partial(sel_port_check, protocol="https"),
    ),
]


SELRelay.serial_methods = [
    SerialMethod(
        name="SEL Relay serial",
        description=str(SELRelay._verify_serial.__doc__).strip(),
        type="direct",
        identify_function=SELRelay._verify_serial,
        reliability=5,
    )
]


__all__ = ["SELRelay"]
