from copy import deepcopy
from pathlib import Path
from pprint import pformat

import yaml

from peat import (
    DeviceData,
    Elastic,
    PeatError,
    config,
    config_crypto,
    consts,
    datastore,
    exit_handler,
    log,
    module_api,
    protocols,
    state,
    utils,
)
from peat.data.default_options import DEFAULT_OPTIONS
from peat.settings import merged_excluded_modules
from peat.settings_manager import LAYER_DESCRIPTIONS

from .log_utils import print_logo, setup_logging


def _load_config_file(config_path: Path) -> list[str]:
    """
    Load a configuration file (YAML, JSON, or a file encrypted by PEAT).

    Returns:
        Error messages, if any. These are returned instead of being logged,
        since this happens before logging is configured.
    """
    if config_crypto.is_encrypted_file(config_path):
        # NOTE: the user is prompted for the password
        decrypted = config_crypto.decrypt_config(config_path, user_password=None)
        if not decrypted:
            return [
                f"Failed to decrypt the encrypted configuration file "
                f"'{config_path.name}' (is the password correct?)"
            ]

        try:
            data = yaml.safe_load(decrypted)
        except yaml.YAMLError as ex:
            return [f"Failed to parse the encrypted configuration file '{config_path.name}': {ex}"]

        if not config.load_from_mapping(data, source=config_path.name):
            return [
                f"The encrypted configuration file '{config_path.name}' must contain "
                f"a mapping of option names to values"
            ]

        return []

    try:
        if not config.load_from_file(config_path):
            return [
                f"Failed to load the configuration file '{config_path.name}'. Check that "
                f"the path is correct and the file is a YAML or JSON file containing a "
                f"mapping of option names to values."
            ]
    except Exception as ex:
        return [f"Failed to load the configuration file '{config_path.name}': {ex}"]

    return []


def _log_config_problems(
    early_errors: list[str],
    applied_section: dict,
    section_warnings: list[str],
    command: str | None,
) -> None:
    """
    Log problems with the configuration that occurred before logging was configured.

    Raises:
        PeatError: If the configuration file couldn't be loaded, or if
            ``excluded_modules`` couldn't be loaded from any source
    """
    for msg in early_errors:
        log.critical(msg)

    for (layer, key), err in config["load_errors"].items():
        source = LAYER_DESCRIPTIONS.get(layer, layer)
        if layer == "env_configs":
            source = f"{source} {config.env_prefix}{key}"
        log.error(f"Failed to load configuration option '{key.lower()}' ({source}): {err}")

    for msg in section_warnings:
        log.warning(msg)

    if applied_section:
        log.info(
            f"Applied the '{command}' section of the config: "
            f"{', '.join(k.lower() for k in sorted(applied_section))}"
        )

    overridden = sorted(k for k in config["section_configs"] if k not in applied_section)
    if overridden:
        log.info(
            f"Options in the '{command}' section of the config that are overridden by "
            f"environment variables or command line arguments: "
            f"{', '.join(k.lower() for k in overridden)}"
        )

    # Fail closed: a broken exclusion must never quietly turn into no exclusion
    excluded_errors = [k for k in config["load_errors"] if k[1] == "EXCLUDED_MODULES"]
    if excluded_errors:
        raise PeatError(
            "Invalid value for 'excluded_modules', refusing to run without "
            "the requested exclusions (see the errors above)"
        )

    if early_errors:
        raise PeatError("Failed to load the configuration file (see the errors above)")


def initialize_peat(conf: dict, entrypoint: consts.EntrypointType = "Package") -> None:
    """
    Various initialization steps for most PEAT use cases.

    .. note::
       If loading from the CLI, ``conf`` will contain the raw values of arguments,
       e.g. an argument that stores ``args.func`` would be in ``conf`` as
       ``conf["func"]``.

    Args:
        conf: Configuration values to set at runtime, if any
        entrypoint: How PEAT is being used. If you're using PEAT
            as a package/library, do NOT set this argument.
            Must be either "CLI" or "Package".
    """
    state.entrypoint = entrypoint

    # Convert top-level keys to lowercase. This makes it easier to use
    # this function directly from testing scripts or the REPL, e.g.
    # initialize_peat({"DEBUG": 1, "OUT_DIR": None})
    conf = consts.lower_dict(conf, children=False)

    # Minor hack to handle case where someone accidentally disables RUN_DIR
    # without disabling OUT_DIR as well, since they're mutually dependent.
    if (
        entrypoint == "Package"
        and "run_dir" in conf
        and conf["run_dir"] is None
        and "out_dir" not in conf
    ):
        conf["out_dir"] = None

    # Errors that occur before logging is configured. These are logged once
    # logging is configured, and then initialization fails.
    early_errors: list[str] = []

    # If config file is specified, load those values
    # NOTE: non-None values in 'conf' will override any file values!
    if conf.get("config_file"):
        config_path = Path(conf["config_file"]).resolve()
        early_errors.extend(_load_config_file(config_path))

    # Load runtime configurations (CLI arguments, program-specified, etc.)
    # This magically populates Configuration options from same-named CLI arguments
    config.load_from_dict(conf)

    # Apply the section of the config file for the command being run, e.g. "pull:".
    # This is done before modules are imported and directories are configured,
    # since the section may change those options.
    applied_section, section_warnings = config.apply_command_section(conf.get("func"))

    # Import third-party device modules
    # The module API handles lists of file paths already
    if config.ADDITIONAL_MODULES:
        config.ADDITIONAL_MODULES = [  # Save as absolute paths
            str(Path(x).resolve()) for x in config.ADDITIONAL_MODULES
        ]

        if not module_api.import_module(config.ADDITIONAL_MODULES):
            raise PeatError(
                f"No additional device modules were valid. "
                f"Module paths: {config.ADDITIONAL_MODULES}"
            )

    # Minor hack to make "--list-modules" work with minimal fuss
    for list_arg in [
        "list_all",
        "list_modules",
        "list_aliases",
        "list_alias_mappings",
        "examples",
        "all_examples",
        "list_heat_protocols",
    ]:
        if conf.get(list_arg):
            return

    # Hack to configure output directories
    if conf.get("out_dir"):
        config.fixup_dirs(config.OUT_DIR, "OUT_DIR", override_all=True)
    elif entrypoint == "Package" and "out_dir" in conf and conf["out_dir"] is None:
        config.OUT_DIR = None
        config.fixup_dirs(None, "OUT_DIR", override_all=True)

    # Set RUN_DIR if manually configured
    if conf.get("run_dir") and "default_run_dir" not in conf["run_dir"]:
        config.fixup_dirs(config.RUN_DIR, "RUN_DIR", override_all=True)
    elif entrypoint == "Package" and "run_dir" in conf and conf["run_dir"] is None:
        config.RUN_DIR = None
        config.fixup_dirs(None, "RUN_DIR", override_all=True)

    # Auto-generate RUN_DIR if not manually configured
    if config.OUT_DIR and (
        not conf.get("run_dir") or "default_run_dir" in conf.get("run_dir", "")
    ):
        # If --run-name is set, use that value for the run name
        if conf.get("run_name"):
            run_name = conf["run_name"]
        else:
            config_name = "default-config"
            if config.METADATA.get("name"):
                config_name = config.METADATA["name"]
            elif conf.get("config_file"):
                # if there's no metadata, fallback to using config file name
                # for example, for a file "peat-config.yaml", config name would
                # be "peat-config".
                config_name = Path(conf["config_file"]).stem

            cmd_name = "unknown-command"
            if conf.get("func"):
                cmd_name = conf["func"]

            # Format: <command>_<config-name>_<timestamp>_<run-id>
            run_name = f"{cmd_name}_{config_name}_{consts.START_TIME}_{consts.RUN_ID}"

        config.RUN_DIR = config.OUT_DIR / run_name
        config.fixup_dirs(config.RUN_DIR, "RUN_DIR", override_all=True)

    # Fancy startup logo, printed to stderr
    if state.entrypoint == "CLI" and not (config.QUIET or config.NO_LOGO):
        print_logo()

    # Configure logging across PEAT (globally)
    log_file = None
    json_file = None
    debug_info_file = None
    if config.LOG_DIR:
        log_file = config.LOG_DIR / "peat.log"
        json_file = config.LOG_DIR / "json-log.jsonl"
        debug_info_file = config.LOG_DIR / "debug-info.txt"

    setup_logging(
        file=log_file,
        json_file=json_file,
        debug_info_file=debug_info_file,
    )

    # Log problems with the configuration that occurred before logging was configured
    _log_config_problems(early_errors, applied_section, section_warnings, conf.get("func"))

    # Exclusions from all sources are combined. Record the combined value so the
    # configuration saved at the end of the run (peat_configuration.yaml) has
    # the exclusions that were actually used.
    try:
        merged_exclusions = merged_excluded_modules(config)
    except ValueError as ex:  # Invalid value set at runtime, e.g. by an API user
        raise PeatError(f"Invalid value for 'excluded_modules': {ex}") from None
    if merged_exclusions:
        config.EXCLUDED_MODULES = merged_exclusions

    # Copy original config file
    if conf.get("config_file") and config.META_DIR:
        config_path = Path(conf["config_file"]).resolve()
        utils.copy_file(config_path, config.META_DIR / config_path.name)

    # Output messages to user now that logging is configured
    config_name = ""
    if config.METADATA.get("name"):
        config_name = f"'{config.METADATA['name']}' "
    if conf.get("config_file"):  # Log so the user sees config was loaded
        log.info(f"Configuration {config_name}loaded from '{conf['config_file']}'")

    if config.RUN_DIR:
        log.info(f"Run directory: {config.RUN_DIR.name}")

    if config.DEBUG:
        log.warning(f"Debugging mode is ENABLED. DEBUG level: {config.DEBUG}")
        log.debug(f"Running using Python {consts.SYSINFO['python_version']}")

    if config.DRY_RUN:
        log.warning(
            "Dry run mode is enabled! Actions won't be executed, but logs and "
            "state will still be written to files and saved to Elasticsearch "
            "(if enabled)."
        )

    if (
        not state.peat_initialized
        and not entrypoint == "Package"
        and (
            conf.get("func", "") not in ["parse", "pillage"]  # Skip passive
            and not (conf.get("ports") or conf.get("port_list"))  # Skip serial
        )
    ):
        # Suggest user run as Administrator on Windows
        if consts.WINDOWS and not state.raw_socket_capable:
            log.warning(
                "PEAT is unable to use RAW sockets, which may impact "
                "scanning performance. To fix this, re-run PEAT from "
                "an Administrator-level command prompt (right click -> "
                "'Run as Administrator')"
            )
        # Suggest user run with sudo on macOS (Scapy needs access to /dev/bpf*)
        elif consts.MACOS and not state.raw_socket_capable:
            log.warning(
                "PEAT is unable to access BPF devices (/dev/bpf*) for raw packet "
                "operations, so ARP and ICMP host checks are disabled and scanning "
                "will be slower. To fix this, re-run PEAT with 'sudo'."
            )

        # Check if default interface is promiscuous (e.g Netmeld didn't reset it)
        if consts.POSIX and protocols.is_promiscuous(state.default_interface_name):
            log.warning(
                f"Default interface '{state.default_interface_name}' is "
                f"in promiscuous mode, this may cause the run to fail."
            )
            # TODO: check the default(s) for the specified hosts

        if not consts.WINDOWS and not consts.SYSINFO["tcpdump"]:
            if state.raw_socket_capable:
                log.warning(
                    "RAW sockets are available, however tcpdump is not installed. "
                    "You may run into issues during host discovery. If so, "
                    "try re-running peat with '--assume-online'."
                )
            else:
                log.warning("tcpdump is not installed, your mileage may vary")

    # Add serial baudrates to the global options if doing serial operations
    if (conf.get("ports") or conf.get("port_list")) and conf.get("baudrates"):
        baudrates = protocols.parse_baudrates(conf["baudrates"])
        datastore.global_options["baudrates"] = baudrates

    # Set the global timeout if user sets it
    if conf.get("default_timeout"):
        datastore.global_options["timeout"] = conf["default_timeout"]
        # !! hack to inject default timeout to individual protocols !!
        for v in DEFAULT_OPTIONS.values():
            if isinstance(v, dict) and "timeout" in v:
                v["timeout"] = conf["default_timeout"]

    # Load global configuration options that are applied to all devices
    if config.DEVICE_OPTIONS:
        # NOTE: do these minor hacks before updating global options so we don't override CLI args
        if config.DEVICE_OPTIONS.get("baudrates") and not datastore.global_options.get(
            "baudrates"
        ):
            baudrates = protocols.parse_baudrates(config.DEVICE_OPTIONS["baudrates"])
            datastore.global_options["baudrates"] = baudrates

        if config.DEVICE_OPTIONS.get("timeout") and not datastore.global_options.get("timeout"):
            # !! hack to inject default timeout to individual protocols !!
            for v in DEFAULT_OPTIONS.values():
                if isinstance(v, dict) and "timeout" in v:
                    v["timeout"] = config.DEVICE_OPTIONS["timeout"]

        datastore.global_options.update(config.DEVICE_OPTIONS)

    # Load host-specific options
    if config.HOSTS:
        for host in config.HOSTS:
            # Set identifying attributes, e.g. data.ip, data.mac, etc.
            opt_dev = DeviceData(**host["identifiers"])

            # Apply options specific to this host
            if host.get("options"):
                opt_dev._host_option_overrides.update(deepcopy(host["options"]))

            if host.get("peat_module"):
                opt_dev._module = module_api.get_module(host["peat_module"])

            datastore.objects.append(opt_dev)

    # Save the current state and configuration to files upon termination.
    # This won't happen if running as a library/Python package.
    if state.entrypoint == "CLI":

        def _save_on_exit():
            if config.META_DIR:
                config.save_to_file(outdir=config.META_DIR, save_json=False)
                state.save_to_file(outdir=config.META_DIR, save_json=False)

        exit_handler.register(_save_on_exit, "FILE")

    # Configure Elasticsearch. If a server is specified,
    # create an Elastic instance and attempt to connect.
    # If elastic server in conf, and elastic already initialized,
    # only reconnect if the server URL is different.
    if (config.ELASTIC_SERVER and not state.elastic) or (
        conf.get("elastic_server")
        and state.elastic
        and conf["elastic_server"] not in state.elastic.unsafe_url
    ):
        try:
            # NOTE: don't log ELASTIC_SERVER value as it may have sensitive login creds
            log.trace2("Setting up global Elastic instance...")
            elastic = Elastic(config.ELASTIC_SERVER)
            elastic.ping()  # Force the connection to be created
        except Exception as ex:
            log.error(
                f"Failed to initialize Elasticsearch/OpenSearch. Data "
                f"from this run will not be pushed to the database. "
                f"Exception: {ex}"
            )
        else:
            if config.ELASTIC_DISABLE_DATED_INDICES:
                log.warning(
                    "Dated index names are disabled, data will be pushed "
                    "to plain index names without a date appended"
                )

            if state.elastic:
                state.elastic.disconnect()

            state.elastic = elastic  # Set the global Elastic instance

    # Record the fact that timezone data may be wonky
    try:
        import tzlocal  # noqa: F401
    except Exception:
        log.warning("Failed to import 'tzlocal'. Timezone names will be non-standard.")

    # Initialize value of state.superuser_privs
    if not state.peat_initialized:
        utils.are_we_superuser()
        if state.superuser_privs:
            log.warning(
                "PEAT is running with superuser privileges (root or "
                "Administrator). This means we can use raw sockets and "
                "do more serial stuff. Just a friendly heads up :)"
            )

    # Log the arguments for debugging
    log.trace4(f"initialize_peat conf\n{pformat(conf, indent=4)}\n")
    log.trace2(f"global_options\n{pformat(datastore.global_options, indent=4)}")

    state.peat_initialized = True
