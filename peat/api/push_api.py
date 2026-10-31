from pathlib import Path
from typing import Literal, get_args

from peat import PeatError, consts, datastore, log, module_api, utils
from peat.module_selection import get_exclusions, select_modules
from peat.protocols import hosts_to_ips, sort_ips

from .scan_api import scan


def push(
    targets: list[str],
    comm_type: consts.AllowedCommTypes,
    device_types: list[str],
    input_source: Path | str,
    push_type: Literal["config", "firmware"],
    skip_scan: bool = False,
) -> bool:
    """
    Push (upload) configuration or firmware to devices.

    .. note::
       By default all targets are scanned and verified, and only the devices that
       are successfully verified are pushed to. This enables this function to be
       used without requiring a scan to be done and ensuring pushes are not
       performed to invalid devices. This behavior can be disabled by setting
       ``PUSH_SKIP_SCAN`` to True or passing ``--push-skip-scan`` on the CLI.

    Args:
        targets: Devices to push to, such as network hosts or serial ports
        comm_type: Method of communication for the push. Allowed values:

            - ``unicast_ip``
            - ``broadcast_ip``
            - ``serial``
        device_types: Names of device modules or module aliases to use. If
            scanning is disabled this should be a single device type.
        input_source: Path of the file to push, as a string
        push_type: Type of push being performed. Valid push types are
            "config" and "firmware".
        skip_scan: If device verification (scanning) should be skipped.
            NOTE: this currently only applies to unicast_ip devices.

    Returns:
        If the push was successful

    Raises:
        PeatError: If the push failed due to an issue with configuration
          or arguments, such as invalid device types or push type, or
          if a target in ``excluded_modules`` is invalid.
    """
    source = utils.check_file(input_source)
    if source is None:
        raise PeatError(f"bad input source '{source}'")

    if push_type not in get_args(consts.PushType):
        raise PeatError(f"Invalid '{push_type}' (supported types: {get_args(consts.PushType)})")

    # Module exclusions (excluded_modules)
    exclusions = get_exclusions()
    exclusions.log_summary()

    # TODO: make input a list of
    #   (device_id, device_comm_type, device_peat_module)

    # Skip scan on push (assume all devices online)
    if skip_scan:
        log.warning(f"Skipping verification scan and pushing to {len(targets)} targets")
        # Device types that only match modules excluded for every target don't count,
        # so e.g. "-d sel -x SELRTAC,SEL3620" (expanded to the 3 SEL modules) works.
        remaining_types = [
            dt
            for dt in device_types
            if not (
                (dt_mods := module_api.lookup_types([dt]))
                and all(m in exclusions.global_mods for m in dt_mods)
            )
        ]
        if len(remaining_types) > 1:
            raise PeatError(
                f"more than 1 device type specified when PUSH_SKIP_SCAN is enabled "
                f"({', '.join(str(dt) for dt in remaining_types)}). Specify a single "
                f"module using '-d' or 'device_types', or exclude the other modules "
                f"using '-x' or 'excluded_modules'."
            )

        modules = select_modules(device_types, filter_attr="ip_methods", exclusions=exclusions)
        if not modules:
            raise PeatError(
                f"No PEAT module is available to push with for device type(s) "
                f"{device_types} (no module matched, or every module is excluded)"
            )
        if len(modules) > 1:
            raise PeatError(
                f"The device type {device_types} matches more than 1 module when "
                f"PUSH_SKIP_SCAN is enabled ({', '.join(m.__name__ for m in modules)}). "
                f"Specify a single module using '-d' or 'device_types', or exclude the "
                f"other modules using '-x' or 'excluded_modules'."
            )
        module = modules[0]

        ips = sort_ips(hosts_to_ips(targets))
        if not ips:
            log.error("Push failed: no IP targets were valid")
            return False

        devices = []  # type: list[DeviceData]
        for ip in ips:
            if exclusions.is_excluded(module, dev=datastore.search(ip, "ip"), target=ip):
                log.warning(
                    f"Skipping push to {ip}: the module {module.__name__} "
                    f"is excluded for this target by excluded_modules"
                )
                continue

            dev = datastore.get(ip)
            dev._is_active = True
            dev._is_verified = True
            dev._module = module
            devices.append(dev)

        if not devices:
            log.error("Push failed: every target is excluded")
            return False
    else:
        scan_summary = scan(targets, comm_type, device_types)  # type: ignore
        if not scan_summary or not scan_summary["hosts_verified"]:
            log.error("Push failed: no devices were found in scan")
            return False

        devices = datastore.verified  # type: list[DeviceData]

    log.info(f"Beginning push to {len(devices)} devices")
    for device in devices:
        # Final check of exclusions, e.g. for devices that were already in the datastore
        if exclusions.is_excluded(device._module, dev=device):
            log.warning(
                f"Skipping push to {device.get_id()}: the module "
                f"{device._module.__name__} is excluded for this device by excluded_modules"
            )
            continue

        try:
            push_result = device._module.push(
                dev=device,
                to_push=source,
                push_type=push_type,
            )
        except Exception:
            log.exception(f"Failed to push to {device.get_id()}")
            return False

        if not push_result:
            return False

    log.info(f"Finished pushing to {len(devices)} devices")
    return True


__all__ = ["push"]
