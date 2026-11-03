import timeit
from operator import itemgetter

from peat import (
    DeviceData,
    PeatError,
    __version__,
    config,
    consts,
    datastore,
    log,
    module_api,
    state,
    utils,
)
from peat.protocols import hosts_to_ips, sort_ips

from .scan_api import scan


def pull(
    targets: list[str],
    comm_type: consts.AllowedCommTypes,
    device_types: list[str],
    skip_scan: bool = False,
) -> dict[str, dict | list | str | float | int] | None:
    """Pull from devices.

    After the pull, devices that are reached through the devices that were
    pulled ("gateways"), e.g. relays behind a SEL RTAC, are pulled, if this is
    configured (refer to :func:`pull_downstream`). ``targets`` can be empty if
    only those are pulled (e.g. ``--rtac-tunnel`` without ``-i``).

    Args:
        targets: Devices to pull from, such as network hosts or serial ports
        comm_type: Method of communication for the pull. Allowed values:

            - ``unicast_ip``
            - ``broadcast_ip``
            - ``serial``
        device_types: Names of device modules or module aliases to use
        skip_scan: If device verification (scanning) should be skipped.
            NOTE: this currently only applies to unicast_ip devices.

    Returns:
        :ref:`pull-summary` as a :class:`dict`, or :obj:`None` if an error occurred
    """
    scan_summary = None

    if not targets:
        # e.g. only relays behind a SEL RTAC (--rtac-tunnel), refer to pull_downstream()
        log.info("No targets to scan, only pulling devices behind gateways (if configured)")
        devices = []
    elif skip_scan:
        log.warning(f"Skipping verification scan and pulling from {len(targets)} targets")

        ips = sort_ips(hosts_to_ips(targets))
        if not ips:
            log.error("Pull failed: no IP targets were valid")
            state.error = True
            return None

        # Build per-IP module map from YAML config hosts
        host_module_map: dict = {}
        for host in config.HOSTS or []:
            ip = host.get("identifiers", {}).get("ip")
            peat_module = host.get("peat_module")
            if ip and peat_module:
                resolved = module_api.lookup_types([peat_module], filter_attr="ip_methods")
                if resolved:
                    host_module_map[ip] = resolved[0]

        # Fallback to the explicitly specified device types when no per-host mapping exists
        fallback_modules = module_api.lookup_types(device_types, filter_attr="ip_methods")
        if len(fallback_modules) > 1 and not host_module_map:
            raise PeatError(
                "More than 1 device type specified with --skip-scan and no per-host "
                "'peat_module' found in YAML config. Specify a single module using '-d' or "
                "add 'peat_module' to each host entry in the YAML config."
            )
        fallback_module = fallback_modules[0] if len(fallback_modules) == 1 else None

        devices = []
        for ip in ips:
            module = host_module_map.get(ip) or fallback_module
            if module is None:
                log.error(f"No module resolved for {ip}, unable to pull")
                state.error = True
                return None

            dev = datastore.get(ip)
            dev._is_active = True
            dev._is_verified = True
            dev._module = module
            devices.append(dev)

        if not devices:
            log.error("Pull failed: no valid devices to pull from")
            state.error = True
            return None
    else:
        scan_summary = scan(targets, comm_type, device_types)

        if not scan_summary or not scan_summary["hosts_verified"]:
            # Devices behind gateways may still be configured (refer to pull_downstream())
            devices = []
        else:
            # * Combine any duplicate devices *
            datastore.deduplicate()

            devices = datastore.verified

    # * Pull from all devices specified *
    if devices:
        log.info(f"Beginning pull for {len(devices)} devices")
    start_time = timeit.default_timer()
    pull_results = []
    pulled = []  # type: list[tuple[DeviceData, dict]]

    for device in devices:
        try:
            successful = device._module.pull(device)
            if not successful:
                log.error(f"Pull failed from {device.get_id()}")
                state.error = True
                continue

            device.purge_duplicates(force=True)

            exported_data = device.elastic()
            pull_results.append(exported_data)
            pulled.append((device, exported_data))

            if state.elastic:
                device.export_to_elastic()
        except Exception:
            log.exception(f"Failed to pull from {device.get_id()}")
            state.error = True

    # * Pull devices behind gateways (opt-in) *
    children = pull_downstream([device for device, _ in pulled], device_types)

    if not devices and not children:
        log.error("Pull failed: no devices were found")
        state.error = True
        return None

    if children:
        # The gateways list the devices behind them now (e.g. "related.hosts")
        pull_results = []
        for device, exported_data in pulled:
            try:
                exported_data = device.elastic()
            except Exception:
                log.exception(f"Failed to export {device.get_id()} again")
            pull_results.append(exported_data)

        for child in children:
            try:
                child.purge_duplicates(force=True)
                pull_results.append(child.elastic())

                if state.elastic:
                    child.export_to_elastic()
            except Exception:
                log.exception(f"Failed to export {child.get_id()}")
                state.error = True

    pull_duration = timeit.default_timer() - start_time
    log.info(
        f"Finished pulling from {len(devices) + len(children)} devices "
        f"in {utils.fmt_duration(pull_duration)}"
    )

    # * Sort pull results by device ID for consistency *
    pull_results.sort(key=itemgetter("id"))

    # * Generate pull summary *
    pull_summary = {
        "peat_version": __version__,
        "peat_run_id": str(consts.RUN_ID),
        "pull_duration": pull_duration,
        "pull_modules": module_api.lookup_names(device_types),
        "pull_targets": scan_summary["scan_targets"] if scan_summary else targets,
        "pull_original_targets": targets,
        # Devices behind gateways don't have an address, they're listed by their ID
        "pull_devices": [dev.get_id() for dev in devices] + [child.id for child in children],
        "pull_comm_type": comm_type,
        "num_pull_results": len(pull_results),
        "pull_results": pull_results,
    }

    # * Save pull results to a file *
    utils.save_results_summary(pull_summary, "pull-summary")

    # * Push pull results summary to Elasticsearch *
    if state.elastic:
        log.info(
            f"Pushing pull result summary to Elasticsearch "
            f"(index basename: {config.ELASTIC_PULL_INDEX})"
        )

        if not state.elastic.push(config.ELASTIC_PULL_INDEX, pull_summary):
            log.error("Failed to push pull result summary to Elasticsearch")

    return pull_summary


def pull_downstream(
    devices: list[DeviceData],
    device_types: list | None = None,
) -> list[DeviceData]:
    """
    Pull the devices that are reached through other devices ("gateways"),
    e.g. SEL relays behind the engineering access tunnels of a SEL RTAC.

    This is opt-in: nothing is pulled unless the user configured it (e.g.
    ``sel.rtac_tunnels``, ``--rtac-tunnel``, or ``sel.rtac_pull_downstream``
    for SEL RTACs, refer to "RTAC engineering tunnels" in the SEL documentation).

    Modules take part with two optional class methods, which are found
    with ``getattr()``:

    - ``downstream_targets(dev)``, on the module of a device that was pulled:
      the devices that can be reached through it
      (:meth:`peat.device.DeviceModule.downstream_targets`, ``[]`` by default).
    - ``pull_downstream(gateway_targets, selected)``, on modules that pull devices
      through gateways: pulls the targets that the user allowed, and returns the
      devices that were pulled. ``gateway_targets`` is a list of the devices that
      were pulled with their ``downstream_targets()``, for the devices that have
      any. ``selected`` is :obj:`True` if the module was selected for the pull
      (``device_types``): targets that are configured for the module itself
      (e.g. ``sel.rtac_tunnels``) should only be pulled then, while the targets
      of the gateways are governed by the gateways' options. The devices are
      added to the datastore by the module.

    The hook is called once per implementation (not again for a subclass that
    inherits it), on the selected module if one of them has it.

    Args:
        devices: The devices that were pulled
        device_types: Names of the modules (or aliases) selected for the pull.
            If :obj:`None`, all modules are selected.

    Returns:
        The devices that were pulled through gateways
    """
    gateway_targets = []  # type: list[tuple[DeviceData, list[dict]]]
    for dev in devices:
        hook = getattr(dev._module, "downstream_targets", None)
        if not callable(hook):
            continue
        try:
            targets = list(hook(dev) or [])
        except Exception:
            log.exception(f"Failed to get the devices behind {dev.get_id()}")
            continue
        if targets:
            gateway_targets.append((dev, targets))

    selected = module_api.lookup_types(device_types)
    others = [module for module in module_api.classes if module not in selected]

    def _defines_hook(module: type) -> bool:
        return "pull_downstream" in vars(module)

    # The selected modules first, then the others. In each group, the modules that
    # define the hook come before the subclasses that inherit it, so the devices
    # get the module that defines it, unless only a subclass is selected.
    ordered = sorted(selected, key=lambda m: not _defines_hook(m)) + sorted(
        others, key=lambda m: not _defines_hook(m)
    )

    children = []  # type: list[DeviceData]
    called = set()
    for module in ordered:
        hook = getattr(module, "pull_downstream", None)
        if not callable(hook):
            continue
        # Once per implementation, e.g. not again for a subclass of a module
        func = getattr(hook, "__func__", hook)
        if func in called:
            continue
        called.add(func)
        try:
            children.extend(hook(gateway_targets, selected=module in selected) or [])
        except Exception:
            log.exception(f"Failed to pull the devices behind gateways with {module.__name__}")
            state.error = True

    return children


__all__ = ["pull", "pull_downstream"]
