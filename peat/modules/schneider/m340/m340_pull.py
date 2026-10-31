"""
Methods to pull from Schneider Modicon M340 PLCs.

This includes process logic, configuration, and firmware.

Authors

- Christopher Goes
- Mark Woodard
- Patrica Schulz
"""

import binascii
import socket
from typing import Any, Final

from peat import CommError, utils
from peat import log as peat_logger
from peat.protocols import FTP, SNMP

from . import m340_snmp
from .umas_packets import UMASResponse, send_umas_packet

# NOTE: the OIDs below are only used by the raw-OID SNMP fallback,
# _get_snmp_metadata(). The primary SNMP method uses the Schneider
# TFE private MIB, refer to m340_snmp.py.
# Format: "info_returned": ("OID under 1.3.6.1.", type)

#: OIDs for information specific to the module running the SNMP server.
SNMP_MODULE_OIDS: Final[dict[str, tuple[str, type]]] = {
    # Slot of the CPU
    "slot": ("4.1.3833.1.7.10.0", int),
    # Full name and version of hardware
    "model_name": ("4.1.3833.1.7.1.0", str),
    "module_description": ("2.1.1.1.0", str),
    # Status of module (1=nok, 2=ok)
    "module_status": ("4.1.3833.1.7.4.0", int),
    "mac_address": ("4.1.3833.1.7.18.0", bytes),
    "configured_ipv4_address": ("4.1.3833.1.7.15.0", str),
    "configured_ipv4_netmask": ("4.1.3833.1.7.16.0", str),
    "configured_ipv4_gateway": ("4.1.3833.1.7.17.0", str),
    # local(1), dhcpServed(2)
    "ip_config_mode": ("4.1.3833.1.7.5.0", int),
    # Number of network interfaces present in the module, regardless of state
    "num_network_interfaces": ("2.1.2.1.0", int),
    "bandwidth_management": ("4.1.3833.1.7.7.0", int),
    "communication_services": ("4.1.3833.1.7.3.0", int),
}

#: OIDs with SMTP email server configuration and status information
#: (first row of emailTable, emailIndex 0)
SNMP_SMTP_OIDS: Final[dict[str, tuple[str, type]]] = {
    "service_status": ("4.1.3833.1.9.1.1.1.2.0", int),
    "ipv4_address": ("4.1.3833.1.9.1.1.1.3.0", str),
    "mail_sent_count": ("4.1.3833.1.9.1.1.1.4.0", int),
    "error_count": ("4.1.3833.1.9.1.1.1.5.0", int),
    "last_error": ("4.1.3833.1.9.1.1.1.6.0", int),
    "last_mail_elapsed_time": ("4.1.3833.1.9.1.1.1.7.0", int),
    # 1 = nok (unreachable), 2 = ok (reachable)
    "link_service_status": ("4.1.3833.1.9.1.1.1.8.0", int),
    # The number of time that the link to the SMTP server has been detected down.
    "server_check_fail_count": ("4.1.3833.1.9.1.1.1.9.0", int),
}

#: OIDs with Port 502 service configuration and status information
SNMP_PORT_502_OIDS: Final[dict[str, tuple[str, type]]] = {
    # The protocols supported by the Port502 Messaging service:
    # modbusThroughGateway(1)         -- MODBUS protocol through UNITE Gateway
    # modbusDirect (2)                -- MODBUS direct
    # unite(4)                        -- UNITE protocol only
    # modbusThroughGatewayAndUnite(5) -- MODBUS through Gateway and UNITE protocol
    # modbusDirectAndUnite(6)         -- MODBUS direct and UNITE protocol
    "supported_protocol": ("4.1.3833.1.2.2.0", int),
    # idle(1), operationnal(2)
    "service_status": ("4.1.3833.1.2.1.0", int),
    # 1=disabled, 2=enabled
    "port_security": ("4.1.3833.1.2.3.0", int),
    "max_connections": ("4.1.3833.1.2.4.0", int),
    "total_messages_received": ("4.1.3833.1.2.9.0", int),
    "total_messages_sent": ("4.1.3833.1.2.10.0", int),
    "total_errors_sent": ("4.1.3833.1.2.11.0", int),
}

#: OIDs with Web server configuration and status information
SNMP_WEB_OIDS: Final[dict[str, tuple[str, type]]] = {
    # idle(1), operationnal(2)
    "service_status": ("4.1.3833.1.5.1.0", int),
    # 1=disabled, 2=enabled
    "password_status": ("4.1.3833.1.5.2.0", int),
    "successful_attempts": ("4.1.3833.1.5.3.0", int),
    "failed_attempts": ("4.1.3833.1.5.4.0", int),
}

#: OIDs with system-wide information
SNMP_SYSTEM_OIDS: Final[dict[str, tuple[str, type]]] = {
    # profileCPUType
    "full_model": ("4.1.3833.1.7.11.0", str),
    # SNMPv2-MIB::sysUpTime (hundredths of a second)
    "system_uptime": ("2.1.1.3.0", int),
    "implementation_class": ("4.1.3833.1.7.19.0", str),
    "firmware_version": ("4.1.3833.1.7.2.0", str),
}

#: Columns of profileLedDisplayTable (ledName, ledDescr, ledState)
SNMP_LED_OIDS: Final[dict[str, tuple[str, type]]] = {
    "name": ("4.1.3833.1.7.9.1.2", str),
    "description": ("4.1.3833.1.7.9.1.3", str),
    # on(1), off(2), blinking(3)
    "state": ("4.1.3833.1.7.9.1.4", int),
}


# TODO: what parts of this are status, and what are config?
def pull_network_config(
    ip: str,
    timeout: float = 1.0,
    snmp_community: str = "public",
    *,
    snmp_port: int = 161,
    snmp_timeout: float | None = None,
    use_snmp: bool = True,
    snmp_max_varbinds: int = m340_snmp.DEFAULT_MAX_VARBINDS,
) -> dict:
    """
    Pull configuration information using SNMP, FTP, and Modbus/TCP.

    SNMP data is pulled using the Schneider TFE private MIB
    (refer to :func:`~peat.modules.schneider.m340.m340_snmp.pull_snmp`).
    If the MIB can't be loaded (or pulling with it fails unexpectedly), a limited
    set of raw OIDs is queried instead.

    Args:
        ip: IP address of the device
        timeout: Time to wait for a service to respond, in seconds
        snmp_community: SNMPv1 Community String to use
        snmp_port: UDP port of the SNMP agent
        snmp_timeout: SNMP timeout, in seconds (if :obj:`None`, ``timeout`` is used)
        use_snmp: If SNMP should be used
        snmp_max_varbinds: Maximum number of SNMP GetNext requests per walked subtree

    Returns:
        The device configuration information. The structured SNMP data
        is in the ``snmp`` key.
    """
    log = peat_logger.bind(target=ip)
    log.debug(f"Pulling configuration using network services for Schneider device {ip}...")
    device_info = {}
    snmp_timeout = snmp_timeout if snmp_timeout else timeout

    services = ["FTP", "SNMP", "Modbus/TCP"] if use_snmp else ["FTP", "Modbus/TCP"]
    if not use_snmp:
        log.info("Skipping SNMP (the 'm340.use_snmp' option is false)")

    # Get configuration information from network sources
    for service in services:
        if service == "SNMP":
            try:
                snmp_data = m340_snmp.pull_snmp(
                    ip,
                    port=snmp_port,
                    timeout=snmp_timeout,
                    community=snmp_community,
                    max_varbinds=snmp_max_varbinds,
                )
                snmp_module, system = m340_snmp.to_legacy(snmp_data)
                device_info["snmp"] = snmp_data
            except CommError as err:  # e.g. SNMP is disabled or wrong community
                log.warning(f"Could not pull SNMP metadata: {err}")
                continue
            except Exception as err:
                if isinstance(err, m340_snmp.TfeMibUnavailableError):
                    log.warning(f"{err}. Falling back to raw-OID SNMP queries")
                else:
                    log.exception(
                        f"Failed to pull SNMP data using {m340_snmp.TFE_MIB}, "
                        f"falling back to raw-OID SNMP queries: {err}"
                    )
                try:
                    snmp_module, system = _get_snmp_metadata(
                        ip, community=snmp_community, timeout=snmp_timeout, port=snmp_port
                    )
                except CommError as fallback_err:
                    log.warning(f"Could not pull SNMP metadata: {fallback_err}")
                    continue
                except Exception as fallback_err:
                    log.exception(f"Could not pull SNMP metadata: {fallback_err}")
                    continue  # Skip to next service if there is an error

            # Add the overall system info straight into the device info
            device_info.update(system)

            # Add the information for each module to its corresponding dict
            if "slot" in snmp_module:
                module_name = f"module_{snmp_module['slot']}"  # module_<slot #>
            else:
                log.warning("SNMP agent didn't report the module slot, using 'module_snmp'")
                module_name = "module_snmp"
            if module_name in device_info:
                # If module exists, add the info
                device_info[module_name].update(snmp_module)
            else:
                # If it doesn't, create it using the info
                device_info[module_name] = snmp_module
        elif service == "FTP":
            try:
                # Pull and parse data from service
                ftp_info = _get_ftp_metadata(ip, timeout=timeout)
            except Exception as err:
                log.exception(f"Could not pull FTP metadata: {err}")
                continue  # Skip to next service if there is an error

            # Merge the FTP info into overall device info
            for index, ftp_value in ftp_info.items():
                # TODO: check slot number
                found_device = False
                if isinstance(ftp_value, dict) and "device" in ftp_value:
                    for j, info_value in device_info.items():
                        if (
                            isinstance(info_value, dict)
                            and info_value.get("model_name") == ftp_value["device"]
                        ):
                            # Check if MAC address found via FTP differs
                            if (
                                "mac_address" in info_value
                                and "mac_address" in ftp_value
                                and info_value["mac_address"] != ftp_value["mac_address"]
                            ):
                                log.warning(
                                    f"Conflicting MAC addresses found for "
                                    f"module {j!s} in device {ip}"
                                )
                                device_info[j]["conflicted_mac_address"] = info_value[
                                    "mac_address"
                                ]

                            # Merge the module dicts
                            info_value.update(ftp_value)
                            found_device = True
                            break

                    if not found_device:
                        device_info[index] = ftp_value  # For things without a module
                else:  # Non-devices (e.g Loader status)
                    device_info[index] = ftp_value
        elif service == "Modbus/TCP":
            try:
                # Pull data from service and add to info
                device_info.update(_get_modbus_metadata(ip, timeout=timeout))
            except Exception as ex:
                log.error(f"Could not pull Modbus/TCP metadata. Error: {ex}")
                continue  # Skip to next service if there is an error
        else:
            log.error(f"Unknown service for device {ip}: {service!s}")

    log.debug(
        f"Finished pulling configuration using network services for Schneider device {ip}",
    )
    return device_info


def _get_snmp_metadata(
    ip: str,
    community: str = "public",
    timeout: float = 0.5,
    max_failures: int = 7,
    port: int = 161,
) -> tuple[dict, dict]:
    """
    Gets device metadata over SNMP by querying raw OIDs.

    .. note::
       This is a fallback for when the Schneider TFE private MIB can't be loaded.
       The MIB-based method,
       :func:`~peat.modules.schneider.m340.m340_snmp.pull_snmp`, gets much more data.

    Args:
        ip: IPv4 address of the device
        community: SNMP Community string to use
        timeout: SNMP protocol timeout, in seconds
        max_failures: max number of failed requests before raising an exception
        port: UDP port of the SNMP agent

    Returns:
        Info for the module hosting SNMP and the overall system, respectively
    """
    log = peat_logger.bind(target=ip)
    log.info(f"Pulling configuration information for device {ip} over SNMP (raw OIDs)...")
    module_info: dict[str, Any] = {}
    system_info: dict[str, Any] = {}

    def _query(oid_pair: tuple[str, type]) -> Any:
        response = snmp.get(f"1.3.6.1.{oid_pair[0]}")
        if not response:
            return None
        try:
            if oid_pair[1] is str:
                return str(response[0]["value_string"]).strip()
            # NOTE: "value_encoded" is the raw int or bytes value
            return oid_pair[1](response[0]["value_encoded"])
        except (TypeError, ValueError) as ex:
            log.debug(f"Bad SNMP value for OID {oid_pair[0]}: {ex}")
            return None

    # Create SNMP object to use for pulling data
    snmp = SNMP(ip=ip, port=port, timeout=timeout, community=community)
    num_failures = 0

    # Pull information for the module running the SNMP server
    log.debug("Pulling SNMP device modules info...")
    for name, oid_pair in SNMP_MODULE_OIDS.items():
        data = _query(oid_pair)
        if data is None:
            num_failures += 1
            if num_failures >= max_failures:
                raise CommError(
                    f"Number of failed SNMP query attempts exceeded max of {max_failures}"
                )
            continue

        if data in ("", b""):
            continue
        if name == "mac_address":
            # PhysAddress, raw bytes
            if len(data) == 6:
                module_info[name] = ":".join(f"{b:02X}" for b in data)
        elif name == "module_status":
            module_info[name] = "ok" if data == 2 else "nok"
        elif name == "ip_config_mode":
            module_info[name] = {1: "local", 2: "dhcpServed"}.get(data, data)
        elif name == "bandwidth_management":
            module_info[name] = "enabled" if data == 2 else "disabled"
        elif name == "communication_services":
            # b0 (least significant bit) = Port502Messaging, ..., b6 = email
            module_info[name] = {
                "port_502_messaging" if k == "port502_messaging" else k: (
                    "supported" if supported else "unsupported"
                )
                for k, supported in m340_snmp.decode_comm_services(data).items()
            }
        else:
            module_info[name] = data

    # Pull SMTP email server information for the module
    smtp_info: dict[str, Any] = {}
    log.debug("Pulling SNMP email server info...")
    for name, oid_pair in SNMP_SMTP_OIDS.items():
        data = _query(oid_pair)
        if data is None or data == "":
            continue
        if name == "link_service_status":
            smtp_info[name] = "reachable" if data == 2 else "unreachable"
        elif name == "service_status":
            if data == 1:
                smtp_info[name] = "no configuration"
            elif data == 2:
                smtp_info[name] = "operational and running"
            else:
                smtp_info[name] = "stopped"
        else:
            smtp_info[name] = data
    if smtp_info:
        module_info["smtp_server"] = smtp_info

    # Pull Port 502 service information for the module
    supp_protos = {
        1: "modbusThroughGateway",
        2: "modbusDirect",
        # Don't ask me what 3 is...it's like Station 9-3/4
        4: "unite",
        5: "modbusThroughGatewayAndUnite",
        6: "modbusDirectAndUnite",
    }
    port_502_info: dict[str, Any] = {}
    log.debug("Pulling SNMP Port502 info...")
    for name, oid_pair in SNMP_PORT_502_OIDS.items():
        data = _query(oid_pair)
        if data is None:
            continue
        if name == "port_security":
            port_502_info[name] = "enabled" if data == 2 else "disabled"
        elif name == "supported_protocol":
            port_502_info[name] = supp_protos.get(data, data)
        elif name == "service_status":
            port_502_info[name] = "operational" if data == 2 else "no configuration"
        else:
            port_502_info[name] = data
    if port_502_info:
        module_info["port_502"] = port_502_info

    # Pull Web server info
    web_info: dict[str, Any] = {}
    log.debug("Pulling SNMP web server info...")
    for name, oid_pair in SNMP_WEB_OIDS.items():
        data = _query(oid_pair)
        if data is None:
            continue
        if name == "password_status":
            web_info[name] = "enabled" if data == 2 else "disabled"
        elif name == "service_status":
            web_info[name] = "operational" if data == 2 else "no configuration"
        else:
            web_info[name] = data
    if web_info:
        module_info["web_server"] = web_info

    # Get information on LEDs on the module and their state,
    # by walking each column of profileLedDisplayTable.
    led_info: dict[str, list] = {}
    log.debug("Pulling SNMP LED info...")
    for name, oid_pair in SNMP_LED_OIDS.items():
        responses = snmp.walk(f"1.3.6.1.{oid_pair[0]}", max_varbinds=64)
        if oid_pair[1] is str:
            led_info[name] = [str(x["value_string"]).strip() for x in responses]
        else:
            led_info[name] = [x["value_encoded"] for x in responses]
    for i, (led_name, led_descr, led_state) in enumerate(
        zip(led_info["name"], led_info["description"], led_info["state"], strict=False)
    ):
        module_info[f"led_{i}"] = {
            "name": led_name,
            "description": led_descr,
            "state": led_state,
        }

    # Pull information for the overall system
    log.debug("Pulling SNMP overall system info...")
    for name, oid_pair in SNMP_SYSTEM_OIDS.items():
        data = _query(oid_pair)
        if data is not None and data != "":
            system_info[name] = data

    return module_info, system_info


def _get_ftp_metadata(
    ip: str,
    user: str = "loader",
    passwd: str = "fwdownload",
    port: int = 21,
    timeout: float = 5.0,
) -> dict:
    """
    Gets as much device metadata as possible over FTP.

    Args:
        ip: IPv4 address of the device
        user: FTP username
        passwd: FTP password
        port: TCP port for FTP service
        timeout: Number of seconds to wait before timing out

    Returns:
        The information found, or empty :class:`dict` if no info was found
    """
    log = peat_logger.bind(target=f"{ip}:{port}")
    log.info(f"Pulling configuration information for {ip}:{port} via FTP...")

    try:
        with FTP(ip, port, timeout) as ftp:
            if not ftp.login(user, passwd):
                log.error(f"Failed FTP login on {ip}:{port}")
                return {}

            ldst_data = ftp.cmd("LDST")
            dinf_data = ftp.cmd("DINF")
            sd_data = ftp.cmd("FREE")
    except Exception as ex:
        log.error(f"Failed to pull FTP data from {ip}: {ex}")
        return {}

    device_info = {}

    # ** Loader status (LDST) **
    loader_status = {}
    ldst_data = ldst_data.split("\n")[1]  # Remove "200" lines
    ldst_data = ldst_data.replace(" ", "").split(",")  # Clean spaces and split
    for pair in ldst_data:
        split = pair.split("=")
        loader_status[utils.convert_to_snake_case(split[0])] = split[1]
    device_info["loader_status"] = loader_status

    # ** Device info (DINF) **
    # Each module is defined by: FwLoc, HwId, FwId, Device, Ir, Desc, Date, MAC
    # Split, Remove "200" lines, recombine
    dinf_data = "".join(dinf_data.split("\n")[1:-1])
    module_number = 0
    next_str, parted, curr_str = dinf_data.rpartition("FwLoc=")
    while "FwLoc=" in parted:
        # Split into key-values, remove trailing whitespace and single quotes
        module_data = [x.strip().replace("'", "") for x in curr_str.split(",")]

        # Remove empty strings
        module_data = list(filter(None, module_data))
        module_info = {}
        module_tag = "device_" + str(module_number)

        # Get the metadata from the key-value pairs
        module_info["fw_loc"] = module_data[0]

        for pair in module_data[1:]:
            split = pair.split("=")

            if split[0] == "Desc":
                key = "description"
            elif split[0] == "HwId":
                key = "hardware_id"
            else:
                key = utils.convert_to_snake_case(split[0])

            if key == "ir":
                module_info[key] = int(split[1])
            # TODO: is "Date" the manufacture date or firmware flash date?
            elif key == "date":
                module_info["timestamp"] = split[1].replace("#dt", "")
            elif key == "mac":
                module_info["mac_address"] = split[1].replace("-", ":")
            else:
                module_info[key] = split[1]

        # Save the module info
        device_info[module_tag] = module_info

        # Move to the next section (next module)
        next_str, parted, curr_str = next_str.rpartition("FwLoc=")
        module_number += 1

    # ** Free space on the SD card (FREE) **
    device_info["free_space_sd_card"] = int(sd_data.split("=")[-1].strip())

    return device_info


def _get_modbus_metadata(ip: str, timeout: float = 5.0, port: int = 502) -> dict:
    """
    Gets as much device metadata as possible over Modbus/TCP.

    Args:
        ip: IPv4 address of the device
        timeout: Number of seconds to wait before timing out
        port: TCP port of the Modbus service

    Returns:
        The information found, or empty :class:`dict` if none was found
    """
    log = peat_logger.bind(target=f"{ip}:{port}")
    log.info(f"Pulling configuration information from {ip} over Modbus/TCP...")

    # TODO: put socket in a with statement
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((ip, port))
    except OSError as err:
        log.error(f"Failed to pull Modbus metadata from {ip}: {err}")
        sock.close()
        return {}

    device_info = {}

    # Get the memory card model
    # Source: github.com/digitalbond/Redpoint/blob/master/modicon-info.nse
    # TODO: is there more information from this?
    payload = binascii.unhexlify("01bf00000005005a000606")
    response = send_umas_packet(sock, payload, UMASResponse)
    device_info["memory_card_model"] = bytes(response.payload)[3:-1].decode()

    sock.close()
    log.debug(f"Metadata found over Modbus for device {ip}: {device_info!s}")

    return device_info
