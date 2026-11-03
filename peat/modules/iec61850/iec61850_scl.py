"""
PEAT module to parse IEC 61850-6 System Configuration description Language (SCL)
files from engineering archives and IED configuration tools.

Supported SCL file types

- ``SCD`` (Substation Configuration Description): every IED of the substation
- ``ICD``/``IID``/``CID`` (IED Capability/Instantiated IED/Configured IED Description)
- ``SED`` (System Exchange Description) and ``SSD`` (System Specification
  Description); an SSD without IEDs produces no device

One device is produced **per IED** in the file. For each IED, PEAT reads the
IEC 61850 configuration summary (:attr:`~peat.data.models.DeviceData.iec61850`:
SCL header and history, IED identity, access points and addresses, logical
devices, GOOSE/SV/report control blocks with MAC/APPID/VLAN, subscriptions)
and derives network interfaces, services (``mms``, ``goose``, ``sv``) and
relationships (``publishes_to``, ``subscribes_to``, ``reports_to``). Configuration
problems (duplicate or out-of-range APPIDs, invalid address values) are reported
as ``scl-validation`` alert events. See :mod:`peat.parsing.scl` for the details.

Files are claimed by their extension (``.scd``, ``.icd``, ``.iid``, ``.ssd``,
``.sed``) or by their content: a plain-XML document whose root element is the
SCL element (this also catches plain-XML ``.cid`` exports). zlib-compressed SEL
``SET_61850.CID`` files are handled by
:class:`~peat.modules.sel.sel_relay.SELRelay`.

.. note::
   SCL files are not validated against the IEC XSD schemas (they are not
   distributed with PEAT). IPv6 addresses are not modeled.

Usage examples

.. code-block:: bash

   peat parse -d IEC61850SCL -- substation.scd
   peat parse -d scl -- ./engineering_archive/
"""

from pathlib import Path
from typing import BinaryIO

from lxml import etree

from peat import IEC61850, DeviceData, DeviceModule, File, ParseError, config, datastore
from peat.file_signature import FileSignature
from peat.parsing import scl
from peat.protocols.addresses import address_to_pathname

SCL_ROOT_TAG = f"{{{scl.SCL_NAMESPACE}}}SCL"


def is_plain_xml_scl(data: BinaryIO) -> bool:
    """
    File signature check: the ROOT element is the SCL element (in the SCL
    namespace). Only the start of the document is read. Compressed data
    (e.g. SEL zlib CIDs) never matches.
    """
    try:
        for _event, elem in etree.iterparse(
            data,
            events=("start",),
            resolve_entities=False,
            no_network=True,
            load_dtd=False,
            huge_tree=False,
        ):
            return elem.tag == SCL_ROOT_TAG
    except Exception:
        return False
    return False


class IEC61850SCL(DeviceModule):
    """
    Parse IEC 61850 SCL files (SCD/ICD/IID/CID/SSD/SED) from engineering archives.

    Produces one device per IED in the file: the first IED is returned, every
    other IED is added to the datastore (and exported, if file output is enabled).
    """

    device_type = "IED"
    vendor_id = ""  # per IED: description.vendor.name = IED@manufacturer
    vendor_name = ""
    # NO "*.cid": patterns match case-insensitively and would also claim SEL zlib
    # CIDs; plain-XML CIDs are claimed by the signature below.
    filename_patterns = ["*.scd", "*.icd", "*.iid", "*.ssd", "*.sed"]
    file_signatures = [
        FileSignature(
            default_filename="iec61850.scd",
            custom_check=is_plain_xml_scl,  # root element is SCL (plain XML only)
        )
    ]
    module_aliases = ["iec61850", "scl", "scd", "cid", "icd"]

    @classmethod
    def _parse(cls, file: Path, dev: DeviceData | None = None) -> DeviceData | None:
        data = file.read_bytes()
        try:
            root = scl.load_scl(data)
        except ParseError as ex:
            cls.log.warning(f"'{file.name}' is not a valid SCL file: {ex}")
            return None
        # Not guessed from the extension (".scd" is a Scribus document to mimetypes).
        # A zlib-compressed SEL CID (0x78 header) is only parsed here if forced.
        mime_type = "application/zlib" if data[:1] == b"\x78" else "application/xml"
        ieds = scl.parse_scl_all(root, scl.file_type_from_name(file))
        if not ieds:
            cls.log.warning(
                f"No IEDs found in SCL file '{file.name}' (an SSD describes the "
                f"substation, not IEDs), no device data was produced"
            )
            return None

        main_dev: DeviceData | None = None
        devices: dict[str, DeviceData] = {}
        claimed: set[int] = set()  # id() of the devices of the IEDs of this file
        for name, ied in ieds.items():
            # One bad IED never loses the others
            created = False
            ied_dev = None
            try:
                if main_dev is None and dev is not None:
                    ied_dev = dev
                else:
                    ied_dev, created = cls._ied_device(ied, file, claimed)
                cls._populate_ied(ied_dev, ied, file, mime_type)
            except Exception as ex:
                cls.log.warning(f"Failed to process IED '{name}' from '{file.name}': {ex}")
                if created and ied_dev is not None:
                    datastore.remove(ied_dev)  # don't leave a half-filled new device behind
                continue
            devices[name] = ied_dev
            claimed.add(id(ied_dev))
            if main_dev is None:
                main_dev = ied_dev

        if main_dev is None:
            cls.log.error(f"Failed to process all IEDs in SCL file '{file.name}'")
            return None

        # Duplicate APPIDs across the IEDs of the file (same VLAN)
        for event in scl.scl_cross_ied_events(ieds):
            for name in event.extra.get("ied_names", []):
                if name in devices:
                    devices[name].store("event", event.copy(deep=True))

        # The returned device is annotated and exported by DeviceModule.parse()
        for ied_dev in {id(d): d for d in devices.values()}.values():
            if ied_dev is main_dev:
                continue
            cls.update_dev(ied_dev)
            ied_dev.purge_duplicates(force=True)
            if config.DEVICE_DIR:
                ied_dev.export_to_files()

        cls.log.info(
            f"Parsed {len(devices)} of {len(ieds)} IEDs from SCL file '{file.name}': "
            f"{', '.join(devices)}"
        )
        return main_dev

    @staticmethod
    def _identity_ip(ied: IEC61850) -> str:
        """
        The IP address that identifies the IED: the first access point IP that is
        not a placeholder (``0.0.0.0``). ``TEMPLATE`` IEDs (ICD files) have none:
        their addresses are defaults, not the address of a device.
        """
        if ied.ied_name.upper() == "TEMPLATE":
            return ""
        return next(
            (ap.ip for ap in ied.access_points if ap.ip and ap.ip not in scl.UNSPECIFIED_IPS),
            "",
        )

    @classmethod
    def _ied_device(
        cls, ied: IEC61850, file: Path, claimed: set[int] | None = None
    ) -> tuple[DeviceData, bool]:
        """
        Existing device for the IED, else a new one.

        Lookup order:

        1. the device of the same IED from the same SCL file (file parsed again)
        2. a device with the IED name (``name`` or ``iec61850.ied_name``)
        3. a device with the IP address of the IED

        A device already used by another IED of the same file is never reused.
        A device found by name or IP is only reused if it has no IED name yet or
        the same IED name, no other IP address and no other manufacturer (e.g.
        the IEDs of two substations with the same IED names are different
        devices). ``TEMPLATE`` (the IED name of every ICD file, IEC 61850-6)
        only matches a device parsed from the same file.

        A new device is named after the IED. A ``TEMPLATE`` IED, or an IED
        without an IP address of its own whose name another device already has,
        is named ``<IED name>@<file stem>`` (``-2``, ``-3``, ... is appended if
        needed): every device keeps its own ID and output directory.

        Returns:
            The device, and if it was created
        """
        claimed = claimed or set()
        file_path = file.as_posix()
        template = ied.ied_name.upper() == "TEMPLATE"
        ip = cls._identity_ip(ied)

        def _usable(candidate: DeviceData | None) -> bool:
            if candidate is None or id(candidate) in claimed:
                return False
            name = candidate.iec61850.ied_name
            if name and name != ied.ied_name:
                return False
            known_ips = {candidate.ip, *(i.ip for i in candidate.interface)} - {""}
            if ip and known_ips and ip not in known_ips:
                return False
            manufacturer = candidate.iec61850.manufacturer
            return not (ied.manufacturer and manufacturer and manufacturer != ied.manufacturer)

        # 1. Same IED in the same file (parsed again)
        found = next(
            (
                d
                for d in datastore.objects
                if d.iec61850.ied_name == ied.ied_name
                and d.iec61850.scl_file == file_path
                and id(d) not in claimed
            ),
            None,
        )
        # 2. By IED name
        if found is None and not template and ied.ied_name:
            found = next(
                (
                    d
                    for d in datastore.objects
                    if ied.ied_name in (d.name, d.iec61850.ied_name) and _usable(d)
                ),
                None,
            )
        # 3. By IP address
        if found is None and ip:
            candidate = datastore.search(ip, "ip")
            if _usable(candidate):
                found = candidate
        if found is not None:
            return found, False

        name = ied.ied_name
        taken = {address_to_pathname(d.name) for d in datastore.objects if d.name}
        if template or (address_to_pathname(name) in taken and not cls._ip_available(ip)):
            base = f"{ied.ied_name}@{file.stem}"
            name = base
            number = 2
            while address_to_pathname(name) in taken:
                name = f"{base}-{number}"
                number += 1
        return datastore.create(name, "name"), True

    @staticmethod
    def _ip_available(ip: str, dev: DeviceData | None = None) -> bool:
        """If ``ip`` can be the IP of ``dev``: no other device has it."""
        if not ip:
            return False
        other = datastore.search(ip, "ip")
        return other is None or other is dev

    @classmethod
    def _populate_ied(cls, dev: DeviceData, ied: IEC61850, file: Path, mime_type: str) -> None:
        ied.scl_file = file.as_posix()
        if not dev.name:
            dev.name = ied.ied_name
        if ied.manufacturer and not dev.description.vendor.name:
            dev.description.vendor.name = ied.manufacturer
        if ied.ied_type and not dev.description.model:
            dev.description.model = ied.ied_type
        if ied.description and not dev.description.description:
            dev.description.description = ied.description

        # dev.ip is the identity of the device (de-duplication merges devices with
        # the same IP): only set it to an IP that no other device has. Placeholder
        # (0.0.0.0) and TEMPLATE addresses, and an IP shared by several IEDs, stay
        # in iec61850.access_points (and in the interfaces of the IED).
        ip = cls._identity_ip(ied)
        identity_ok = cls._ip_available(ip, dev)
        if identity_ok and not dev.ip:
            dev.ip = ip
        ip_before, id_before = dev.ip, dev.id
        scl.apply_iec61850(dev, ied)
        if not identity_ok:  # store("interface") copies the first interface IP to dev.ip
            dev.ip, dev.id = ip_before, id_before

        dev.store(
            "files",
            File(local_path=file, mime_type=mime_type, category={"configuration", "iec61850"}),
        )


__all__ = ["IEC61850SCL"]
