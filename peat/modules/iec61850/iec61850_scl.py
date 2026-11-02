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
        try:
            root = scl.load_scl(file)
        except ParseError as ex:
            cls.log.warning(f"'{file.name}' is not a valid SCL file: {ex}")
            return None
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
                cls._populate_ied(ied_dev, ied, file)
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
    def _ied_device(
        ied: IEC61850, file: Path, claimed: set[int] | None = None
    ) -> tuple[DeviceData, bool]:
        """
        Existing device for the IED (by name, then by IP), else a new one.

        A device already used by another IED of the same file is never reused.
        ``TEMPLATE`` (the IED name of every ICD file, IEC 61850-6) is not looked
        up by name, and only matches a ``TEMPLATE`` device parsed from the same
        file. A device found by IP is only reused if it has no IED name yet or
        the same IED name.

        Returns:
            The device, and if it was created
        """
        claimed = claimed or set()
        file_path = file.as_posix()
        template = ied.ied_name.upper() == "TEMPLATE"

        def _usable(candidate: DeviceData | None) -> bool:
            if candidate is None or id(candidate) in claimed:
                return False
            name = candidate.iec61850.ied_name
            return not name or (
                name == ied.ied_name and (not template or candidate.iec61850.scl_file == file_path)
            )

        if template:
            # Same ICD file parsed again
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
        elif ied.ied_name:
            found = datastore.search(ied.ied_name, "name")
            if found is not None and id(found) in claimed:
                found = None
        else:
            found = None
        ip = next((ap.ip for ap in ied.access_points if ap.ip), "")
        if found is None and ip:
            candidate = datastore.search(ip, "ip")
            if _usable(candidate):
                found = candidate
        if found is not None:
            return found, False
        return datastore.create(ied.ied_name, "name"), True

    @staticmethod
    def _populate_ied(dev: DeviceData, ied: IEC61850, file: Path) -> None:
        ied.scl_file = file.as_posix()
        if not dev.name:
            dev.name = ied.ied_name
        if ied.manufacturer and not dev.description.vendor.name:
            dev.description.vendor.name = ied.manufacturer
        if ied.ied_type and not dev.description.model:
            dev.description.model = ied.ied_type
        if ied.description and not dev.description.description:
            dev.description.description = ied.description
        ip = next((ap.ip for ap in ied.access_points if ap.ip), "")
        if ip and not dev.ip:
            dev.ip = ip

        scl.apply_iec61850(dev, ied)
        dev.store("files", File(local_path=file, category={"configuration", "iec61850"}))


__all__ = ["IEC61850SCL"]
