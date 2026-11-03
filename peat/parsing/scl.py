"""
Parser for IEC 61850-6 System Configuration description Language (SCL) files:
``SSD``, ``SCD``, ``ICD``, ``IID``, ``CID`` and ``SED``.

The IEC 61850 communication configuration of each IED is read into a
:class:`~peat.data.models.IEC61850` summary (:func:`parse_scl`,
:func:`parse_scl_all`), and :func:`apply_iec61850` stores it on a
:class:`~peat.data.models.DeviceData` together with the network interfaces,
services (``mms``, ``goose``, ``sv``), relationships (``publishes_to``,
``subscribes_to``, ``reports_to``) and configuration alerts derived from it.

Notes

- Parsing uses :mod:`lxml` with a hardened parser: no DTD loading, no entity
  expansion, no network access, no huge trees. Documents that declare entities
  or reference an external DTD are rejected with :class:`~peat.consts.ParseError`
  (SCL files never use DTDs).
- No XSD validation is performed (the IEC schema files are not distributed with
  PEAT). Elements are matched by their **local name**, so files with the SCL
  namespace (``http://www.iec.ch/61850/2003/SCL``), with vendor ``Private``
  namespaces, or without any namespace all work.
- ``APPID`` and ``VLAN-ID`` address values are **hexadecimal** in SCL
  (``"064"`` is VLAN 100, ``"1000"`` is APPID 4096). ``VLAN-PRIORITY`` is decimal.
- Every address value (``MAC-Address``, ``APPID``, ``VLAN-ID``, ``VLAN-PRIORITY``,
  ``IP``, ``IP-SUBNET``, ``IP-GATEWAY``, ``MMS-Port``) is validated on its own.
  An invalid value is left unset, recorded in
  ``IEC61850.extra["invalid_addresses"]``, logged as a warning and reported as an
  ``scl-validation`` alert by :func:`scl_configuration_events`. It never aborts
  the parse.
- IPv6 addresses (``P type="IPv6"``), ``DataTypeTemplates``, ``DOI``/``DAI``
  values, ``LogControl`` and ``Private`` elements are not modeled.
"""

from __future__ import annotations

import zlib
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path, PurePath

from lxml import etree
from pydantic import ValidationError

from peat import ParseError, log
from peat.data.data_utils import merge_models
from peat.data.models import (
    IEC61850,
    DeviceData,
    Event,
    IEC61850AccessPoint,
    IEC61850Address,
    IEC61850Header,
    IEC61850HistoryItem,
    IEC61850LogicalDevice,
    IEC61850Publication,
    IEC61850ReportControl,
    IEC61850Subscription,
    Interface,
    Relationship,
    RelationshipEndpoint,
    Service,
    ServiceSecurity,
    Vlan,
)

SCL_NAMESPACE = "http://www.iec.ch/61850/2003/SCL"
"""XML namespace of SCL documents (all editions)."""

SCL_FILE_TYPES = ("SSD", "SCD", "ICD", "IID", "CID", "SED")
"""SCL file types (file extensions), see :func:`file_type_from_name`."""

DEFAULT_MMS_PORT = 102
"""MMS (ISO-TSAP over TCP) port used when the SCL has no ``MMS-Port``."""

APPID_RANGES = {"GOOSE": (0x0000, 0x3FFF), "GSSE": (0x0000, 0x3FFF), "SV": (0x4000, 0x7FFF)}
"""IEC 61850-8-1 / 9-2 APPID ranges (control block type -> (min, max))."""

MAX_DECOMPRESSED_SIZE = 256 * 1024 * 1024
"""Upper limit for the size of decompressed zlib-wrapped SCL (256 MiB)."""

UNSPECIFIED_IPS = ("0.0.0.0", "::")
"""
Placeholder addresses: an access point ``IP`` that is not configured, or an
``IP-GATEWAY`` meaning "no gateway". Never used as an interface, gateway or
device address.
"""

# Name of the control block attribute that references its DataSet
_DATSET = "datSet"


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #
def _parser() -> etree.XMLParser:
    # No DTDs, no entity expansion, no network, no huge trees (XXE / billion laughs safe)
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        huge_tree=False,
        remove_comments=True,
        remove_pis=True,
    )


def decode_scl_bytes(data: bytes) -> bytes:
    """
    Decompress zlib-wrapped SCL (SEL ``SET_61850.CID``) and strip a UTF-8 BOM.

    Data that starts with ``0x78`` (zlib header) but fails to decompress is
    returned unchanged (minus a BOM).

    Raises:
        ParseError: the decompressed data is larger than
            :data:`MAX_DECOMPRESSED_SIZE`
    """
    data = bytes(data)
    if data[:1] == b"\x78":
        decompressor = zlib.decompressobj()
        try:
            decompressed = decompressor.decompress(data, MAX_DECOMPRESSED_SIZE)
        except zlib.error:
            decompressed = None
        if decompressed is not None:
            if decompressor.unconsumed_tail:
                raise ParseError(f"decompressed SCL is larger than {MAX_DECOMPRESSED_SIZE} bytes")
            data = decompressed
    return data.removeprefix(b"\xef\xbb\xbf")


def load_scl(source: bytes | str | Path) -> etree._Element:
    """
    Parse an SCL document with a hardened XML parser.

    Args:
        source: Raw bytes (plain or zlib-compressed), XML text (:class:`str`),
            or the :class:`~pathlib.Path` of a file

    Returns:
        The root ``SCL`` element

    Raises:
        ParseError: The data is not well-formed XML, the root element is not
            ``SCL``, or the document declares entities or references an external
            DTD (XXE)
    """
    if isinstance(source, PurePath):
        data = Path(source).read_bytes()
    elif isinstance(source, str):
        data = source.encode("utf-8")
    else:
        data = source

    try:
        root = etree.fromstring(decode_scl_bytes(data), parser=_parser())
    except etree.XMLSyntaxError as ex:
        raise ParseError(f"invalid SCL XML: {ex}") from None

    # Entities are never expanded by the parser, but SCL documents never use
    # DTDs: reject entity declarations and external DTDs outright (XXE).
    docinfo = root.getroottree().docinfo
    dtd = docinfo.internalDTD
    if (
        docinfo.system_url
        or docinfo.public_id
        or (dtd is not None and next(iter(dtd.iterentities()), None) is not None)
    ):
        raise ParseError("SCL document declares entities or an external DTD (rejected)")

    if _ln(root) != "SCL":
        raise ParseError(f"root element is '{_ln(root)}', expected 'SCL'")
    return root


def is_scl(data: bytes | str | Path) -> bool:
    """
    If ``data`` (plain or zlib-compressed bytes, XML text, or a file
    :class:`~pathlib.Path`) is an SCL document.
    """
    try:
        load_scl(data if isinstance(data, (bytes, str, PurePath)) else bytes(data))
        return True
    except Exception:
        return False


def file_type_from_name(name: str | PurePath) -> str:
    """
    SCL file type from a file name: ``"SET_61850.CID"`` -> ``"CID"``.

    Returns:
        One of :data:`SCL_FILE_TYPES`, or ``""`` for other extensions
    """
    ext = PurePath(str(name)).suffix.lstrip(".").upper()
    return ext if ext in SCL_FILE_TYPES else ""


# --------------------------------------------------------------------------- #
# Small XML helpers (namespace-agnostic)
# --------------------------------------------------------------------------- #
def _ln(el) -> str:
    """Local name of an element (``""`` for comments and processing instructions)."""
    return etree.QName(el).localname if isinstance(el.tag, str) else ""


def _kids(el, name: str) -> list:
    if el is None:
        return []
    return [c for c in el if _ln(c) == name]


def _kid(el, name: str):
    found = _kids(el, name)
    return found[0] if found else None


def _desc(el, name: str) -> list:
    return [c for c in el.iter() if _ln(c) == name]


def _attrs(el) -> dict[str, str]:
    """Attributes of an element with namespace prefixes removed from the names."""
    return {etree.QName(k).localname: v for k, v in el.attrib.items()}


def _bool(value: str | None, default: bool | None = None) -> bool | None:
    if value is None:
        return default
    return value.strip().lower() in ("true", "1")


# Largest xs:unsignedInt (SCL confRev, smpRate, nofASDU, bufTime, intgPd, ...)
UINT32_MAX = 0xFFFFFFFF


def _int(value: str | None, base: int = 10) -> int | None:
    try:
        return int(str(value).strip(), base) if value not in (None, "") else None
    except ValueError:
        return None


def _uint(value: str | None) -> int | None:
    """
    ``xs:unsignedInt`` (0 to :data:`UINT32_MAX`), else :obj:`None` (malformed
    values never abort the parse, and out-of-range values never reach Elasticsearch).
    """
    result = _int(value)
    return result if result is not None and 0 <= result <= UINT32_MAX else None


def _p_values(address_el) -> dict[str, str]:
    """``<Address><P type="X">v</P>`` -> ``{"X": "v"}``."""
    if address_el is None:
        return {}
    return {p.get("type", ""): (p.text or "").strip() for p in _kids(address_el, "P")}


def _record_problem(
    problems: list[dict], where_key: str, where: str, parameter: str, value: str, error: object
) -> None:
    """Record an invalid address value (ECS-4): it is reported, never fatal."""
    problems.append(
        {
            where_key: where,
            "parameter": parameter,
            "value": value,
            "error": str(error)[:200],
        }
    )
    log.warning(f"Invalid SCL address value {parameter}={value!r} for {where}")


def _l2_address(container_el, problems: list[dict], context: str) -> IEC61850Address:
    """
    ``GSE``/``SMV`` element -> :class:`~peat.data.models.IEC61850Address`
    (``APPID`` and ``VLAN-ID`` are HEX). Each value is validated on its own: an
    invalid value is left unset and recorded in ``problems`` (raw value kept).
    """
    p = _p_values(_kid(container_el, "Address"))
    addr = IEC61850Address()

    def try_set(parameter: str, field: str, make: Callable[[str], object]) -> None:
        raw = p.get(parameter)
        if raw in (None, ""):
            return
        try:
            setattr(addr, field, make(raw))
        except (ValueError, ValidationError) as ex:
            _record_problem(problems, "control_block", context, parameter, raw, ex)

    try_set("MAC-Address", "mac", lambda v: v)
    try_set("APPID", "appid", lambda v: int(v, 16))
    try_set("VLAN-ID", "vlan", lambda v: Vlan.from_hex(v, None, tagged=True))
    try_set(
        "VLAN-PRIORITY",
        "vlan",
        lambda v: Vlan(id=addr.vlan.id, tagged=addr.vlan.tagged, priority=int(v)),
    )
    return addr


def _ms(el) -> int | None:
    """
    ``MinTime``/``MaxTime`` -> ms. ``tDurationInMilliSec`` (``xs:decimal``, unit
    ``s``, multiplier fixed to ``m``): the value is already in ms; decimals are rounded.
    """
    if el is None or not (el.text or "").strip():
        return None
    try:
        value = round(float(el.text.strip()))
    except (ValueError, OverflowError):
        return None
    return value if 0 <= value <= UINT32_MAX else None


def ln_name(ln_el) -> str:
    """Logical node name: ``LLN0`` for ``LN0``, else ``prefix + lnClass + inst``."""
    if _ln(ln_el) == "LN0":
        return "LLN0"
    return f"{ln_el.get('prefix', '')}{ln_el.get('lnClass', '')}{ln_el.get('inst', '')}"


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def list_ieds(root) -> list[str]:
    """Names of the IEDs in the SCL document, in document order."""
    return [ied.get("name", "") for ied in _kids(root, "IED") if ied.get("name")]


def _norm_file_type(file_type: str) -> str:
    value = (file_type or "").strip().upper()
    return value if value in SCL_FILE_TYPES else ""


def _header(root, file_type: str) -> IEC61850Header:
    hdr = _kid(root, "Header")
    version = "".join(root.get(a, "") for a in ("version", "revision", "release")) or "2003"
    header = IEC61850Header(file_type=file_type, scl_version=version)
    if hdr is not None:
        header.id = hdr.get("id", "")
        header.version = hdr.get("version", "")
        header.revision = hdr.get("revision", "")
        header.tool_id = hdr.get("toolID", "")
        header.name_structure = hdr.get("nameStructure", "")
        header.history = [
            IEC61850HistoryItem(
                **{k: h.get(k, "") for k in ("version", "revision", "when", "who", "what", "why")}
            )
            for h in _kids(_kid(hdr, "History"), "Hitem")
        ]
    return header


def _publication_references(root) -> dict[tuple[str, str, str, str], str]:
    """
    ``(kind GO|GS|MS|US|RP|BR, iedName, ldInst, cbName)`` -> control block
    reference, for every IED in the document.
    """
    refs = {}
    for ied_el in _kids(root, "IED"):
        ied_name = ied_el.get("name", "")
        for ap_el in _kids(ied_el, "AccessPoint"):
            for ld_el in _kids(_kid(ap_el, "Server"), "LDevice"):
                inst = ld_el.get("inst", "")
                ld_name = ld_el.get("ldName") or f"{ied_name}{inst}"
                for ln in ld_el:
                    if _ln(ln) not in ("LN0", "LN"):
                        continue
                    for cb in ln:
                        tag, cb_name = _ln(cb), cb.get("name", "")
                        if tag == "GSEControl":
                            kind = (
                                "GS" if (cb.get("type") or "").strip().upper() == "GSSE" else "GO"
                            )
                        elif tag == "SampledValueControl":
                            kind = "MS" if _bool(cb.get("multicast"), True) else "US"
                        elif tag == "ReportControl":
                            kind = "BR" if _bool(cb.get("buffered"), False) else "RP"
                        else:
                            continue
                        refs[(kind, ied_name, inst, cb_name)] = (
                            f"{ld_name}/{ln_name(ln)}${kind}${cb_name}"
                        )
    return refs


class _SclIndex:
    """Lookups shared by all IEDs of one SCL document (built once per document)."""

    def __init__(self, root) -> None:
        self.root = root
        # (iedName, apName) -> (ConnectedAP element, SubNetwork element)
        self.connected_aps: dict[tuple[str, str], tuple] = {}
        # (GSE|SMV, iedName, ldInst, cbName) -> GSE/SMV element
        self.cb_addresses: dict[tuple[str, str, str, str], object] = {}
        for subnet in _kids(_kid(root, "Communication"), "SubNetwork"):
            for cap in _kids(subnet, "ConnectedAP"):
                ied = cap.get("iedName", "")
                self.connected_aps.setdefault((ied, cap.get("apName", "")), (cap, subnet))
                for kind in ("GSE", "SMV"):
                    for el in _kids(cap, kind):
                        key = (kind, ied, el.get("ldInst", ""), el.get("cbName", ""))
                        self.cb_addresses.setdefault(key, el)
        self.references = _publication_references(root)
        # iedName -> Substation/VoltageLevel/Bay paths with an LNode of the IED
        self.functional_locations: dict[str, list[str]] = defaultdict(list)
        for sub in _kids(root, "Substation"):
            for vl in _kids(sub, "VoltageLevel"):
                for bay in _kids(vl, "Bay"):
                    path = f"{sub.get('name', '')}/{vl.get('name', '')}/{bay.get('name', '')}"
                    names = {ln.get("iedName", "") for ln in _desc(bay, "LNode")}
                    for name in sorted(n for n in names if n):
                        self.functional_locations[name].append(path)


def _subscription_reference(
    stype: str, ext, pub_ld: str, cb: str, pub_refs: dict[tuple[str, str, str, str], str]
) -> str:
    """
    Join key to the publisher (OT-8): the publisher's real reference if the
    publisher is in the same file, else built from the ExtRef ``src*`` attributes.
    """
    if not cb:
        return ""  # Edition 1 ExtRef: no source control block
    kinds = {"GOOSE": ("GO", "GS"), "SMV": ("MS", "US"), "Report": ("RP", "BR")}.get(stype, ())
    for kind in kinds:
        ref = pub_refs.get((kind, ext.get("iedName", ""), pub_ld, cb))
        if ref:
            return ref
    if stype not in ("GOOSE", "SMV"):
        return ""  # report kind (RP/BR) cannot be known from the subscriber side
    ln = f"{ext.get('srcPrefix', '')}{ext.get('srcLNClass') or 'LLN0'}{ext.get('srcLNInst', '')}"
    kind = "GO" if stype == "GOOSE" else "MS"
    return f"{ext.get('iedName', '')}{pub_ld}/{ln}${kind}${cb}"


def _access_point(
    ap_el, ied_name: str, index: _SclIndex, problems: list[dict]
) -> IEC61850AccessPoint:
    ap_name = ap_el.get("name", "")
    server = _kid(ap_el, "Server")
    ap = IEC61850AccessPoint(
        name=ap_name,
        server=server is not None,
        router=_bool(ap_el.get("router")),
        clock=_bool(ap_el.get("clock")),
    )
    cap, subnet = index.connected_aps.get((ied_name, ap_name), (None, None))
    mms_port = None
    if cap is not None:
        p = _p_values(_kid(cap, "Address"))
        ap.subnetwork = subnet.get("name", "")
        ap.subnetwork_type = subnet.get("type", "")
        ip_params = (("ip", "IP"), ("subnet_mask", "IP-SUBNET"), ("gateway", "IP-GATEWAY"))
        for field, ptype in ip_params:
            if p.get(ptype):
                try:
                    setattr(ap, field, p[ptype])
                except (ValueError, ValidationError) as ex:
                    _record_problem(problems, "access_point", ap_name, ptype, p[ptype], ex)
        if p.get("MMS-Port"):  # Edition 2 tPTypeEnum
            mms_port = _int(p["MMS-Port"])
            if mms_port is None or not 0 < mms_port < 65536:
                _record_problem(
                    problems, "access_point", ap_name, "MMS-Port", p["MMS-Port"], "invalid port"
                )
                mms_port = None
        ap.osi = {k: v for k, v in p.items() if k.startswith("OSI-")}
        ap.redundancy = cap.get("redProt") or ""
        ap.physical_ports = [
            (pp.text or "").strip()
            for pc in _kids(cap, "PhysConn")
            for pp in _kids(pc, "P")
            if pp.get("type") == "Port" and (pp.text or "").strip()
        ]
    if server is not None:
        ap.mms_port = mms_port or DEFAULT_MMS_PORT
        auth = _kid(server, "Authentication")
        if auth is None:
            flags = {"none": True}
        else:
            flags = {
                "none": _bool(auth.get("none"), True),
                **{
                    k: _bool(auth.get(k), False)
                    for k in ("password", "weak", "strong", "certificate")
                },
            }
        ap.authentication = {k for k, v in flags.items() if v}
    return ap


def _publications(
    ln, ied_name: str, inst: str, ld_name: str, index: _SclIndex, problems: list[dict]
) -> list[IEC61850Publication]:
    ds_sizes = {d.get("name", ""): len(_kids(d, "FCDA")) for d in _kids(ln, "DataSet")}
    pubs = []
    for gse in _kids(ln, "GSEControl"):
        cb = gse.get("name", "")
        gtype = (gse.get("type") or "GOOSE").strip().upper()
        if gtype not in ("GOOSE", "GSSE"):
            log.warning(f"Unknown GSEControl type '{gtype}' of {ied_name}/{inst}/{cb}")
            gtype = "GOOSE"
        addr_el = index.cb_addresses.get(("GSE", ied_name, inst, cb))
        pubs.append(
            IEC61850Publication(
                type=gtype,
                name=cb,
                ld_inst=inst,
                reference=f"{ld_name}/{ln_name(ln)}${'GO' if gtype == 'GOOSE' else 'GS'}${cb}",
                id=gse.get("appID", ""),
                dataset=gse.get(_DATSET, ""),
                dataset_members_count=ds_sizes.get(gse.get(_DATSET, "")),
                conf_rev=_uint(gse.get("confRev")),
                security=gse.get("securityEnable", "None"),
                address=(
                    _l2_address(addr_el, problems, f"{inst}/{cb}")
                    if addr_el is not None
                    else IEC61850Address()
                ),
                min_time=_ms(_kid(addr_el, "MinTime")) if addr_el is not None else None,
                max_time=_ms(_kid(addr_el, "MaxTime")) if addr_el is not None else None,
                subscribers=[(i.text or "").strip() for i in _kids(gse, "IEDName")],
                description=gse.get("desc", ""),
            )
        )
    for svc in _kids(ln, "SampledValueControl"):
        cb = svc.get("name", "")
        sv_kind = "MS" if _bool(svc.get("multicast"), True) else "US"
        addr_el = index.cb_addresses.get(("SMV", ied_name, inst, cb))
        pubs.append(
            IEC61850Publication(
                type="SV",
                name=cb,
                ld_inst=inst,
                reference=f"{ld_name}/{ln_name(ln)}${sv_kind}${cb}",
                id=svc.get("smvID", ""),
                dataset=svc.get(_DATSET, ""),
                dataset_members_count=ds_sizes.get(svc.get(_DATSET, "")),
                conf_rev=_uint(svc.get("confRev")),
                security=svc.get("securityEnable", "None"),
                address=(
                    _l2_address(addr_el, problems, f"{inst}/{cb}")
                    if addr_el is not None
                    else IEC61850Address()
                ),
                smp_rate=_uint(svc.get("smpRate")),
                smp_mod=svc.get("smpMod", ""),
                nof_asdu=_uint(svc.get("nofASDU")),
                subscribers=[(i.text or "").strip() for i in _kids(svc, "IEDName")],
                description=svc.get("desc", ""),
            )
        )
    return pubs


def _report_controls(ln, inst: str) -> list[IEC61850ReportControl]:
    rcbs = []
    for rc in _kids(ln, "ReportControl"):
        trg = _kid(rc, "TrgOps")
        trg_attrs = _attrs(trg) if trg is not None else {}
        trg_attrs.setdefault("gi", "true")  # XSD default
        enabled = _kid(rc, "RptEnabled")
        max_clients = None
        if enabled is not None:
            max_clients = _uint(enabled.get("max"))
            if max_clients is None:
                max_clients = 1  # XSD default
        rcbs.append(
            IEC61850ReportControl(
                name=rc.get("name", ""),
                ld_inst=inst,
                ln=ln_name(ln),
                report_id=rc.get("rptID", ""),
                dataset=rc.get(_DATSET, ""),
                conf_rev=_uint(rc.get("confRev")),
                buffered=_bool(rc.get("buffered"), False),
                buffer_time=_uint(rc.get("bufTime")),
                integrity_period=_uint(rc.get("intgPd")),
                trigger_options={k for k, v in trg_attrs.items() if _bool(v)},
                max_clients=max_clients,
                clients=[c.get("iedName") for c in _kids(enabled, "ClientLN") if c.get("iedName")],
            )
        )
    return rcbs


def _parse_ied(ied_el, index: _SclIndex, file_type: str) -> IEC61850:
    """Summarize one ``IED`` element."""
    name = ied_el.get("name", "")
    problems: list[dict] = []
    ied = IEC61850(
        ied_name=name,
        description=ied_el.get("desc", ""),
        manufacturer=ied_el.get("manufacturer", ""),
        ied_type=ied_el.get("type", ""),
        config_version=ied_el.get("configVersion", ""),
        original_scl_version="".join(
            ied_el.get(a, "")
            for a in ("originalSclVersion", "originalSclRevision", "originalSclRelease")
        ),
        header=_header(index.root, file_type),
    )
    services = _kid(ied_el, "Services")
    if services is not None:
        ied.capabilities = {_ln(s): _attrs(s) for s in services if _ln(s)}

    datasets = 0
    subs: dict[tuple[str, str, str, str], list] = defaultdict(list)
    for ap_el in _kids(ied_el, "AccessPoint"):
        ap = _access_point(ap_el, name, index, problems)
        ied.access_points.append(ap)
        for ld_el in _kids(_kid(ap_el, "Server"), "LDevice"):
            inst = ld_el.get("inst", "")
            ld_name = ld_el.get("ldName") or f"{name}{inst}"
            lns = [ln for ln in ld_el if _ln(ln) in ("LN0", "LN")]
            ied.logical_devices.append(
                IEC61850LogicalDevice(
                    inst=inst,
                    name=ld_name,
                    description=ld_el.get("desc", ""),
                    access_point=ap.name,
                    logical_nodes=[ln_name(ln) for ln in lns],
                )
            )
            for ln in lns:
                datasets += len(_kids(ln, "DataSet"))
                ied.publications.extend(_publications(ln, name, inst, ld_name, index, problems))
                ied.report_controls.extend(_report_controls(ln, inst))
                sg = _kid(ln, "SettingControl")
                if sg is not None:
                    ied.setting_groups = _uint(sg.get("numOfSGs"))
                    ied.active_setting_group = _uint(sg.get("actSG"))
                for inputs in _kids(ln, "Inputs"):
                    for ext in _kids(inputs, "ExtRef"):
                        if not ext.get("iedName"):
                            continue  # internal binding
                        key = (
                            ext.get("serviceType", ""),
                            ext.get("iedName", ""),
                            ext.get("srcLDInst") or ext.get("ldInst", ""),
                            ext.get("srcCBName", ""),
                        )
                        subs[key].append(ext)
    ied.datasets_count = datasets

    for (stype, pub_ied, pub_ld, cb), refs in subs.items():
        kind = {"GOOSE": "GSE", "SMV": "SMV"}.get(stype, "")
        addr_el = index.cb_addresses.get((kind, pub_ied, pub_ld, cb)) if kind and cb else None
        ied.subscriptions.append(
            IEC61850Subscription(
                service_type=stype,
                publisher_ied=pub_ied,
                publisher_ld_inst=pub_ld,
                control_block=cb,
                reference=_subscription_reference(stype, refs[0], pub_ld, cb, index.references),
                ext_ref_count=len(refs),
                address=(
                    _l2_address(addr_el, problems, f"{pub_ied}/{pub_ld}/{cb}")
                    if addr_el is not None
                    else IEC61850Address()
                ),
            )
        )
    ied.functional_locations = list(index.functional_locations.get(name, []))
    if problems:
        ied.extra["invalid_addresses"] = problems
    return ied


def parse_scl(root, ied_name: str | None = None, file_type: str = "") -> IEC61850:
    """
    Summarize ONE IED of an SCL document.

    Args:
        root: Root element returned by :func:`load_scl`
        ied_name: Name of the IED (``IED@name``). If :obj:`None`, the only IED
            is used (the first IED, with a warning, if there are several).
        file_type: SCL file type (one of :data:`SCL_FILE_TYPES`), see
            :func:`file_type_from_name`

    Returns:
        The IEC 61850 configuration summary of the IED

    Raises:
        ParseError: The document has no IED, or no IED named ``ied_name``
    """
    ieds = _kids(root, "IED")
    if not ieds:
        raise ParseError("SCL document has no IED elements")
    if ied_name:
        matches = [i for i in ieds if i.get("name") == ied_name]
        if not matches:
            raise ParseError(f"IED '{ied_name}' not found in SCL")
        ied_el = matches[0]
    else:
        if len(ieds) > 1:
            log.warning(f"SCL has {len(ieds)} IEDs, using the first ({ieds[0].get('name')})")
        ied_el = ieds[0]
    return _parse_ied(ied_el, _SclIndex(root), _norm_file_type(file_type))


def parse_scl_all(root, file_type: str = "") -> dict[str, IEC61850]:
    """
    Summarize every IED of an SCL document (e.g. an SCD).

    An IED that fails to parse is logged and left out; it never loses the
    other IEDs.

    Returns:
        IED name -> configuration summary, in document order
    """
    index = _SclIndex(root)
    file_type = _norm_file_type(file_type)
    result: dict[str, IEC61850] = {}
    for ied_el in _kids(root, "IED"):
        name = ied_el.get("name", "")
        if not name:
            continue
        if name in result:
            log.warning(f"Duplicate IED name '{name}' in SCL, using the first")
            continue
        try:
            result[name] = _parse_ied(ied_el, index, file_type)
        except Exception as ex:
            log.warning(f"Failed to parse IED '{name}' in SCL: {ex}")
    return result


# --------------------------------------------------------------------------- #
# Configuration alerts
# --------------------------------------------------------------------------- #
def _scl_alert(reason: str, **extra) -> Event:
    return Event(
        action="scl-validation",
        kind={"alert"},
        category={"configuration"},
        type={"info"},
        dataset="scl",
        message=reason,
        reason=reason,
        extra=extra,
    )


def scl_configuration_events(ied: IEC61850) -> list[Event]:
    """
    Configuration problems of one IED worth an alert: duplicate GOOSE/SV APPIDs
    within the IED, APPIDs outside the IEC 61850-8-1/9-2 ranges (GOOSE/GSSE
    ``0x0000-0x3FFF``, SV ``0x4000-0x7FFF``), and invalid address values
    (``IEC61850.extra["invalid_addresses"]``).

    Returns:
        ``scl-validation`` alert events (``event.kind: alert``,
        ``event.category: configuration``)
    """
    seen: dict[tuple[str, int], list[str]] = defaultdict(list)
    events = []
    for pub in ied.publications:
        appid = pub.address.appid
        if appid is None:
            continue
        seen[(pub.type, appid)].append(pub.name)
        low, high = APPID_RANGES.get(pub.type, (0, 0xFFFF))
        if not low <= appid <= high:
            events.append(
                _scl_alert(
                    f"{pub.type} APPID 0x{appid:04X} of {pub.name} "
                    f"outside 0x{low:04X}-0x{high:04X}",
                    ied_names=[ied.ied_name],
                    control_blocks=[pub.name],
                    appid=f"0x{appid:04X}",
                )
            )
    events += [
        _scl_alert(
            f"duplicate {t} APPID 0x{appid:04X} ({', '.join(names)})",
            ied_names=[ied.ied_name],
            control_blocks=names,
            appid=f"0x{appid:04X}",
        )
        for (t, appid), names in sorted(seen.items())
        if len(names) > 1
    ]
    for bad in ied.extra.get("invalid_addresses", []):
        where = bad.get("control_block") or bad.get("access_point", "")
        events.append(
            _scl_alert(
                f"invalid {bad.get('parameter', '')} '{bad.get('value', '')}' ({where})",
                ied_names=[ied.ied_name],
                parameter=bad.get("parameter", ""),
                value=bad.get("value", ""),
            )
        )
    return events


def scl_cross_ied_events(ieds: dict[str, IEC61850]) -> list[Event]:
    """
    Duplicate GOOSE/SV APPIDs across the IEDs of one SCD on the same VLAN.

    The names of the affected IEDs are in ``Event.extra["ied_names"]``.

    Args:
        ieds: IED name -> configuration summary, as returned by :func:`parse_scl_all`
    """
    seen: dict[tuple[str, int, str], list[tuple[str, str]]] = defaultdict(list)
    for ied_name, ied in ieds.items():
        for pub in ied.publications:
            if pub.address.appid is not None:
                key = (pub.type, pub.address.appid, pub.address.vlan.id)
                seen[key].append((ied_name, pub.name))
    events = []
    for (t, appid, vid), found in sorted(seen.items()):
        ied_names = sorted({name for name, _ in found})
        if len(ied_names) < 2:
            continue  # duplicates inside one IED are reported by scl_configuration_events()
        blocks = [f"{name}/{cb}" for name, cb in found]
        events.append(
            _scl_alert(
                f"duplicate {t} APPID 0x{appid:04X} on VLAN {vid or 'untagged'} "
                f"({', '.join(blocks)})",
                ied_names=ied_names,
                control_blocks=blocks,
                appid=f"0x{appid:04X}",
                vlan=vid,
            )
        )
    return events


# --------------------------------------------------------------------------- #
# Feeding DeviceData
# --------------------------------------------------------------------------- #
def _security_mode(value: str) -> str:
    """SCL ``securityEnable`` -> :attr:`ServiceSecurity.security_mode`."""
    lowered = (value or "None").strip().lower()
    return {
        "none": "none",
        "signature": "sign",
        "signatureandencryption": "sign_and_encrypt",
    }.get(lowered, lowered)


def _appid_str(appid: int | None) -> str:
    return f"0x{appid:04X}" if appid is not None else ""


def apply_iec61850(
    dev: DeviceData, ied: IEC61850, *, populate_interfaces: bool = True, evidence: str = "scl"
) -> None:
    """
    Store ``ied`` on ``dev`` and derive interfaces, services, relationships and
    configuration alerts from it.

    - ``dev.iec61850`` is set (or merged, if already set)
    - access points with an IP -> :class:`~peat.data.models.Interface` (unless
      ``populate_interfaces`` is False, an interface already has that IP, or the
      IP is a placeholder in :data:`UNSPECIFIED_IPS`)
    - access points with a server -> ``mms`` server service (tcp/102 or ``MMS-Port``),
      with ``security`` from ``Server/Authentication``
    - GOOSE/SV control blocks -> ``goose``/``sv`` publisher services, with
      ``security.security_mode`` from ``securityEnable``
    - one ``publishes_to`` relationship per GOOSE/SV control block (destination =
      multicast MAC), ``subscribes_to`` per subscribed control block, ``reports_to``
      per report control block client; ``reference`` joins both ends across devices
    - :func:`scl_configuration_events` alerts

    Args:
        dev: Device to update
        ied: Summary from :func:`parse_scl`
        populate_interfaces: Create interfaces from access point addresses
        evidence: Value for :attr:`Relationship.evidence`
    """
    if dev.is_default("iec61850"):
        dev.iec61850 = ied
    else:
        merge_models(dev.iec61850, ied)

    if populate_interfaces:
        for ap in ied.access_points:
            if ap.ip in UNSPECIFIED_IPS:
                continue  # placeholder (e.g. 0.0.0.0 in a template), kept in access_points
            if ap.ip and not any(i.ip == ap.ip for i in dev.interface):
                dev.store(
                    "interface",
                    Interface(
                        name=ap.physical_ports[0] if ap.physical_ports else ap.name,
                        type="ethernet",
                        ip=ap.ip,
                        subnet_mask=ap.subnet_mask,
                        gateway="" if ap.gateway in UNSPECIFIED_IPS else ap.gateway,
                        application="iec61850",
                    ),
                )

    servers = [ap for ap in ied.access_points if ap.server]
    mms_port = next((ap.mms_port for ap in servers if ap.mms_port), DEFAULT_MMS_PORT)
    if servers:
        auth = set().union(*(ap.authentication for ap in servers))
        methods = auth - {"none"}
        dev.store(
            "service",
            Service(
                protocol="mms",
                transport="tcp",
                port=mms_port,
                role="server",
                enabled=True,
                security=ServiceSecurity(  # OT-22: SCL Server/Authentication
                    authentication_required=bool(methods) and "none" not in auth,
                    authentication_methods=methods,
                ),
            ),
        )

    for ptype, proto in (("GOOSE", "goose"), ("SV", "sv")):
        pubs = [p for p in ied.publications if p.type == ptype]
        if not pubs:
            continue
        modes = {_security_mode(p.security) for p in pubs}
        mode = modes.pop() if len(modes) == 1 else "mixed"
        dev.store(
            "service",
            Service(
                protocol=proto,
                role="publisher",
                enabled=True,
                security=ServiceSecurity(  # OT-22: securityEnable (IEC 62351-6)
                    security_mode=mode,
                    # "encrypted" is derived (False) by Service.annotate() otherwise
                    encrypted=True if mode == "sign_and_encrypt" else None,
                ),
            ),
        )

    for pub in ied.publications:
        # One relationship per publication (destination = multicast MAC). Configured
        # subscribers are listed in extra; each subscriber's own SCL yields subscribes_to.
        dev.store(
            "relationships",
            Relationship(
                type="publishes_to",
                protocol="sv" if pub.type == "SV" else "goose",
                medium="ethernet",
                direction="egress",
                local=RelationshipEndpoint(
                    role="publisher", protocol_address=_appid_str(pub.address.appid)
                ),
                remote=RelationshipEndpoint(mac=pub.address.mac, role="subscriber"),
                vlan=pub.address.vlan,
                reference=pub.reference,  # OT-8: join key to the subscribers
                enabled=True,
                evidence={evidence},
                extra={
                    "publication_id": pub.id,
                    "subscribers": list(pub.subscribers),
                    "security": pub.security,
                },
            ),
        )

    for sub in ied.subscriptions:
        common = {
            "type": "subscribes_to",
            "reference": sub.reference,
            "vlan": sub.address.vlan,
            "evidence": {evidence},
            "extra": {"control_block": sub.control_block, "ext_ref_count": sub.ext_ref_count},
        }
        if sub.service_type in ("Report", "Poll"):
            # ECS-6: the subscriber is the MMS CLIENT and opens TCP to the publisher's server
            rel = Relationship(
                protocol="mms",
                transport="tcp",
                direction="egress",
                local=RelationshipEndpoint(role="client"),
                remote=RelationshipEndpoint(
                    name=sub.publisher_ied, port=DEFAULT_MMS_PORT, role="server"
                ),
                **common,
            )
        elif sub.service_type in ("GOOSE", "SMV"):
            rel = Relationship(
                protocol="goose" if sub.service_type == "GOOSE" else "sv",
                medium="ethernet",
                direction="ingress",
                local=RelationshipEndpoint(role="subscriber"),
                remote=RelationshipEndpoint(
                    name=sub.publisher_ied,
                    mac=sub.address.mac,
                    protocol_address=_appid_str(sub.address.appid),
                    role="publisher",
                ),
                **common,
            )
        else:
            # Edition 1 ExtRef without serviceType: GOOSE, report or poll is unknown,
            # so the protocol, direction and roles are left empty (no inference).
            rel = Relationship(
                remote=RelationshipEndpoint(name=sub.publisher_ied),
                **common,
            )
        dev.store("relationships", rel)

    ld_names = {ld.inst: ld.name for ld in ied.logical_devices}
    for rcb in ied.report_controls:
        kind = "BR" if rcb.buffered else "RP"
        ld_name = ld_names.get(rcb.ld_inst) or f"{ied.ied_name}{rcb.ld_inst}"
        for client in rcb.clients:
            dev.store(
                "relationships",
                Relationship(
                    type="reports_to",
                    protocol="mms",
                    transport="tcp",
                    direction="ingress",
                    local=RelationshipEndpoint(role="server", port=mms_port),
                    remote=RelationshipEndpoint(name=client, role="client"),
                    reference=f"{ld_name}/{rcb.ln}${kind}${rcb.name}",
                    evidence={evidence},
                ),
            )

    for ev in scl_configuration_events(ied):
        dev.store("event", ev)


__all__ = [
    "APPID_RANGES",
    "DEFAULT_MMS_PORT",
    "SCL_FILE_TYPES",
    "SCL_NAMESPACE",
    "UNSPECIFIED_IPS",
    "apply_iec61850",
    "decode_scl_bytes",
    "file_type_from_name",
    "is_scl",
    "list_ieds",
    "ln_name",
    "load_scl",
    "parse_scl",
    "parse_scl_all",
    "scl_configuration_events",
    "scl_cross_ied_events",
]
