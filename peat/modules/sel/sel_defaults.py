"""
Known-default baselines and factory default credentials for SEL devices.

The baselines are used by ``peat baseline-compare --known-defaults``
(:attr:`~peat.device.DeviceModule.known_defaults`):

- ``sel-relay-factory-defaults`` (``kind="factory_default"``): the factory
  VALUES of SEL relays. A failed rule means "changed from the factory default"
  (severity ``info``), not a problem.
- ``sel-relay-vendor-recommended`` (``kind="vendor_recommended"``): hardening
  checks for SEL relays.
- ``sel-rtac-vendor-recommended`` (``kind="vendor_recommended"``): hardening
  checks for SEL RTACs.

Sources: ``docs/sel.rst`` (factory default RID/TID) and
``peat/modules/sel/sel_relay.py`` (default ports and access level passwords).

The factory default credentials are only used in code, to set
``Service.security.default_credentials``. They are never exported or logged.
"""

from typing import Final

from peat.data.models import (
    Baseline,
    BaselineProvenance,
    BaselineRule,
    BaselineSelector,
    ServiceSecurity,
)

FACTORY_RID: Final[list[str]] = ["FEEDER 1", "feeder 1", "feeder_1"]
"""Factory default Relay ID (RID) of most SEL relays, as PEAT stores it in ``name``."""

FACTORY_TID: Final[list[str]] = ["STATION A", "station a", "station_a"]
"""Factory default Terminal ID (TID) of most SEL relays (``extra.terminal_id``)."""

SEL_RELAY_ACCESS_LEVEL_DEFAULTS: Final[frozenset[tuple[str, str]]] = frozenset(
    {
        ("ACC", "OTTER"),  # Access level 1
        ("BAC", "EDITH"),  # Access level B ("breaker")
        ("2AC", "TAIL"),  # Access level 2
        ("CAL", "CLARKE"),  # Access level C (calibration)
    }
)
"""Factory default passwords of the SEL ASCII access levels (Telnet, serial, web)."""

SEL_RELAY_FTP_DEFAULTS: Final[frozenset[tuple[str, str]]] = frozenset(
    {
        ("FTPUSER", "TAIL"),  # 351S, 700G, 710, 751
        ("2AC", "TAIL"),  # 451, 411L, 487E, 2032 (Level 2 password)
        ("FTP", "TAIL"),  # 351
    }
)
"""Factory default FTP credentials of SEL relays (the FTP password is the Level 2 password)."""

SEL_RELAY_FACTORY_CREDENTIALS: Final[frozenset[tuple[str, str]]] = (
    SEL_RELAY_ACCESS_LEVEL_DEFAULTS | SEL_RELAY_FTP_DEFAULTS
)
"""All factory default credentials of SEL relays (:attr:`SELRelay.factory_default_credentials`)."""

_RELAY_SELECTOR = BaselineSelector(vendor_id="SEL", device_type="Relay")
_RELAY_PROVENANCE = BaselineProvenance(
    author="SELRelay",
    reference="docs/sel.rst",
    description=(
        "SEL relay factory defaults (RID/TID, Telnet and FTP ports) from docs/sel.rst "
        "and peat/modules/sel/sel_relay.py"
    ),
)

SEL_RELAY_FACTORY_DEFAULTS: Final[Baseline] = Baseline(
    id="sel-relay-factory-defaults",
    name="SEL relay factory defaults",
    version="1",
    kind="factory_default",
    scope="device_type",
    selector=_RELAY_SELECTOR,
    provenance=_RELAY_PROVENANCE,
    rules=[
        BaselineRule(
            id="sel.default.telnet-port",
            name="Telnet on factory port",
            path="service[protocol=telnet].port",
            operator="equals",
            value=23,
            category="ports_services",
            severity="info",
            reason="Telnet port changed from factory default 23 to {actual}",
        ),
        BaselineRule(
            id="sel.default.ftp-port",
            name="FTP on factory port",
            path="service[protocol=ftp].port",
            operator="equals",
            value=21,
            category="ports_services",
            severity="info",
            reason="FTP port changed from factory default 21 to {actual}",
        ),
        BaselineRule(
            id="sel.default.rid",
            name="Factory relay ID",
            path="name",
            operator="in",
            value=FACTORY_RID,
            category="identity",
            severity="info",
            reason="Relay ID changed from factory default",
        ),
        BaselineRule(
            id="sel.default.tid",
            name="Factory terminal ID",
            path="extra.terminal_id",
            operator="in",
            value=FACTORY_TID,
            category="identity",
            severity="info",
            reason="Terminal ID changed from factory default",
        ),
    ],
)

SEL_RELAY_VENDOR_RECOMMENDED: Final[Baseline] = Baseline(
    id="sel-relay-vendor-recommended",
    name="SEL relay hardening",
    version="1",
    kind="vendor_recommended",
    scope="device_type",
    selector=_RELAY_SELECTOR,
    provenance=BaselineProvenance(
        author="SELRelay",
        reference="docs/sel.rst",
        description=(
            "Hardening checks for SEL relays: cleartext services, factory default "
            "passwords, factory default identifiers and unsigned GOOSE"
        ),
    ),
    rules=[
        BaselineRule(
            id="sel.service.ftp.disabled",
            name="FTP disabled",
            path="service[protocol=ftp].enabled",
            operator="not_equals",
            value=True,
            category="ports_services",
            severity="medium",
            reason="FTP (21/tcp, cleartext) is enabled",
        ),
        # A disabled Telnet service (ETELNET=N) is stored with enabled=False
        BaselineRule(
            id="sel.service.telnet.absent",
            name="Telnet not exposed",
            path="service[protocol=telnet].enabled",
            operator="not_equals",
            value=True,
            category="ports_services",
            severity="low",
            reason="Telnet (23/tcp, cleartext) is enabled",
        ),
        # Telnet found open by a scan or used by a pull (no settings: enabled unset)
        BaselineRule(
            id="sel.service.telnet.open",
            name="Telnet not answering",
            path="service[protocol=telnet].status",
            operator="not_in",
            value=["open", "verified"],
            category="ports_services",
            severity="low",
            reason="Telnet (23/tcp, cleartext) is open ({actual})",
        ),
        BaselineRule(
            id="sel.accounts.default-credentials",
            name="No factory default passwords",
            path="service[*].security.default_credentials",
            operator="not_equals",
            value=True,
            category="accounts",
            severity="high",
            alert=True,
            reason="A factory default password was accepted",
        ),
        BaselineRule(
            id="sel.identity.rid-changed",
            name="Relay ID set",
            path="name",
            operator="not_in",
            value=FACTORY_RID,
            category="identity",
            severity="low",
            reason="Relay ID is still the factory default {actual}",
        ),
        BaselineRule(
            id="sel.identity.tid-changed",
            name="Terminal ID set",
            path="extra.terminal_id",
            operator="not_in",
            value=FACTORY_TID,
            category="identity",
            severity="low",
            reason="Terminal ID is still the factory default {actual}",
        ),
        BaselineRule(
            id="sel.iec61850.goose.signed",
            name="GOOSE signed (IEC 62351-6)",
            path="iec61850.publications[type=GOOSE].security",
            operator="not_equals",
            value="None",
            category="settings",
            severity="info",
            reason="GOOSE publications are not signed (rarely supported by relays)",
        ),
    ],
)

SEL_RELAY_KNOWN_DEFAULTS: Final[list[Baseline]] = [
    SEL_RELAY_FACTORY_DEFAULTS,
    SEL_RELAY_VENDOR_RECOMMENDED,
]
"""Known-default baselines of :class:`~peat.modules.sel.sel_relay.SELRelay`."""

SEL_RTAC_VENDOR_RECOMMENDED: Final[Baseline] = Baseline(
    id="sel-rtac-vendor-recommended",
    name="SEL RTAC hardening",
    version="1",
    kind="vendor_recommended",
    scope="device_type",
    selector=BaselineSelector(vendor_id="SEL", device_type="RTAC"),
    provenance=BaselineProvenance(
        author="SELRTAC",
        reference="peat/modules/sel/sel_rtac.py",
        description="Hardening checks for SEL RTACs: no factory default passwords",
    ),
    rules=[
        BaselineRule(
            id="sel.rtac.accounts.default-credentials",
            name="No factory default passwords",
            path="service[*].security.default_credentials",
            operator="not_equals",
            value=True,
            category="accounts",
            severity="high",
            alert=True,
            reason="A factory default password was accepted",
        ),
    ],
)

SEL_RTAC_KNOWN_DEFAULTS: Final[list[Baseline]] = [SEL_RTAC_VENDOR_RECOMMENDED]
"""Known-default baselines of :class:`~peat.modules.sel.sel_rtac.SELRTAC`."""


def credential_security(
    module: type,
    user: str,
    password: str,
    rejected: list[tuple[str, str]] | tuple = (),
    service_defaults: frozenset[tuple[str, str]] | set = frozenset(),
) -> ServiceSecurity:
    """
    Security facts of a service from the credential that SUCCEEDED (never stored).

    - anonymous login -> ``anonymous_access=True``, ``authentication_required=False``
    - otherwise ``authentication_required=True`` and ``default_credentials``:
      ``True`` if ``(user, password)`` is a factory default of ``module``
      (:meth:`~peat.device.DeviceModule.is_factory_default_credential`); ``False``
      only if every factory default of the service (``service_defaults``) was
      tried and rejected before (``rejected``); else :obj:`None` (unknown)

    Args:
        module: The PEAT module class (e.g. ``SELRelay``)
        user: User name that succeeded
        password: Password that succeeded
        rejected: Credentials that were tried and rejected before
        service_defaults: Factory default credentials that apply to this service
    """
    if user.strip().lower() == "anonymous":
        return ServiceSecurity(anonymous_access=True, authentication_required=False)

    security = ServiceSecurity(authentication_required=True)
    if module.is_factory_default_credential(user, password):
        security.default_credentials = True
    elif service_defaults and all(
        any(u.lower() == r_user.lower() and p == r_pass for r_user, r_pass in rejected)
        for u, p in service_defaults
    ):
        security.default_credentials = False
    return security


__all__ = [
    "FACTORY_RID",
    "FACTORY_TID",
    "SEL_RELAY_ACCESS_LEVEL_DEFAULTS",
    "SEL_RELAY_FACTORY_CREDENTIALS",
    "SEL_RELAY_FACTORY_DEFAULTS",
    "SEL_RELAY_FTP_DEFAULTS",
    "SEL_RELAY_KNOWN_DEFAULTS",
    "SEL_RELAY_VENDOR_RECOMMENDED",
    "SEL_RTAC_KNOWN_DEFAULTS",
    "SEL_RTAC_VENDOR_RECOMMENDED",
    "credential_security",
]
