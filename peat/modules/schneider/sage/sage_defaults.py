"""
Known-default baselines for Schneider Electric Sage RTUs.

These are vendor hardening recommendations (``kind="vendor_recommended"``), used by
``peat baseline-compare --known-defaults``. Factory default VALUES are not declared:
the Sage's only documented factory default is the ``Admin`` account password, which is
checked through ``Service.security.default_credentials`` and never stored here.
"""

from typing import Final

from peat.data.models import Baseline, BaselineProvenance, BaselineRule, BaselineSelector

_SELECTOR = BaselineSelector(vendor_id="Schneider", device_type="RTU")
_PROVENANCE = BaselineProvenance(
    author="Sage",
    reference="peat/modules/schneider/sage/sage.py",
    description=(
        "Hardening checks for Sage RTUs: cleartext services that are enabled by "
        "default, the factory default Admin password and unconfigured placeholders"
    ),
)

SAGE_VENDOR_RECOMMENDED: Final[Baseline] = Baseline(
    id="sage-vendor-recommended",
    name="Sage RTU hardening",
    version="1",
    kind="vendor_recommended",
    scope="device_type",
    selector=_SELECTOR,
    provenance=_PROVENANCE,
    rules=[
        BaselineRule(
            id="sage.service.telnet.absent",
            name="Telnet not exposed",
            path="service[protocol=telnet]",
            operator="absent",
            category="ports_services",
            severity="medium",
            reason="Telnet (23/tcp, cleartext) is exposed",
        ),
        BaselineRule(
            id="sage.service.ftp.absent",
            name="FTP not exposed",
            path="service[protocol=ftp]",
            operator="absent",
            category="ports_services",
            severity="medium",
            reason="FTP (21/tcp, cleartext) is exposed",
        ),
        BaselineRule(
            id="sage.service.http.absent",
            name="HTTP not exposed",
            path="service[protocol=http]",
            operator="absent",
            category="ports_services",
            severity="medium",
            reason="The web interface is exposed without TLS (HTTP 80/tcp)",
        ),
        BaselineRule(
            id="sage.accounts.default-credentials",
            name="No factory default passwords",
            path="service[*].security.default_credentials",
            operator="not_equals",
            value=True,
            category="accounts",
            severity="high",
            alert=True,
            reason="The factory default Admin password was accepted",
        ),
        BaselineRule(
            id="sage.settings.placeholders",
            name="No ChangeMe placeholders",
            path="extra.rtusetup_placeholders",
            operator="absent",
            category="settings",
            severity="low",
            reason="rtusetup.xml fields are still set to the ChangeMe placeholder: {actual}",
        ),
    ],
)

SAGE_KNOWN_DEFAULTS: Final[list[Baseline]] = [SAGE_VENDOR_RECOMMENDED]

__all__ = ["SAGE_KNOWN_DEFAULTS", "SAGE_VENDOR_RECOMMENDED"]
