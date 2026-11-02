"""
Known-default baselines for Schneider Electric Modicon M340 PLCs.

These are vendor hardening recommendations (``kind="vendor_recommended"``), used by
``peat baseline-compare --known-defaults``. The factory default FTP account
(``M340.factory_default_credentials``) is checked through
``Service.security.default_credentials`` and never stored here.
"""

from typing import Final

from peat.data.models import Baseline, BaselineProvenance, BaselineRule, BaselineSelector

M340_VENDOR_RECOMMENDED: Final[Baseline] = Baseline(
    id="m340-vendor-recommended",
    name="Modicon M340 hardening",
    version="1",
    kind="vendor_recommended",
    scope="device_type",
    selector=BaselineSelector(vendor_id="Schneider", device_type="PLC"),
    provenance=BaselineProvenance(
        author="M340",
        reference="peat/modules/schneider/m340/m340.py",
        description=(
            "Hardening checks for Modicon M340 PLCs: factory default FTP (firmware "
            "loader) account and SNMP communities, and the web server password"
        ),
    ),
    rules=[
        BaselineRule(
            id="m340.accounts.default-credentials",
            name="No factory default credentials",
            path="service[*].security.default_credentials",
            operator="not_equals",
            value=True,
            category="accounts",
            severity="high",
            alert=True,
            reason=(
                "A factory default credential was accepted (FTP loader account or "
                "SNMP public/private community)"
            ),
        ),
        BaselineRule(
            id="m340.web.password",
            name="Web server password enabled",
            path="service[protocol=http].security.authentication_required",
            operator="not_equals",
            value=False,
            category="authentication",
            severity="medium",
            reason="The web server password is disabled",
        ),
    ],
)

M340_KNOWN_DEFAULTS: Final[list[Baseline]] = [M340_VENDOR_RECOMMENDED]

__all__ = ["M340_KNOWN_DEFAULTS", "M340_VENDOR_RECOMMENDED"]
