"""
Known-default baselines for Rockwell Automation (Allen-Bradley) ControlLogix PLCs.

These are vendor hardening recommendations (``kind="vendor_recommended"``), used by
``peat baseline-compare --known-defaults``. Factory default VALUES are not declared.
The only factory default PEAT knows of is the ``Administrator`` web/FTP account with
an empty password, which is checked through ``Service.security.default_credentials``
and never stored here.

There is deliberately no rule for the CIP Identity "Configured" status bit: Logix
controllers often leave it clear even when configured.
"""

from typing import Final

from peat.data.models import Baseline, BaselineProvenance, BaselineRule, BaselineSelector

_SELECTOR = BaselineSelector(vendor_id="Rockwell", device_type="PLC")
_PROVENANCE = BaselineProvenance(
    author="ControlLogix",
    reference="peat/modules/rockwell/controllogix.py",
    description=(
        "Hardening checks for ControlLogix controllers: the key switch position "
        "(decoded from the CIP Identity status word) and the factory default "
        "Administrator account of the Ethernet communication modules"
    ),
)

CLX_VENDOR_RECOMMENDED: Final[Baseline] = Baseline(
    id="clx-vendor-recommended",
    name="ControlLogix hardening",
    version="1",
    kind="vendor_recommended",
    scope="device_type",
    selector=_SELECTOR,
    provenance=_PROVENANCE,
    rules=[
        BaselineRule(
            id="clx.key_switch.run",
            name="Key switch in RUN",
            path="key_switch",
            operator="equals",
            value="run",
            category="settings",
            severity="medium",
            reason="Key switch is not in RUN; remote program changes possible",
        ),
        BaselineRule(
            id="clx.accounts.default-credentials",
            name="No factory default passwords",
            path="service[*].security.default_credentials",
            operator="not_equals",
            value=True,
            category="accounts",
            severity="high",
            alert=True,
            reason="The factory default Administrator account (empty password) was accepted",
        ),
    ],
)

CLX_KNOWN_DEFAULTS: Final[list[Baseline]] = [CLX_VENDOR_RECOMMENDED]

__all__ = ["CLX_KNOWN_DEFAULTS", "CLX_VENDOR_RECOMMENDED"]
