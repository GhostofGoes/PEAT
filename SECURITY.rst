***************
Security Policy
***************

Reporting Security Issues
-------------------------

The PEAT team and community take security bugs in PEAT seriously.
We appreciate your efforts to responsibly disclose your findings, and will make every effort to acknowledge your contributions.

Please report security issues privately, using either of these methods. Do **not** open a public GitHub issue for a security issue.

- Use GitHub's `private vulnerability reporting <https://github.com/sandialabs/PEAT/security/advisories/new>`__ ("Report a vulnerability" on the repository's Security tab).
- Email our development team at ``peat AT sandia DOT gov``.

Please include a description of the issue, the PEAT version (``peat --version``), the steps to reproduce it, and its impact, if known.

Report security bugs in third-party modules and model components to the person or team maintaining the module or model component.

Supported Versions
------------------

Security fixes are made in the ``main`` branch and published in the next release. Only the latest release receives security fixes; older releases are not patched. PEAT releases are backwards-compatible in normal use, so upgrading to the latest release is the supported way to get a fix. Refer to the `releases page <https://github.com/sandialabs/PEAT/releases>`__ for the latest release and the :doc:`changelog` for what changed.

Response Process
----------------

When the PEAT team receives a vulnerability report, we:

#. Acknowledge receipt to the reporter within 14 days, usually much sooner.
#. Confirm the issue and assess its severity and impact (using `CVSS <https://www.first.org/cvss/>`__ as a guide), and keep the reporter informed of progress. We may ask the reporter for additional information or guidance.
#. Develop and test a fix in a private fork or `GitHub Security Advisory <https://docs.github.com/en/code-security/security-advisories>`__. Our goal is to release fixes for medium and higher severity vulnerabilities within 60 days of the report, and as quickly as possible for critical vulnerabilities.
#. Release the fix, and publish a GitHub Security Advisory describing the vulnerability, affected versions, and how to fix or mitigate it. A CVE is requested through GitHub when appropriate.
#. Note the fix in the :doc:`changelog`.

We ask reporters to keep the issue private until a fix is released, or for 90 days after the report, whichever comes first. We're happy to coordinate disclosure timing with the reporter.

Vulnerabilities in PEAT's dependencies are found by the weekly dependency audit (``.github/workflows/dependency-audit.yml``) and by GitHub's dependency review on pull requests. These are fixed by updating the dependency, following the same timeline.

Credit
------

We credit reporters by name (or handle) in the security advisory and the changelog entry for the fix, unless they ask to remain anonymous.
