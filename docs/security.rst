.. _security-docs:

********
Security
********

This page describes what users can and can't expect from PEAT's security, how PEAT is designed to meet those expectations, and how to verify PEAT releases. To report a vulnerability, refer to the :doc:`security_policy`.

.. _security-requirements:

Security requirements
=====================

PEAT is a tool for authorized operators to collect information from :term:`OT` devices that they own or are responsible for. It runs on the operator's own system, with the operator's privileges, and talks directly to devices over the network or serial connections. It is not a network service: it doesn't listen for connections, and it has no user accounts of its own.

What PEAT is designed to do
---------------------------

- **Only change devices when explicitly asked.** ``scan``, ``pull``, ``parse``, ``pillage``, and ``heat`` read information and don't intentionally change device configuration. Only ``peat push`` uploads configuration or firmware to a device, and only to the targets and files the operator specifies.
- **Only talk to the targets the operator specifies.** PEAT contacts the hosts, networks, and serial ports given on the command line or in the configuration file, and the Elasticsearch or OpenSearch server the operator configures. It doesn't send data anywhere else, and it has no telemetry.
- **Handle data from devices as untrusted.** Device responses and files pulled from devices may be malformed or malicious. PEAT's parsers are expected to reject or skip invalid data without crashing or running anything from it.
- **Protect credentials the operator supplies.** Device and Elasticsearch credentials come from the operator's configuration file, environment, or command line, and aren't hard-coded or sent anywhere except the device or server they belong to. Configuration files containing credentials can be encrypted at rest (``peat encrypt-config``), and so can results (``peat encrypt-results``).
- **Use the strongest security the device supports.** When a device supports a secure protocol (such as HTTPS or SSH), PEAT uses it where the module supports it.
- **Be verifiable.** Releases are built by GitHub Actions from the public source code and signed, so users can verify where a release came from (refer to :ref:`verifying-releases`).

What PEAT does not do
---------------------

- **It can't make insecure devices secure.** Many OT devices only support unauthenticated or unencrypted protocols (such as Telnet, FTP, HTTP, Modbus, or vendor protocols), or only old versions of TLS. PEAT has to use these protocols to talk to such devices, so an attacker on the same network may be able to observe or tamper with that traffic, including any credentials sent. Run PEAT from a trusted system on a trusted network segment.
- **It doesn't verify device TLS certificates.** OT devices almost always use self-signed certificates, so PEAT doesn't verify them when connecting to devices over HTTPS.
- **It doesn't sandbox device modules.** Device modules, including modules loaded at runtime with ``-I``/``--import-modules``, are Python code that runs with the operator's privileges. Only load modules from sources you trust.
- **It doesn't protect results at rest by default.** Output files (configurations, firmware, logs, and parsed data) are written to the output directory unencrypted unless results encryption is used. Protect them as the sensitive data they are.

Assurance case
==============

This section is PEAT's argument for why it meets the security requirements above.

Threat model
------------

PEAT's users are trusted operators running PEAT on systems they control. The assets PEAT protects are the operator's system, the credentials the operator supplies, the data PEAT collects, and the integrity of the devices PEAT connects to.

The threats PEAT is designed to resist are:

- **Malicious or malformed data from a device**, or from a file being parsed, intended to crash PEAT, exhaust resources, or run code on the operator's system. A device on the network may be compromised, or an attacker may impersonate one.
- **Accidental changes to devices**, for example from running the wrong command or targeting the wrong device.
- **Credential exposure**, through logs, output files, or being sent to the wrong system.
- **Tampered releases or dependencies**, where a user downloads a PEAT build that wasn't built from the public source code, or a dependency is compromised.

Out of scope: attackers who already control the operator's system or user account, and network attackers against protocols that devices only support insecurely (refer to the limits above).

Trust boundaries
----------------

.. code-block:: text

   +------------------------- operator's system (trusted) --------------------------+
   |  operator --> CLI args / config file / env vars --> PEAT --> output directory  |
   |                                                       |  ^                     |
   |                          runtime device modules (-I) -+  |  (trusted code)      |
   +-------------------------------------------------------|--|---------------------+
                                       network / serial    |  |  untrusted data
                                                           v  |
                                    OT devices, packet captures, files to parse
                                                           |
                                       Elasticsearch / OpenSearch (operator-configured)

- **Operator input** (command line, configuration files, environment variables) is trusted, but validated so mistakes produce clear errors.
- **Device responses, pulled files, and files given to** ``peat parse`` **are untrusted.** This is the main boundary PEAT defends.
- **Device modules are trusted code**, whether built-in or loaded at runtime.
- **The Elasticsearch or OpenSearch server** is operator-configured and trusted to store results.

Secure design principles
------------------------

PEAT applies the `Saltzer and Schroeder <https://web.mit.edu/Saltzer/www/publications/protection/>`__ secure design principles where they apply to a command line tool:

- **Economy of mechanism:** PEAT uses well-known libraries for protocols, parsing, and cryptography (for example ``requests``, ``paramiko``, ``scapy``, and ``cryptography``) rather than implementing its own, except for device-specific protocols that have no library.
- **Fail-safe defaults:** device-changing actions require the explicit ``push`` command, and PEAT does nothing beyond what the operator requests.
- **Least privilege:** PEAT runs with the operator's privileges and has no privileged service component. Most features don't need root or Administrator; only features that need low-level access do (such as ``pillage`` mounting disk images, and ICMP/ARP pings or sniffing for some scanning methods).
- **Open design:** PEAT's security doesn't depend on secrecy. The source code, design (:doc:`design_documents`), and this document are public.
- **Separation of privilege and least common mechanism:** each device module is separate, so a parsing problem in one module doesn't affect others, and errors from one device don't stop a scan of others.
- **Psychological acceptability:** secure options, such as encrypting configuration and results, are single commands.
- **Input validation:** operator input is validated (for example, IP addresses, networks, and configuration values), and data from devices is checked against the expected format before use, with invalid data rejected or skipped and logged.

Countering common weaknesses
----------------------------

PEAT addresses the most common implementation weaknesses (from the `CWE Top 25 <https://cwe.mitre.org/top25/>`__ and `OWASP Top 10 <https://owasp.org/Top10/>`__) that apply to it:

- **Memory safety** (CWE-787, CWE-125, CWE-416): PEAT is written in Python, a memory-safe language.
- **Injection** (CWE-78, CWE-94, CWE-502): YAML is loaded with ``yaml.safe_load``, data from devices is never passed to ``eval``, ``exec``, ``pickle``, or a shell, and operator-supplied values used in subprocess commands come only from the operator's own configuration.
- **XML attacks** (CWE-611, CWE-776): XML from devices is parsed with Python's standard library parser, which doesn't resolve external entities, and is protected against entity expansion attacks by the bundled Expat library.
- **Improper input validation and crashes** (CWE-20): parsers handle malformed input from devices, and this is tested with fuzz tests (``tests/test_fuzz.py``) in addition to unit tests using real device data.
- **Hard-coded credentials** (CWE-798): PEAT contains no private credentials. Some modules include publicly documented vendor factory default credentials, which PEAT uses only to check whether a device still uses its defaults. Operators supply all other credentials.
- **Credentials in logs** (CWE-532): credentials in Elasticsearch URLs are removed before the URL is logged.
- **Weak cryptography** (CWE-327, CWE-916): configuration file encryption uses the ``cryptography`` library's Fernet (AES-128-CBC with HMAC-SHA256), with the key derived from the password using PBKDF2-HMAC-SHA256 with 1,200,000 iterations. Results encryption uses AES-256 encrypted ZIP archives (WinZip AES, via ``pyzipper``). PEAT doesn't implement its own cryptography.
- **Vulnerable dependencies** (CWE-1395): dependencies are pinned in ``pdm.lock``, reviewed by GitHub dependency review on every pull request, and audited weekly for known vulnerabilities.

These arguments are supported by automated checks that run on every change: static analysis with CodeQL and Ruff, the unit and fuzz test suites, dependency review, and the OpenSSF Scorecard.

.. _verifying-releases:

Verifying releases
==================

Release files on the `releases page <https://github.com/sandialabs/PEAT/releases>`__ are signed with `Sigstore <https://www.sigstore.dev/>`__ build provenance attestations, created by the release workflow in GitHub Actions. An attestation proves the file was built from the PEAT source code by PEAT's release workflow, and hasn't been modified since.

To verify a file, install the `GitHub CLI <https://cli.github.com/>`__ and run:

.. code-block:: bash

   gh attestation verify peat --repo sandialabs/PEAT

Replace ``peat`` with the file you downloaded (for example ``peat.exe`` or the ``.whl`` file). The command prints the workflow and commit the file was built from, and fails if the file doesn't match.

Each release also includes ``SHA256SUMS.txt``, with the SHA-256 checksum of every release file. This is also signed, and can be used to check files on systems without the GitHub CLI:

.. code-block:: bash

   sha256sum --check --ignore-missing SHA256SUMS.txt
