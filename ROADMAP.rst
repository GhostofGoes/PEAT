*******
Roadmap
*******

This roadmap describes what the PEAT team intends to work on over the next year (October 2026 through October 2027). It's a statement of intent, not a commitment: priorities can change based on user needs and available resources. Most items link to a GitHub issue where the details are discussed, and anyone is welcome to comment or contribute.

The roadmap is reviewed and updated by the maintainers at least once a year (refer to :doc:`governance`).

Security and supply chain
-------------------------

- Update the pinned dependencies that have known vulnerabilities, including ``cryptography``, ``paramiko``, ``requests``, and ``urllib3`` (`#68 <https://github.com/sandialabs/PEAT/issues/68>`__, `#28 <https://github.com/sandialabs/PEAT/issues/28>`__).
- Sign releases and publish build provenance (`#73 <https://github.com/sandialabs/PEAT/issues/73>`__).
- Add a cooldown to dependency updates (`#64 <https://github.com/sandialabs/PEAT/issues/64>`__), and audit GitHub Actions workflows with zizmor (`#54 <https://github.com/sandialabs/PEAT/issues/54>`__).
- Earn the OpenSSF Best Practices passing and silver badges, and track the OpenSSF Scorecard.

Reliability and usability
-------------------------

- Validate settings and configuration files against a schema, with clear errors for invalid YAML (`#76 <https://github.com/sandialabs/PEAT/issues/76>`__, `#77 <https://github.com/sandialabs/PEAT/issues/77>`__).
- Tab completion for the command line interface (`#24 <https://github.com/sandialabs/PEAT/issues/24>`__).
- Fix merging and de-duplication issues when multiple modules find the same device (`#22 <https://github.com/sandialabs/PEAT/issues/22>`__).
- Increase test coverage, and extend fuzz testing to more of the parsers that handle data from devices.

Architecture
------------

- Migrate the data model to Pydantic v2 (`#86 <https://github.com/sandialabs/PEAT/issues/86>`__).
- Refactor the pull API, and merge the pillage and parse functionality (`#52 <https://github.com/sandialabs/PEAT/issues/52>`__, `#49 <https://github.com/sandialabs/PEAT/issues/49>`__).
- Data model improvements, and automatically generated Elasticsearch type mappings (`#48 <https://github.com/sandialabs/PEAT/issues/48>`__, `#51 <https://github.com/sandialabs/PEAT/issues/51>`__).
- Investigate Kaitai Struct for binary file parsing (`#25 <https://github.com/sandialabs/PEAT/issues/25>`__).

Device support
--------------

- New and improved SEL device support, including SEL-362X and additional SEL-3620 pulls (`#79 <https://github.com/sandialabs/PEAT/pull/79>`__, `#21 <https://github.com/sandialabs/PEAT/issues/21>`__, `#53 <https://github.com/sandialabs/PEAT/issues/53>`__).
- OpenPLC Runtime v3 support, with a hands-on tutorial using GRFICS (`#94 <https://github.com/sandialabs/PEAT/pull/94>`__).
- A module verification script to help module developers (`#47 <https://github.com/sandialabs/PEAT/issues/47>`__).

Documentation
-------------

- Keep the documentation current with each release, and add more tutorials and examples.
