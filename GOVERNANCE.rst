**********
Governance
**********

PEAT is an open source project developed and maintained by `Sandia National Laboratories <https://www.sandia.gov/>`__. The source code is hosted in the `sandialabs GitHub organization <https://github.com/sandialabs>`__, which Sandia owns and administers.

Decision making
---------------

PEAT is maintainer-led. Decisions about the project are made by the maintainers, in public wherever possible:

- Changes are proposed as GitHub pull requests, and features and bugs are discussed in GitHub issues. Anyone can comment.
- A pull request is merged once a maintainer approves it and CI passes. Refer to the :doc:`contributing` for the requirements.
- Larger decisions (new major features, breaking changes, dependency or platform support changes, the :doc:`roadmap`) are discussed in an issue first. The maintainers aim for consensus. If they can't reach it, the maintainers decide by majority, and Sandia's PEAT project leadership makes the final call when needed.
- Security issues are handled privately, as described in the :doc:`security_policy`.

Roles and responsibilities
--------------------------

Users
   Anyone who uses PEAT. Users can report bugs, request features, and ask questions in `GitHub issues <https://github.com/sandialabs/PEAT/issues>`__.

Contributors
   Anyone who contributes code, documentation, tests, or other changes through a pull request. Contributors follow the :doc:`contributing` and the :doc:`code_of_conduct`. Contributors are listed in ``AUTHORS``.

Module authors
   Contributors who wrote or maintain a device module are listed in the ``Authors`` section of that module's docstring, and are the first point of contact for questions about it.

Maintainers
   Maintainers have write access to the repository. They review and merge pull requests, triage issues, run releases, respond to security reports, and set the project's direction. Maintainers are listed below, and in ``.github/CODEOWNERS`` as the default reviewers.

Administrators
   Sandia staff who administer the ``sandialabs`` GitHub organization. They can grant and remove repository access, including when a maintainer leaves.

Current maintainers
^^^^^^^^^^^^^^^^^^^

- Christopher Goes (`@GhostofGoes <https://github.com/GhostofGoes>`__)
- Bryan Watson (`@BugFriendlyGarden <https://github.com/BugFriendlyGarden>`__)

Becoming a maintainer
^^^^^^^^^^^^^^^^^^^^^

Contributors with a history of high-quality contributions and reviews may be invited to become maintainers by the existing maintainers.

Continuity
----------

PEAT is set up so the project can continue with minimal interruption if any one person becomes unavailable:

- At least two maintainers have permission to merge pull requests, triage issues, and run releases.
- Releases are built, signed, and published by GitHub Actions workflows in the repository (refer to the :doc:`contributing`), so no individual's machine, keys, or credentials are needed to make a release.
- The ``sandialabs`` organization is administered by Sandia, which can grant access to new maintainers if needed.
- Project knowledge is kept in the repository and its public documentation, not with individuals.
