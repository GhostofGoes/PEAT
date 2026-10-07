****************************
Code guidelines and policies
****************************
Conventions for PEAT's Python code and Git history. Most are enforced by the tooling
(``pdm run format``, ``pdm run lint``, pre-commit, and CI); the rest are reviewed in pull
requests.

Code style
==========
- `PEP 8 <https://peps.python.org/pep-0008/>`__ applies, with one exception: lines may be
  up to 99 characters (``line-length`` in the ``[tool.ruff]`` section of
  ``pyproject.toml``). Individual lines can be excluded with ``# noqa: E501``.
- Run ``pdm run format`` before pushing. There's no need to worry about formatting by
  hand: `the Ruff formatter <https://docs.astral.sh/ruff/formatter/>`__ formats the code
  and `Ruff's isort rules <https://docs.astral.sh/ruff/rules/#isort-i>`__ sort imports.
- ``pdm run lint`` runs the linters: Ruff with the rule sets selected in
  ``pyproject.toml`` (pycodestyle, Pyflakes, bugbear, comprehensions, pytest style,
  pyupgrade, and more), `vulture <https://github.com/jendrikseipp/vulture>`__ for unused
  code, `codespell <https://github.com/codespell-project/codespell>`__ for spelling, and
  `doc8 <https://github.com/PyCQA/doc8>`__ for the reStructuredText files. Each Ruff rule
  is documented at ``ruff rule <code>``; if a rule doesn't fit a specific line, suppress it
  there with ``# noqa: <code>`` and a reason, rather than disabling it project-wide.
- Docstrings follow `PEP 257 <https://peps.python.org/pep-0257/>`__, with arguments and
  return values in the `Google style <https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings>`__
  (`Sphinx examples <https://www.sphinx-doc.org/en/master/usage/extensions/example_google.html>`__).
  Types go in annotations, not docstrings; the documentation build reads the annotations.
- Every module should have a module docstring describing what it is for and listing its
  authors with contact information, so it's clear who to ask about a part of the codebase.
- ``TODO`` comments are permitted. If the ``TODO`` is significant, discuss it with the
  team or open an issue on GitHub.
- No ``print()`` for messages to the user; see :doc:`logging`.

Type annotations
================
Python type annotations are used for all functions and methods, and for variables when
the type isn't obvious. They may look verbose for a dynamically typed language, but:

- They document expected types, which is invaluable in the deep device-level code that's
  hard to untangle if you aren't the original developer (the ControlLogix code is the
  prime example).
- The documentation build uses them for the types of parameters and return values,
  instead of docstrings that drift out of date.
- `mypy <https://mypy-lang.org/>`__ (``pdm run typecheck``) catches typing errors
  statically.
- Editors (Pylance in VS Code) catch mistakes such as arguments in the wrong order.

.. seealso::

   The :mod:`typing` module, `PEP 484 <https://peps.python.org/pep-0484/>`__ (type hints),
   and `PEP 526 <https://peps.python.org/pep-0526/>`__ (variable annotations)

Exception handling
==================
PEAT's approach differs from common Python guidance, and can be summed up as **"get as
much data as possible and fail safely."** If a function to collect some piece of data
fails, log that it failed and continue trying other methods and other data. Implement
this by wrapping code that may fail in ``try``/``except`` blocks that handle the generic
``Exception``, logging at an appropriate level (:doc:`logging`). If a failure is critical
to continuing the collection, or could affect the device's operation, log it in detail and
re-raise (or raise :class:`~peat.consts.DeviceError`) so that device's run is terminated,
while other devices continue. This is why ``try: ...; except Exception: ...`` appears in
many places; it is deliberate.

Other conventions
=================
- Timestamps are in the :term:`UTC` timezone unless there's a specific reason otherwise,
  such as a value recovered from a device with an unknown timezone, and
  :class:`~datetime.datetime` objects should be timezone-aware.
  :func:`peat.utils.parse_date` handles most formats.
- UTF-8 encoding for all files (unless required and documented otherwise). Pass
  ``encoding="utf-8"`` explicitly when reading or writing text to avoid Windows surprises.
- Hashes should be SHA-256 (PEAT records MD5, SHA-1, SHA-256, and SHA-512 for files
  because downstream tools want them; new code comparing hashes should use SHA-256).
- Strings and bytes: raw data is :class:`bytes`; use :class:`bytearray` only as an
  intermediate representation (e.g. building a file chunk by chunk). Convert with
  :meth:`str.encode` and :meth:`bytes.decode` using UTF-8.
  `This guide <https://stackoverflow.com/a/36149089>`__ covers hex and bytes conversions.
- Write files through :func:`peat.utils.write_file` or
  :meth:`DeviceData.write_file() <peat.data.models.DeviceData.write_file>`, which sanitize
  names, create directories, avoid clobbering (numbered duplicates), and respect the
  output configuration.
- Use the data model (:doc:`/developer/data_model`): put data in the defined fields, and
  vendor-specific leftovers in ``extra``. Don't invent parallel structures.
- Device IDs, IPs, and names in log messages make them useful; bind the logger with the
  target (see :doc:`logging`).

Git
===
- All changes are made on a branch; pushes directly to ``main`` are rejected.
- All branches are merged through a GitHub pull request, with a code review by another
  PEAT developer. Reviewers check that the change is reasonable and complete, look for
  edge cases, and for anything that seems "fishy" (see the review guidelines in
  :doc:`index`).
- Commit messages and PR titles follow Conventional Commits with a lowercase type
  (:doc:`index`). Scope commits to a single change.
- Open a *draft* pull request when work is nearing completion, to raise visibility and
  start discussion before the review.
- Before merging: ``AUTHORS`` and module docstring authors updated, tests added, CI
  passing, review by a maintainer.

Versioning
==========
Releases are tagged with a calendar version prefixed with ``v``, e.g. ``v2024.5.6`` for a
release on May 6th, 2024. The tag is created by the release workflow, not manually (see
:doc:`releases`).

The version of the Python package (``peat --version``) is derived from the Git tags by
``pdm-backend`` when PEAT is installed or built. Development builds get an automatically
generated version such as ``2024.5.6.dev801+gf79832d6.d20240506``. The release workflow
builds the artifacts before the tag exists, so it sets ``PDM_BUILD_SCM_VERSION`` to stamp
the release version into the executables, package, and documentation.

Security
========
PEAT runs with elevated privileges on sensitive networks. Treat anything that parses data
from a device or a file as untrusted input (devices can be compromised; files can be
crafted), avoid shelling out with user-controlled strings, and never log credentials
(the Elasticsearch URL is redacted for this reason). Report vulnerabilities per
``SECURITY.rst`` rather than in a public issue.

License
=======
By contributing to this project, you agree that your contributions will be licensed under
the `GNU General Public License v3.0 <https://github.com/sandialabs/PEAT/blob/main/LICENSE>`__
that covers the project. Third-party code must be license-compatible and attributed (see
``NOTICE``).
