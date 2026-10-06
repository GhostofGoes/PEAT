*************
Documentation
*************
How the documentation is organized, built, checked, and written. The documentation is
built with `Sphinx <https://www.sphinx-doc.org/en/master/>`__ from the reStructuredText files in
``docs/``, uses the `Furo <https://pradyunsg.me/furo/>`__ theme, and is published to
https://sandialabs.github.io/PEAT/ by the ``Documentation`` GitHub Actions workflow on
every push to ``main`` and on every release.

Organization
============
The documentation follows the `Diátaxis <https://diataxis.fr/>`__ framework, separating
material by what the reader is trying to do:

.. list-table::
   :header-rows: 1
   :widths: 24 30 46

   * - Section (directory)
     - Purpose
     - Contains
   * - Getting started (``getting_started/``)
     - Orientation and first steps
     - Introduction, supported devices, requirements, install, quickstart
   * - Tutorials (``tutorials/``)
     - Learning by doing: story-driven, end-to-end walkthroughs
     - One page per scenario
   * - User guide (``user_guide/``)
     - How-to: task-oriented guidance for each command and feature
     - One page per command or topic; also the ``man peat`` page
   * - Reference (``reference/``)
     - Facts to look up: exhaustive and generated where possible
     - CLI, configuration, output files, summaries, Elasticsearch, schema, protocols,
       device references, example artifacts, glossary
   * - Developer reference (``developer/``)
     - The Python API and how to extend PEAT
     - Module developer guide, examples, data model, API pages (autodoc)
   * - Design (``design/``)
     - Understanding: how and why PEAT works the way it does
     - Architecture, run lifecycle, scanning, pull/parse/push, configuration and state
   * - Contributing (``contributing/``)
     - Working on PEAT
     - This section; ``CONTRIBUTING.rst`` is included as its index

When adding a page, ask which question it answers ("how do I...", "what is...", "why...",
"show me") and put it in the matching section. Prefer extending an existing page over
creating a new one.

Building the documentation
==========================
The documentation has its own virtual environment and lock file, because recent Sphinx
releases need a newer ``requests`` than PEAT pins at runtime (PEAT needs ``urllib3`` 1.x
to talk to some old devices; the docs build only imports PEAT for autodoc). The
override is in ``docs/overrides.txt`` and applies only to ``pdm.docs.lock``.

.. code-block:: bash

   # One-time setup: a "docs" virtualenv from pdm.docs.lock (requires Python 3.12 or newer)
   pdm run docs-venv

   # Build the HTML docs into _docs_html/ (warnings are errors)
   pdm run docs-html
   pdm run docs-serve          # then open http://localhost:8000/

   # The man page into _docs_man/peat.1
   pdm run docs-man
   man ./_docs_man/peat.1

   # Checks
   pdm run docs-linkcheck      # External links (slow; network required)
   pdm run docs-a11y           # Accessibility checks of the built HTML
   pdm run lint                # Includes doc8 for the .rst files

   # After changing the docs dependency group in pyproject.toml
   pdm run docs-lock
   pdm run docs-venv

The commands work the same on Windows (PowerShell or ``cmd``); ``pdm run docs-venv`` is
a small Python helper (``scripts/docs_venv.py``) rather than a shell script for that
reason. If it complains that no suitable Python was found, create the environment with
an explicit interpreter, ``pdm venv create --name docs 3.12``, and run it again (PDM can
also install Python 3.12 for you: ``pdm python install 3.12``). Graphviz (``dot``) must
be installed for the class diagrams: ``sudo apt install graphviz`` on Debian/Ubuntu,
``winget install Graphviz.Graphviz`` on Windows, ``brew install graphviz`` on macOS.

The build runs ``sphinx-build -W --keep-going``: **every warning fails the build**, in CI
and locally, so broken references, missing files, malformed tables, and autodoc problems
are caught at build time rather than noticed later. Fix the warning rather than
suppressing it; if a warning is truly unavoidable, discuss it in the pull request.

``pdm run docs-html`` first generates ``docs/developer/dependencies_table.rst`` with
``pip-licenses`` (``pdm run dep-doc``); the file is ignored by Git.

Conventions
===========
- **Headings**: ``*`` over and under for page titles, then ``=``, ``-``, ``^``, ``+``.
  One title per page. Keep titles short; the sidebar shows them.
- **Line length**: wrap prose at about 90 to 100 characters (doc8's line length check
  is disabled, but long lines are hard to review).
- **Links**: ``:doc:`` for pages (absolute from the docs root, ``/user_guide/scan``),
  ``:ref:`` for sections with labels, and ``:attr:``/``:class:``/``:func:`` for code. Use
  anonymous external links (two trailing underscores) to avoid duplicate-target warnings.
  Link terms to the :doc:`glossary </glossary>` with ``:term:`` on first use in a page;
  add missing terms to the glossary rather than defining them inline.
- **Code**: ``.. code-block:: bash`` for commands, ``console`` for commands with their
  output (``$`` prompt; the copy button strips prompts), ``yaml``, ``json``, ``python``,
  ``powershell``, ``text`` for everything else. Use ``literalinclude`` to pull in files
  from the repository (``examples/``, ``peat/cli_args.py``) rather than copying them.
- **Tabs** (``.. tab-set::`` / ``.. tab-item::`` from sphinx-design) for per-platform
  variants, with ``:sync:`` keys ``linux``, ``windows``, ``container``, ``python`` so the
  choice follows the reader across pages. Cards and dropdowns are also available.
- **Tables**: ``list-table`` with ``:widths:`` for hand-written tables, ``csv-table`` for
  data kept in CSV files. The device support tables are generated from
  ``getting_started/supported_devices.csv`` by the ``peat-device-table`` directive
  (``docs/_ext/peat_docs.py``); edit the CSV, not the page. Tables wrap rather than
  scroll (``_static/custom.css``), so keep cell text reasonably short.
- **Admonitions**: ``note``, ``tip``, ``warning``, ``danger`` (for actions that change
  devices), ``seealso``. Don't stack several in a row.
- **Addresses and names** in examples: ``192.0.2.0/24`` and ``198.51.100.0/24``
  (documentation ranges), ``example.net``. Never real credentials.
- **Diagrams** are inline SVG files in ``docs/images/`` included with
  ``.. raw:: html`` + ``:file:``, with an ``.. only:: not html`` text alternative for
  the man page. They use Furo's CSS variables (``var(--color-foreground-primary)``,
  ``var(--color-brand-primary)``, ...) so they adapt to light and dark mode, and carry a
  ``<title>`` and ``<desc>`` with ``role="img"`` for screen readers. Edit them as text.
- **Redirects**: when a page moves or is renamed, add its old name to ``redirects`` in
  ``docs/conf.py`` (sphinx-reredirects) so existing links keep working.
- **Spelling**: codespell runs on the docs; add legitimate words to
  ``ignore-words-list`` in ``pyproject.toml`` only when needed.

Accessibility
=============
The documentation aims to meet `WCAG 2.1 AA <https://www.w3.org/WAI/standards-guidelines/wcag/>`__.
Furo provides a solid base (semantic HTML, skip link, keyboard-operable navigation,
color schemes that respect the operating system), and the project adds:

- Brand colors chosen for at least 4.5:1 contrast with their backgrounds in both color
  schemes, visible focus indicators, and respect for ``prefers-reduced-motion``
  (``docs/_static/custom.css``).
- Alternative text for every image, and titles and descriptions on inline diagrams.
- Tables that wrap instead of scrolling horizontally.

``pdm run docs-a11y`` runs `axe-core <https://github.com/dequelabs/axe-core>`__ against
the built HTML in headless Chromium (``scripts/docs_a11y.py``) and fails on serious or
critical violations. It runs in CI on pull requests. Run it after changing templates,
CSS, or anything with custom HTML, and when adding a diagram.

Writing for the reader
======================
- Lead with what the reader needs to do or know; put background after.
- Prefer concrete commands and their expected output over descriptions of commands.
  Trim output to the lines that matter and say so (``...``).
- Say what PEAT *does* in the present tense, and be explicit about limits and gaps.
  "Not yet implemented" is more useful than silence.
- Define a term once, in the glossary, and link to it.
- One idea per paragraph; use lists for parallel items and tables for anything with
  more than two attributes.
- Check your facts against the code (the options in ``peat/settings.py``, the arguments
  in ``peat/cli_args.py``, the behavior in ``peat/api/``). Documentation that disagrees
  with the code is worse than none.

Checking links
==============
``pdm run docs-linkcheck`` checks every external link. Some sites block automated
requests (Stack Overflow, several vendor sites); those are listed in ``linkcheck_ignore``
in ``docs/conf.py``, and known-good redirects in ``linkcheck_allowed_redirects``. Update
URLs that have permanently moved rather than adding them to the ignore list. The check
runs in CI as a non-blocking job, since external sites come and go.

Publishing
==========
The ``Documentation`` workflow builds the HTML with ``-W`` on pull requests (as a check)
and on pushes to ``main`` (deploying to GitHub Pages), and the release workflow
dispatches it after creating a release tag so the published version string is current.
The HTML is also attached to each release as ``peat_docs.zip``, and the man page is
installed with the Linux executable. See :doc:`ci` and :doc:`releases`.

A PDF build with `rinohtype <https://github.com/brechtm/rinohtype>`__ is a long-standing
TODO (the dependency is present, the configuration is not).
