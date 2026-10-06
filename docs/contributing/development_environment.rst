***********************
Development environment
***********************
How to set up a machine for working on PEAT's code. There are two ways: a
:ref:`devcontainer <devcontainer>`, which is the recommended, "batteries included" method
that avoids platform-specific issues, and a :ref:`manual setup <manual-setup>` for
advanced developers or those who want more control over their environment.

The recommended editor is `Visual Studio Code (VS Code) <https://code.visualstudio.com/>`__,
and the project uses `PDM <https://pdm-project.org/en/latest/>`__ for dependency
management and task running. Python 3.11, 3.12, or 3.13 is required (3.12 or newer to
build the documentation).

.. _devcontainer:

Devcontainer
============
#. Create a fork of the `PEAT GitHub repository <https://github.com/sandialabs/PEAT>`__.
#. Ensure Git is installed. If it isn't, follow `these instructions <https://git-scm.com/install/>`__.
#. Install Docker:

   - Linux: follow the `Linux Docker install guide <https://docs.docker.com/engine/install/>`__
     (do **not** install using ``snap``).
   - macOS: follow the `macOS Docker install guide <https://docs.docker.com/desktop/setup/install/mac-install/>`__.
   - Windows:

     #. Open a PowerShell terminal as an Administrator (right-click PowerShell, "Run as
        Administrator").
     #. Run ``wsl --install``.
     #. Reboot.
     #. Follow the `Windows Docker instructions <https://docs.docker.com/desktop/setup/install/windows-install/>`__
        to download and install "Docker Desktop for Windows", and check the box to use the
        WSL 2 backend. Use ``Docker Desktop for Windows - x86_64``, *not* the Microsoft
        Store or ARM versions.

#. Follow the `Dev Containers setup guide <https://code.visualstudio.com/docs/devcontainers/containers#_system-requirements>`__
   for Docker, VS Code, and the Dev Containers extension.
#. Clone your fork and add the main repository as the ``upstream`` remote:

   .. code-block:: bash

      git clone https://github.com/<your-username>/peat.git
      cd peat
      git remote add upstream https://github.com/sandialabs/PEAT.git

#. Open the folder in VS Code (``code .``). When prompted at the bottom right to reopen in
   a container, accept. If the prompt doesn't appear, press :kbd:`Ctrl+Shift+P`, search
   for ``Dev Containers: Rebuild and Reopen in Container``, and press Enter.

The devcontainer uses a pre-built image (``ghcr.io/ghostofgoes/peat/peat-devcontainer``),
rebuilt by CI whenever the dependencies or the devcontainer configuration change. On first
start it runs ``pdm install -d`` and ``pre-commit install`` (``.devcontainer/setup.sh``),
and it comes with the recommended VS Code extensions (Ruff, Python, GitLens, YAML, XML,
hex editor, and others) and settings.

.. _manual-setup:

Manual setup
============
.. note::
   On Windows, we strongly recommend PowerShell when setting up manually.

#. Create a fork of the `PEAT GitHub repository <https://github.com/sandialabs/PEAT>`__.
#. Install Python 3.11, 3.12, or 3.13:

   - Ubuntu 22.04: ``sudo apt install -y python3.11 python3.11-dev python3.11-venv``
   - Ubuntu 24.04: ``sudo apt install -y python3 python3-dev python3-venv`` (Python 3.12)
   - Windows: download from `python.org <https://www.python.org/downloads/windows/>`__.
     During install, check "Add Python to PATH". Also install
     `Npcap <https://npcap.com/>`__ for Scapy (skip if Wireshark or Nmap is installed).
   - macOS: `python.org <https://www.python.org/downloads/macos/>`__ or Homebrew.

#. Ensure Git is installed (`instructions <https://git-scm.com/install/>`__).
#. `Install PDM <https://pdm-project.org/en/latest/#installation>`__.
#. Clone your fork and add the upstream remote:

   .. code-block:: bash

      git clone https://github.com/<your-username>/peat.git
      cd peat
      git remote add upstream https://github.com/sandialabs/PEAT.git

#. Create the virtual environment and install all dependencies:

   .. code-block:: bash

      pdm config check_update false   # Faster, and avoids proxy-related errors
      pdm install -d

   PDM creates the environment in ``./.venv/`` and manages it; there is no need to
   activate it. Use ``pdm run <command>`` for anything that needs it.

#. Check that it works:

   .. code-block:: bash

      pdm run peat --version
      pdm run peat --help
      pdm run python --version

#. Set up the `pre-commit <https://pre-commit.com/>`__ hooks:

   .. code-block:: bash

      pdm run pre-commit install
      pdm run pre-commit run --all-files

#. Make sure linting and tests work:

   .. code-block:: bash

      pdm run format
      pdm run lint
      pdm run test-full

System packages
---------------
Some dependencies need system libraries, and some features need tools:

- Linux: ``sudo apt install -y tcpdump libpcap0.8 libpcap-dev libpq-dev libpq5 libxml2-dev libxslt1-dev lrzsz qemu-utils graphviz``
  (libpcap for Scapy, libpq for PostgreSQL, libxml2/libxslt for XML parsing, ``lrzsz``
  for SEL YMODEM transfers, ``qemu-utils`` for pillage, Graphviz for the documentation's
  class diagrams).
- Building the Linux executable needs ``python3-dev patchelf binutils scons`` as well; see
  :doc:`building`.

Notes
=====
- `pre-commit <https://pre-commit.com/>`__ catches common issues before they're committed
  and pushed: commit message format (Conventional Commits), Ruff linting and formatting,
  file hygiene (large files, merge conflict markers, line endings), and Towncrier news
  fragment validation.
- Edits to ``.py`` files don't require a reinstall; the package is installed in editable
  mode. Re-run ``pdm install -d`` after pulling changes to ``pyproject.toml`` or
  ``pdm.lock``.
- Tests are run with ``pytest`` (see :doc:`testing`).
- In the :doc:`developer reference </developer/index>`, the ``[source]`` link next to a
  documented class or function shows its code, which saves time when the source isn't at
  hand.
- VS Code's Remote Development extensions are helpful when working on a remote server, a
  device behind a jump host (such as a :term:`SCEPTRE` environment), or in :term:`WSL`.
  See `VS Code Remote Development <https://code.visualstudio.com/docs/remote/remote-overview>`__.
- A ``launch.json`` with debugger configurations for the CLI commands is in
  ``examples/vscode/``.

Helpful PDM commands
====================
``pdm run -l`` lists every script with a description. The ones you'll use most:

.. code-block:: bash

   pdm run peat ...          # Run PEAT from the source tree (code changes apply immediately)
   pdm run -l                # List scripts

   pdm run format            # Format code (Ruff formatter and import sorting)
   pdm run lint              # All quality checks: vulture, codespell, ruff, format check, doc8
   pdm run check             # Ruff only, no changes
   pdm run fix               # Ruff with safe auto-fixes
   pdm run typecheck         # mypy

   pdm run test              # Unit tests, excluding slow tests
   pdm run test-full         # Unit tests including slow tests
   pdm run pytest -k name    # Any pytest invocation

   pdm run docs-venv         # Create/update the documentation environment (Python 3.12+)
   pdm run docs-html         # Build the HTML documentation into _docs_html/
   pdm run docs-a11y         # Accessibility checks of the built documentation

   pdm run build-exe         # Executable with PyInstaller (Windows, or non-portable Linux)
   pdm run build-linux-exe   # Portable Linux executable (PyInstaller + StaticX)
   pdm run build-docker      # Container image
   pdm build                 # Python wheel and sdist into dist/

   pdm run clean             # Remove caches and build artifacts
   pdm run clean-all         # Reset to a clean checkout (keeps the virtualenv)

   # Test with a specific Python version, e.g. 3.12
   pdm use -f 3.12
   pdm install -d
   pdm run test

Dependency management
=====================
Runtime dependencies live in ``[project] dependencies`` in ``pyproject.toml`` with a
comment for each explaining what it's for and which modules need it; development
dependencies are grouped (``lint``, ``test``, ``exe``, ``dev``, ``docs``) under
``[tool.pdm.dev-dependencies]``. Exact versions are pinned in ``pdm.lock``.

.. code-block:: bash

   pdm add some-package                # Add a runtime dependency
   pdm add -G test some-plugin         # Add to a group
   pdm outdated                        # What can be updated
   pdm lock --update-reuse -d          # Update the lock with minimal version bumps
   pdm lock -d                         # Update the lock to the newest allowed versions
   pdm sync -d                         # Install exactly what the lock says

Several runtime packages are pinned for compatibility with old devices (``requests``
2.29, ``pyserial`` 3.4, ``paramiko`` 2.12, ``pydantic`` 1.10); the comments in
``pyproject.toml`` explain each. The documentation uses a separate lock file
(``pdm.docs.lock``) that relaxes the ``requests`` pin; see :doc:`documentation`.
