.. _distribution:

**********************
Building and packaging
**********************
How PEAT is packaged and distributed, and how to build each distribution yourself. The
release workflow builds all of these automatically (see :doc:`releases`); building
locally is for testing changes to the packaging and for environments where you must
produce your own artifacts.

Distribution formats and goals
==============================
PEAT is a cross-platform Python program packaged in several formats, each for a platform
and situation:

.. list-table::
   :header-rows: 1
   :widths: 24 40 36

   * - Format
     - What it is
     - For
   * - Linux executable (``peat``)
     - Single self-contained file built with PyInstaller and made portable across
       distributions with StaticX
     - Field laptops, servers, and old distributions (RHEL 6, Ubuntu 14.04) without
       installing anything
   * - Windows executable (``peat.exe``)
     - Single self-contained file built with PyInstaller
     - Engineering workstations and Windows laptops, which are usually what's available on
       a control network
   * - Container image (``ghcr.io/sandialabs/peat``)
     - The CLI with its dependencies and Zeek, on a slim Debian/Python base
     - Reproducible runs anywhere with Docker or Podman; HEAT; CI
   * - Python package (wheel and sdist)
     - Standard Python distribution
     - Using PEAT as a library, integrating with other tools, development
   * - Sneakypeat (``sneakypeat``, ``sneakypeat.exe``)
     - Minimal scanner built from ``distribution/sneakypeat.py``
     - Red team exercises where a small footprint matters

The goals behind these formats:

- **Ease of use**: PEAT should run anywhere it's needed with minimal fuss, ideally "copy a
  file onto the system and run it".
- **Compatibility**: PEAT should run on the platforms relevant to its use cases and
  deployments: :term:`RHEL` (deployments), Ubuntu (developers), Kali (exercises and
  emulated environments), and Windows (real-world control networks almost always have a
  Windows machine with a path to the devices, such as an engineering workstation; getting
  PEAT there on a flash drive or through a data diode avoids the many problems of getting
  a Linux system onto the network). macOS compatibility is maintained on a best-effort
  basis for developers who use Macs.
- **Portability**: a reasonable size and easy to get onto a system, including isolated
  ones.

The platforms each format is supported on are listed in
:doc:`/getting_started/requirements`.

Linux executable
================
`PyInstaller <https://pyinstaller.org/en/stable/>`__ bundles PEAT and its Python
dependencies into one executable, and `StaticX <https://github.com/JonathonReinhart/staticx>`__
then bundles the system shared libraries so the result runs on other distributions and
versions (a package built on Ubuntu 24.04 works on Ubuntu 14.04 or RHEL 7).

.. warning::
   StaticX does **not** work with Pythons installed with `pyenv <https://github.com/pyenv/pyenv>`__
   or compiled manually, because the needed shared libraries aren't present. Use a system
   Python (from the distribution, or the deadsnakes PPA on Ubuntu).

.. code-block:: bash

   # Build tools (Debian/Ubuntu)
   sudo apt install -qyf python3-dev patchelf binutils scons libpq-dev libpq5

   # Environment with the "exe" dependency group (PyInstaller, StaticX)
   pdm install -d

   # Build. This reinstalls psycopg2 from source first so its libraries are bundled,
   # runs PyInstaller with distribution/peat.spec, then StaticX.
   pdm run build-linux-exe

   # Test
   ./dist/peat --version
   ./dist/peat --help
   ./dist/peat parse --list-modules
   ./dist/peat parse -d AwesomeTool -I examples/example_peat_module/ -- examples/example_peat_module/awesome_output.json

   # Inspect what's inside (the PyInstaller archive before StaticX is kept in build/)
   pdm run inspect-exe

The build script is ``distribution/build-linux-package.sh``; ``distribution/peat.spec`` is
the PyInstaller spec shared with the Windows build. If the build warns about
``Unexpected line in ldd output``, re-run the psycopg2 reinstall the script prints.

Windows executable
==================
The Windows distribution is a PyInstaller bundle built on Windows. Files involved:

- ``distribution/peat.spec``: the PyInstaller configuration (data files such as MIBs,
  the TC6 schema, and the ``manuf`` database; hidden imports; excludes)
- ``distribution/file_version_info.txt``: version metadata embedded in the ``.exe``
  (updated by ``distribution/update_file_version_info.py`` in CI; don't edit by hand)
- ``distribution/peat_icon.ico``: the executable's icon

.. code-block:: powershell

   # Prerequisites: a supported Python from python.org, PDM, and the
   # Microsoft Visual C++ 2015 Redistributable (VCRuntime140.dll)
   pdm install -d
   pdm run python .\distribution\update_file_version_info.py
   pdm run build-exe
   .\dist\peat.exe --version

``pdm run build-exe`` also works on Linux and macOS to produce a non-portable executable
for the build machine's own distribution (useful for quick tests of the packaging).

Hidden imports
--------------
PyInstaller only includes modules it can see being imported. Third-party device modules
loaded at runtime, and some libraries (pysnmp MIBs, ``dateutil``, ``manuf``) need to be
listed explicitly in ``hidden_imports`` in ``peat.spec``. The symptom of a missing one is
``Failed to import mypackage.mymodule: No module named 'csv'`` at runtime. See the notes in
``peat.spec`` and :doc:`/developer/module_developer_guide`.

Sneakypeat
==========
.. code-block:: bash

   pdm run build-sneakypeat          # Windows, or non-portable Linux
   pdm run build-linux-sneakypeat    # Portable Linux (StaticX)
   ./dist/sneakypeat --help
   ./dist/sneakypeat --scan localhost

The Linux build uses ``python -OO`` to strip docstrings, which saves about a megabyte.

Container image
===============
``distribution/build-docker.sh`` builds the multi-stage ``Dockerfile``: a ``builder``
stage installs the build tools, downloads the runtime ``.deb`` packages (including Zeek
6.0 from the Zeek project's repository) and creates the virtual environment with
``pdm install --prod``; the ``release`` stage copies the environment and installs the
downloaded packages onto a ``python:3.11-slim-bookworm`` base. The image is labeled with
the version and commit, sets ``PEAT_IN_CONTAINER``, and runs ``python -m peat`` as its
entry point.

.. code-block:: bash

   pdm run build-docker                       # Builds ghcr.io/sandialabs/peat:latest locally
   docker run --rm -i ghcr.io/sandialabs/peat --version

   # Use a different registry for the base image (e.g. an internal mirror)
   docker build --build-arg REGISTRY_IMAGE="registry.example.net/python" -t peat:test .

The GitHub Actions ``Docker Build and Release`` workflow builds and pushes the image on
every push to ``main`` (tag ``main`` and the commit SHA) and on release tags (the version
tag and ``latest``). You can't push to ``ghcr.io/sandialabs`` from a local build.

Python package
==============
.. code-block:: bash

   pdm build                 # dist/PEAT-<version>-py3-none-any.whl and dist/peat-<version>.tar.gz
   ls -lAht ./dist/
   pdm run wheel-files       # List the files in the wheel
   pdm run check-sdist       # Verify the sdist contains exactly what it should

The package metadata, included files, and the SCM-derived version are configured in
``pyproject.toml`` (``[project]``, ``[tool.pdm.build]``, ``[tool.pdm.version]``). The
version comes from the latest ``v*`` Git tag; set ``PDM_BUILD_SCM_VERSION`` to override it
(the release workflow does this because it builds before tagging).

Man page and documentation
==========================
.. code-block:: bash

   pdm run docs-man          # _docs_man/peat.1
   pdm run docs-html         # _docs_html/

See :doc:`documentation`. The release attaches the HTML as ``peat_docs.zip`` and ships the
man page in the Linux bundle, where ``distribution/linux-install-script.sh`` installs it.

Cleaning up
===========
.. code-block:: bash

   pdm run clean-build       # dist/, build/
   pdm run clean-docs        # Documentation outputs and caches
   pdm run clean             # Caches, build artifacts, test artifacts
   pdm run clean-all         # Everything above plus PEAT output directories and generated images

Updating pinned GitHub Actions
==============================
The workflows pin every action to a commit SHA for supply-chain safety. To update them to
the latest releases:

.. code-block:: bash

   pdm run update-actions    # Runs mheap/pin-github-action in Docker against .github/workflows
