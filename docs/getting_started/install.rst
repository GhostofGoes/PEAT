*******
Install
*******
PEAT is distributed in several formats, all published with each
`release on GitHub <https://github.com/sandialabs/PEAT/releases>`__:

- Pre-built, self-contained executables for Linux (``peat``) and Windows (``peat.exe``).
  **Recommended for most users.** Python is not required.
- A :term:`container <Container>` image on the GitHub Container Registry
  (``ghcr.io/sandialabs/peat``) for :term:`Docker` and :term:`Podman`.
- A Python package (wheel and source distribution) for using PEAT as a library or
  installing it into an existing Python environment.
- The Linux man page (``peat.1``), the HTML documentation (``peat_docs.zip``), and the
  :term:`Sneakypeat` executables.

Check the :doc:`requirements` first, then pick the installation method for your platform.
If you need to build the executables yourself, see :doc:`/contributing/building`.

Installation
============

.. tab-set::

   .. tab-item:: :peat-icon:`linux` Linux
      :sync: linux

      **Scripted installation (recommended)**

      The install script downloads the latest release of the executable and the man page,
      installs them to ``/usr/local/bin/peat`` and ``/usr/local/share/man/man1/peat.1``,
      and updates the manual database if ``mandb`` is present.

      .. code-block:: bash

         # Download the script
         curl -fLO https://raw.githubusercontent.com/sandialabs/PEAT/refs/heads/main/scripts/install_peat.sh

         # Review the script before running it
         less install_peat.sh

         # Run it (root is required to write to /usr/local)
         chmod +rx install_peat.sh
         sudo ./install_peat.sh

         # Verify the installation
         peat --version
         man peat

      The one-liner equivalent is ``curl -sSL <script-url> | sudo sh -``. We strongly
      recommend reviewing scripts before piping them to a shell.

      **Manual installation**

      For systems without Internet access, download ``peat`` and ``peat.1`` from the
      `releases page <https://github.com/sandialabs/PEAT/releases>`__ (or the
      ``peat_linux_<version>.tgz`` bundle, which also contains the install script and
      example configuration files), copy them to the system, then:

      .. code-block:: bash

         sudo cp ./peat /usr/local/bin/peat
         sudo chmod +rx /usr/local/bin/peat
         peat --version

         # Install the manual page (optional, but recommended)
         sudo mkdir -p /usr/local/share/man/man1/
         sudo cp ./peat.1 /usr/local/share/man/man1/
         sudo mandb   # If this fails, install "man-db": sudo apt install -y man-db
         man peat

      **Running without installing**

      .. code-block:: bash

         chmod u+x ./peat
         ./peat --version
         man ./peat.1

   .. tab-item:: :peat-icon:`windows` Windows
      :sync: windows

      The Windows executable needs no installation and can be run from wherever it is
      downloaded. An install script is also available that downloads the latest release to
      ``%LOCALAPPDATA%\Programs\peat.exe`` and adds that directory to the user's ``PATH``
      (no administrator rights needed).

      **Scripted installation**

      .. code-block:: powershell

         powershell -ExecutionPolicy ByPass -c "irm https://raw.githubusercontent.com/sandialabs/PEAT/refs/heads/main/scripts/install_peat.ps1 | iex"

         # Open a new terminal, then verify
         peat.exe --version

      **Running without installing**

      Download ``peat.exe`` (or the ``peat_windows_<version>.zip`` bundle, which includes
      example configuration files) from the
      `releases page <https://github.com/sandialabs/PEAT/releases>`__, open a PowerShell
      terminal in that folder, and run:

      .. code-block:: powershell

         .\peat.exe --version
         .\peat.exe --help

      We recommend running in an Administrator PowerShell terminal for scans and pulls;
      see :ref:`windows-usage` for details. Microsoft Defender SmartScreen may warn about
      an unrecognized app the first time the executable runs.

   .. tab-item:: :peat-icon:`docker` Container
      :sync: container

      The container image provides an isolated and reproducible way to run PEAT on any
      platform with a container runtime. Replace ``docker`` with ``podman`` when using
      Podman (for example on :term:`RHEL`).

      .. code-block:: bash

         docker pull ghcr.io/sandialabs/peat:latest

         # Verify the container runs
         docker run --rm -i ghcr.io/sandialabs/peat:latest --version
         docker run --rm -i ghcr.io/sandialabs/peat:latest --help

      Release images are tagged with the version (for example
      ``ghcr.io/sandialabs/peat:2026.9.2``); ``latest`` is the most recent release, and
      ``main`` tracks the development branch.

      Results are only saved if the output directory is mounted into the container, and
      scanning requires ``--network host``. Refer to :doc:`/user_guide/containers` for the
      full set of arguments and examples.

      **Offline (air-gapped) systems**

      On an Internet-connected system, save the image to a tar file:

      .. code-block:: bash

         docker pull ghcr.io/sandialabs/peat:latest
         docker save -o peat_docker_image.tar ghcr.io/sandialabs/peat:latest

      Copy ``peat_docker_image.tar`` to the isolated system (via approved removable media
      or transfer mechanism), then load and verify it:

      .. code-block:: bash

         docker load -i peat_docker_image.tar
         docker run --rm -i ghcr.io/sandialabs/peat:latest --version

   .. tab-item:: :peat-icon:`python` Python package
      :sync: python

      Install the Python package to use PEAT as a library (``import peat``) or to get the
      ``peat`` command inside an existing Python environment. Python 3.11, 3.12, or 3.13
      is required.

      .. code-block:: bash

         # From the wheel attached to a release (recommended)
         python3 -m pip install ./PEAT-2026.9.2-py3-none-any.whl

         # Or directly from the repository (latest development version)
         python3 -m pip install "git+https://github.com/sandialabs/PEAT.git"

         # Isolated install of the CLI with pipx
         pipx install ./PEAT-2026.9.2-py3-none-any.whl

         peat --version
         python3 -c "import peat; print(peat.__version__)"

      Some dependencies need system libraries on Linux (``libpcap`` for Scapy, ``libpq``
      for PostgreSQL support, ``libxml2``/``libxslt`` for XML parsing). On Debian/Ubuntu:
      ``sudo apt install -y tcpdump libpcap0.8 libpq5 libxml2 libxslt1.1``. To set up a
      development environment instead, see :doc:`/contributing/development_environment`.

Upgrading
=========
- **Executable**: re-run the install script, or download the new executable and replace
  the old one. ``peat --version`` prints the installed version.
- **Container**: ``docker pull ghcr.io/sandialabs/peat:latest``.
- **Python package**: ``python3 -m pip install --upgrade <new wheel or git URL>``.

Each run of PEAT records the version that produced it in the run's summary and metadata
files (``peat_version``), so results from different versions can be told apart.

Uninstalling
============
- **Linux**: ``sudo rm /usr/local/bin/peat /usr/local/share/man/man1/peat.1``
- **Windows**: delete ``%LOCALAPPDATA%\Programs\peat.exe``. The install script adds
  ``%LOCALAPPDATA%\Programs`` to your user ``PATH``; remove it if nothing else uses it
  (Settings > System > About > Advanced system settings > Environment Variables).
- **Container**: ``docker rmi ghcr.io/sandialabs/peat:latest``
- **Python package**: ``python3 -m pip uninstall PEAT``

PEAT also leaves behind its output (``./peat_results/`` and ``./pillage_results/`` in the
directories where it was run), which you may want to keep or securely delete.

PEAT releases
=============
Releases are managed via `GitHub Releases <https://github.com/sandialabs/PEAT/releases>`__
and are versioned by date (for example ``v2026.9.2``, see :doc:`/changelog`). A release
usually consists of:

- The Linux and Windows executables (``peat`` and ``peat.exe``), and bundles of each with
  the example configuration files (``peat_linux_<version>.tgz``,
  ``peat_windows_<version>.zip``)
- The Python source distribution (``.tar.gz``) and binary wheel (``.whl``)
- The Linux man page (``peat.1``)
- The container image via the GitHub Container Registry (``ghcr.io/sandialabs/peat``)
- The documentation in HTML format (``peat_docs.zip``)
- :term:`Sneakypeat` executables (``sneakypeat`` and ``sneakypeat.exe``)

Builds of the ``main`` branch are also available from the
`GitHub Actions <https://github.com/sandialabs/PEAT/actions>`__ workflow runs as
artifacts, for trying out unreleased changes.

Next steps
==========
Continue to the :doc:`quickstart` to run your first scan, pull, and parse.
