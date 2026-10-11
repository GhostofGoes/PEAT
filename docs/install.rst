*******
Install
*******
This section documents how to setup PEAT for optimal use on each supported platform. Refer to :doc:`operate` for next steps after completing installation.

PEAT is distributed in multiple formats customized to each supported platform. All formats are included in `official releases on GitHub <https://github.com/sandialabs/PEAT/releases>`__. If you need to build the executables manually or know more about the various distribution methods, refer to the :ref:`distribution`.

Installation
------------
The recommended method of installation for most users is to use the latest pre-built executable release (``peat`` on Linux and ``peat.exe`` on Windows). Additionally, a :term:`Container` image is available for use with :term:`Docker` or :term:`Podman`.

Linux
^^^^^
The recommended method of installation for most users is to run the Bash script, however other methods of installation are documented here in case the installation script doesn't work for your use case.

Scripted installation
+++++++++++++++++++++
.. code-block:: bash

   # Download script
   curl -fLO https://raw.githubusercontent.com/sandialabs/PEAT/refs/heads/main/scripts/install_peat.sh

   # Verify script contents to ensure they are trusted
   less install_peat.sh

   # Run script
   chmod +rx install_peat.sh
   sudo ./install_peat.sh

   # Verify installation
   peat --version
   man peat

The script installs to ``/usr/local`` by default. It honors the standard ``PREFIX`` and ``DESTDIR`` environment variables, so it can install without root to a user-writable location, or stage files for packaging:

.. code-block:: bash

   # Install for the current user only (no sudo needed)
   PREFIX="$HOME/.local" ./install_peat.sh

   # Stage the files under ./pkgroot/usr/local for packaging
   DESTDIR="$PWD/pkgroot" ./install_peat.sh

Manual Installation
+++++++++++++++++++
These steps are intended for use in environments where there is no Internet access (or access is restricted). The manual page is optional, but recommended.

.. warning::
   This assumes the files ``peat`` and ``peat.1`` are in the current working directory.

.. code-block:: bash

   sudo cp ./peat /usr/local/bin/peat
   sudo chmod +rx /usr/local/bin/peat

   # Verify installation
   peat --version

   # Install the manual page ("manpage")
   sudo mkdir -p /usr/local/share/man/man1/
   sudo cp ./peat.1 /usr/local/share/man/man1/

   # (Optional) Update manpage database
   # If this command fails, then the package "man-db" needs to be installed
   # sudo apt install -y man-db
   sudo mandb

   # Verify manual page
   man peat


Usage without installation
++++++++++++++++++++++++++

.. warning::
   This assumes the file ``peat`` is in the current working directory.

.. code-block:: bash

   # Mark the file as executable, then run to verify it works
   chmod u+x ./peat
   ./peat --version

   # View man page
   man ./peat.1

Windows
^^^^^^^
The Windows distribution does not require any special installation steps and is usually run from wherever the executable is copied to. However, there is a install script that will place it in Local AppData and add to user's PATH for a more persistent installation.

We recommend verifying that the executable works before using it in a deployed environment. There are some special considerations regarding usage, refer to :ref:`windows-usage` for further details.

Scripted installation
+++++++++++++++++++++

.. code-block:: powershell

   powershell -ExecutionPolicy ByPass -c "irm https://raw.githubusercontent.com/sandialabs/PEAT/refs/heads/main/scripts/install_peat.ps1 | iex"

Usage without installation
++++++++++++++++++++++++++

.. code-block:: powershell

   .\peat.exe --version
   .\peat.exe --help

Container
^^^^^^^^^
The :term:`Container` image provides a isolated and reliable method of executing PEAT on any platform with a container runtime. It is usable with both :term:`Docker` and :term:`Podman`. Refer to the :ref:`containers` documentation for further details on the Container distribution and it's usage.

Docker
++++++
.. code-block:: bash

   docker pull ghcr.io/sandialabs/peat:latest

   # Verify the container is able to run
   docker run -i ghcr.io/sandialabs/peat:latest --version
   docker run -i ghcr.io/sandialabs/peat:latest --help

Podman
++++++
.. code-block:: bash

   podman pull ghcr.io/sandialabs/peat:latest

   # Verify the container is able to run
   podman run -i ghcr.io/sandialabs/peat:latest --version
   podman run -i ghcr.io/sandialabs/peat:latest --help

Offline system install
++++++++++++++++++++++

The container image can be used on isolated or Internet-restricted networks by downloading the image on a Internet-connected system, exporting it to a file, copying to the isolated network, then loading the image from the tar. This should also work for :term:`Podman`.

1. On the Internet-connected system, pull the PEAT container image

   .. code-block:: bash

      docker pull ghcr.io/sandialabs/peat:latest

2. Save the image to a tar file for transfer

   .. code-block:: bash

      docker save -o peat_docker_image.tar ghcr.io/sandialabs/peat:latest

3. Copy ``peat_docker_image.tar`` to the isolated system (for example, via approved removable media or transfer mechanism).

4. On the isolated system, load the image from the tar file

   .. code-block:: bash

      docker load -i peat_docker_image.tar

5. Verify the container runs and reports its version

   .. code-block:: bash

      docker run -i ghcr.io/sandialabs/peat:latest --version


Python package
^^^^^^^^^^^^^^
PEAT can also be installed as a Python package with ``pip`` (or ``pipx``), using the wheel (``.whl``) attached to each `release <https://github.com/sandialabs/PEAT/releases>`__. This requires a supported version of Python (refer to :doc:`system_requirements`). ``pip`` honors the usual installation options, such as ``--user``, ``--prefix``, and ``--root``.

.. code-block:: bash

   pip install ./peat-<version>-py3-none-any.whl
   peat --version

.. _uninstall:

Uninstall
---------

Linux
^^^^^
Remove the files the install script (or the manual installation steps) created. If you set ``PREFIX`` when installing, use that instead of ``/usr/local``.

.. code-block:: bash

   sudo rm -f /usr/local/bin/peat /usr/local/share/man/man1/peat.1
   sudo mandb

Windows
^^^^^^^
Delete ``peat.exe`` from ``%LOCALAPPDATA%\Programs`` (where the install script puts it), and remove that directory from your user ``PATH`` if nothing else uses it.

.. code-block:: powershell

   Remove-Item "$env:LOCALAPPDATA\Programs\peat.exe"

Container
^^^^^^^^^

.. code-block:: bash

   docker image rm ghcr.io/sandialabs/peat:latest

Python package
^^^^^^^^^^^^^^

.. code-block:: bash

   pip uninstall peat

PEAT Releases
-------------
PEAT releases are managed via `GitHub Releases <https://github.com/sandialabs/PEAT/releases>`__, and usually consist of the following:

- The Linux and Windows executables (``peat`` and ``peat.exe``)
- The Python source distribution (``.tar.gz``) and binary wheel (``.whl``)
- The Linux man page (``peat.1`` file)
- The :term:`Container` image via GitHub Container Registry (``ghcr.io``)
- The documentation in HTML format (``peat_docs.zip``)
- Sneakypeat executables (``sneakypeat`` and ``sneakypeat.exe``)
- ``SHA256SUMS.txt``, with checksums of the release files

Release files are signed. Refer to :ref:`verifying-releases` for how to verify them.
