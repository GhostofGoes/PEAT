.. _containers:

**************************************
Running as a container (Docker/Podman)
**************************************
The PEAT :term:`container <Container>` image (``ghcr.io/sandialabs/peat``) is the standard
command line interface bundled with its dependencies, including Zeek for :term:`HEAT`.
It is the most reproducible way to run PEAT, and the only one that needs no installation
beyond a container runtime. This page covers the arguments that matter and examples for
each command. Install instructions are in :doc:`/getting_started/install`.

.. note::
   The commands use :peat-icon:`docker` ``docker``. With :peat-icon:`podman` :term:`Podman` (for example on :term:`RHEL`), replace
   ``docker`` with ``podman``; the interfaces are nearly identical, though lesser-used
   arguments may differ. Refer to the `Podman documentation <https://docs.podman.io/en/latest/>`__.
   On Linux, ``sudo`` is required before ``docker`` unless your user is in the ``docker``
   group; it is omitted below for brevity.

Container arguments that matter
===============================
Everything between ``docker run`` and the image name is an argument to Docker; everything
after the image name is an argument to PEAT.

.. code-block:: text

   docker run --rm -i --network host -v "$(pwd)/peat_results:/peat_results" ghcr.io/sandialabs/peat:latest  pull -d selrelay -i 192.0.2.0/24
   └──── Docker arguments ──────────────────────────────────────────────────┘ └── image ─────────────┘ └──── PEAT arguments ─────┘

.. list-table::
   :header-rows: 1
   :widths: 36 64

   * - Argument
     - Why
   * - ``-v "$(pwd)/peat_results:/peat_results"``
     - **Required to keep results.** PEAT writes to ``/peat_results`` inside the
       container; without a volume mount the results vanish when the container exits.
   * - ``--network host``
     - **Required for scanning and pulling.** Removes the container's network isolation so
       PEAT can use the host's interfaces. Without it scans are less reliable, :term:`MAC`
       addresses aren't resolved, broadcast scanning doesn't work, and a server on
       ``localhost`` (Elasticsearch) isn't reachable.
   * - ``-i``
     - Interactive: keeps standard input open, which PEAT needs (and which is how files are
       piped in for parsing).
   * - ``--rm``
     - Remove the container when it exits, so stopped containers don't accumulate.
   * - ``--privileged``
     - Gives the container full access to the host, which lets PEAT use raw sockets for
       ARP/ICMP host checks exactly as root on the host would. Use it for scans and pulls
       when you can; omit it for parsing.
   * - ``-v /host/path:/path``
     - Mount files or directories to parse, push, or pillage into the container.

File paths in PEAT's output and logs refer to paths *inside* the container (for example
``/peat_results/...``), not on the host.

Parsing files and directories
=============================
Host paths can't be used directly, so either pipe a single file into the container or
mount a directory:

.. code-block:: bash

   # A single file via a pipe or redirection
   cat examples/devices/sel/sel_351/set_all.txt | docker run --rm -i ghcr.io/sandialabs/peat parse -d selrelay
   docker run --rm -i ghcr.io/sandialabs/peat parse -d selrelay < examples/devices/sel/sel_351/set_all.txt

   # A directory, mounted as a volume (the path after the image is the path inside the container)
   docker run --rm -i -v "$(pwd)/relay_backups:/relay_backups" -v "$(pwd)/peat_results:/peat_results" \
       ghcr.io/sandialabs/peat parse -v -d selrelay -- /relay_backups

   # Parse previously pulled files and export to an Elasticsearch server on localhost
   docker run --rm -i --network host -v "$(pwd)/peat_results:/peat_results" \
       ghcr.io/sandialabs/peat parse -e -v -d selrelay -- "/peat_results/*/devices/"

Scanning and pulling
====================
.. code-block:: bash

   # Scan a subnet
   docker run --rm -i --privileged --network host -v "$(pwd)/peat_results:/peat_results" \
       ghcr.io/sandialabs/peat scan -i 192.0.2.0/24

   # Broadcast scan (requires --network host)
   docker run --rm -i --privileged --network host -v "$(pwd)/peat_results:/peat_results" \
       ghcr.io/sandialabs/peat scan -b 192.0.2.255

   # Pull from everything PEAT recognizes on a subnet
   docker run --rm -i --privileged --network host -v "$(pwd)/peat_results:/peat_results" \
       ghcr.io/sandialabs/peat pull -i 192.0.2.0/24

   # Pull from SEL relays on two networks with a configuration file, and export to Elasticsearch
   docker run --rm -i --privileged --network host \
       -v "$(pwd)/peat_results:/peat_results" -v "$(pwd)/site.yaml:/site.yaml:ro" \
       ghcr.io/sandialabs/peat pull -vV -e -c /site.yaml -d selrelay -i 192.0.3.44-55 192.0.2.22-33

Pushing
=======
.. code-block:: bash

   docker run --rm -i --network host \
       -v "$(pwd)/peat_results:/peat_results" -v "$(pwd)/relay_configs:/relay_configs:ro" \
       ghcr.io/sandialabs/peat push -vV -d selrelay -i 192.0.2.22 -- /relay_configs/

HEAT
====
The image includes Zeek 6.0, so the FTP extractor works out of the box:

.. code-block:: bash

   docker run --rm -i --network host -v "$(pwd)/pcaps:/pcaps" -v "$(pwd)/peat_results:/peat_results" \
       ghcr.io/sandialabs/peat heat -vVV -e http://localhost:9200 --pcaps /pcaps --heat-file-only --heat-protocols FTPExtractor

See :doc:`heat`.

Pillage
=======
.. warning::
   In a container, pillage **does not work with Windows disk images** and may not work
   reliably with Linux disk images, since the container can't attach block devices or load
   kernel modules. Mounted filesystems do work: mount the drive on the host, then pass it
   into the container with ``-v``. For disk images use the Linux executable on the host.

.. code-block:: bash

   docker run --rm -i -v "$(pwd)/site.yaml:/site.yaml:ro" -v /mnt/workstation:/workstation:ro \
       -v "$(pwd)/pillage_results:/pillage_results" \
       ghcr.io/sandialabs/peat pillage -c /site.yaml -P /workstation

Image tags
==========
- ``latest``: the most recent release
- ``<version>`` (for example ``2026.9.2``): a specific release
- ``main``: the current development branch, rebuilt on every push to ``main``
- ``<sha>``: a specific commit

The image is labeled with the version and the source commit
(``org.opencontainers.image.version``, ``org.opencontainers.image.revision``), which
``docker inspect`` shows. Pin a version tag in scripts and automation.

Development and debugging
=========================
.. code-block:: bash

   # Get a shell in the container
   docker run --rm -it --entrypoint /bin/sh -v "$(pwd)/peat_results:/peat_results" ghcr.io/sandialabs/peat

   # Attach to a running container
   docker ps
   docker exec -it <container-name> /bin/sh

   # Keep a modified container as a new image
   docker run --name peat_dev -it --entrypoint /bin/sh ghcr.io/sandialabs/peat
   docker commit peat_dev my-peat

Inside the container PEAT is installed in ``/PEAT`` with its virtual environment in
``/PEAT/.venv``, the working directory is ``/`` (so results go to ``/peat_results`` and
pillage output to ``/pillage_results``), and the ``PEAT_IN_CONTAINER`` environment variable
is set, which PEAT records in its logs (``peat.containerized``).

Docker refresher
================
Images are the built artifact (``ghcr.io/sandialabs/peat``); containers are running (or
stopped) instances of an image created by ``docker run``.

.. code-block:: bash

   # Images
   docker pull ghcr.io/sandialabs/peat:latest   # Download or update
   docker load -i peat_docker_image.tar          # Load from a file (offline systems)
   docker images                                 # List
   docker rmi <image-id>                         # Delete
   docker image prune                            # Clean up dangling layers

   # Containers
   docker ps                                     # Running
   docker ps -a                                  # Running and stopped
   docker logs -f <container>                    # Follow a container's output
   docker rm -f <container>                      # Delete
   docker container prune                        # Delete all stopped containers
   docker system prune                           # Clean up images, containers, networks, volumes

Further reading:

- `Docker documentation <https://docs.docker.com/>`__ and the
  `Docker Engine install guide <https://docs.docker.com/engine/install/>`__
- `Docker volumes <https://docs.docker.com/engine/storage/volumes/>`__
- `Start containers automatically <https://docs.docker.com/engine/containers/start-containers-automatically/>`__
- `Compose file reference <https://docs.docker.com/reference/compose-file/>`__
- `lazydocker <https://github.com/jesseduffield/lazydocker>`__, a terminal UI for
  monitoring containers and images
- `Podman documentation <https://docs.podman.io/en/latest/>`__

Building the image yourself is covered in :doc:`/contributing/building`.
