.. _sceptre-phenix-tutorial:

**********************************************
Virtual RTUs in a SCEPTRE (phenix) experiment
**********************************************
*You are putting together a range for testing OT tools and procedures. You want RTUs that
speak real protocols, that you can break and rebuild at will, and a workstation inside the
same network from which an assessor would run PEAT, with nothing physical to procure.*

:peat-icon:`sceptre` :term:`SCEPTRE` is Sandia's modeling and simulation platform for
:term:`ICS`/:term:`SCADA` environments. Its orchestrator, `phenix <https://phenix.sceptre.dev/>`__,
builds experiments out of virtual machines on `minimega <https://www.sandia.gov/minimega/>`__,
and `bennu <https://github.com/sandialabs/sceptre-bennu>`__ provides the virtual field
devices: software RTUs and PLCs that serve DNP3, Modbus, BACnet, or IEC 60870-5-104 from
a simulated process. PEAT's :class:`~peat.modules.sandia.sceptre_fcd.SCEPTRE` module
knows these devices. This tutorial deploys a small experiment with two bennu RTUs and a
PEAT workstation, then scans and pulls from the RTUs exactly as you would on a real
network.

.. only:: html

   .. container:: peat-logo

      .. image:: /images/logos/phenix.png
         :alt: The phenix logo, a stylized orange phoenix
         :width: 96px
         :target: https://phenix.sceptre.dev/

Plan on an hour, most of it downloading the VM image. Nothing in the experiment touches
your real network: phenix creates the experiment's VLANs on its own virtual switch.

What you need
=============
- A Linux machine with hardware virtualization (KVM): Ubuntu 22.04 or newer is what
  phenix recommends. The four VMs are configured with 3 GB of RAM in total, and the bennu
  image is a 10 GB (sparse) disk, so a machine with 8 GB of RAM and some tens of GB free
  is comfortable. You need ``root`` on it, and Internet access for the downloads.
- `Docker Engine with Docker Compose <https://docs.docker.com/engine/install/>`__. The
  phenix documentation's own quick start runs phenix and minimega as containers, and so
  does this tutorial.
- `oras <https://oras.land/docs/installation>`__, the client that downloads pre-built VM
  images from the GitHub container registry, and ``git`` with
  `Git LFS <https://git-lfs.com/>`__ for the example topologies.
- The PEAT Linux executable from the
  `releases page <https://github.com/sandialabs/PEAT/releases>`__, and the three files in
  ``examples/phenix/`` of the PEAT repository (linked below).

What you will build
===================
.. raw:: html
   :file: ../images/phenix_lab_topology.svg

.. only:: not html

   Four virtual machines on one phenix host: two bennu field devices (``rtu-1`` at
   10.117.4.101 and ``rtu-2`` at 10.117.4.102, each a DNP3 outstation on TCP port 20000
   with an FTP server on port 21) and the PEAT workstation (10.117.4.50) on the ``EXP``
   control network, and the PyPower simulation provider (172.16.1.2) on the ``MGMT``
   network, which the RTUs also join (172.16.1.4 and 172.16.1.5) to receive process values
   over UDP multicast. The operator reaches the VMs through the phenix web interface on
   port 3000 and its VNC consoles.

All four VMs use the same ``bennu.qc2`` image, Ubuntu 22.04 with bennu installed. Which
ones behave as field devices is decided by the *scenario*, which attaches phenix's
``sceptre`` app to the ``provider``, ``rtu-1``, and ``rtu-2`` nodes. The ``peat`` node has
no app metadata, so it is just an Ubuntu VM, with the PEAT executable injected into its
disk when the experiment starts.

The addresses are those of the ``soap`` topology from
`sceptre-phenix-topologies <https://github.com/sandialabs/sceptre-phenix-topologies>`__,
because the scenario reuses two things from it: the PyPower power-flow case that drives the
simulation, and its hand-written RTU configurations. Those configurations are the same
files PEAT ships as :doc:`example artifacts </reference/example_artifacts>` in
``examples/devices/sceptre/soap/``, which lets you check PEAT's pull against a known-good
copy at the end.

Step 1: Run phenix
==================
Follow the `phenix quick start <https://phenix.sceptre.dev/latest/>`__: clone the
repository and start the containers with the pre-built images. Both containers run
privileged on the host network and share the ``/phenix`` directory with the host, which is
where images, topologies, and injected files live.

.. code-block:: bash

   git clone https://github.com/sandialabs/sceptre-phenix.git
   cd sceptre-phenix/docker
   sudo docker compose up -d --pull always
   sudo docker compose logs -f     # Ctrl+C once phenix and minimega are up

   # Make "phenix" a command on the host (a wrapper around "docker exec ... phenix")
   cd .. && sudo make install-wrapper
   sudo phenix experiment list     # an empty table: no experiments yet

The web interface is at http://localhost:3000/ (authentication is disabled in the
container image's default configuration). Keep a terminal open as ``root`` or with
``sudo`` for the rest of the tutorial; phenix's own documentation runs its commands as
``root``.

Step 2: Download the bennu image and the example topologies
===========================================================
phenix looks for disk images in ``/phenix/images``. Pre-built images are published weekly
by `sceptre-phenix-images <https://github.com/sandialabs/sceptre-phenix-images>`__ and kept
for 90 days.

.. code-block:: bash

   sudo mkdir -p /phenix/images /phenix/injects /phenix/topologies
   cd /phenix/images
   sudo oras pull ghcr.io/sandialabs/sceptre-phenix-images/bennu.qc2:latest

   # The example topologies: the scenario below uses the PyPower case file and the RTU
   # configurations from the "soap-legacy" topology
   sudo git clone https://github.com/sandialabs/sceptre-phenix-topologies /phenix/topologies
   cd /phenix/topologies && sudo git lfs pull

.. note::
   If the pull fails because the image has expired, build it from the same repository:
   ``make bennu`` in a clone of sceptre-phenix-images builds ``bennu.qc2`` with
   ``phenix image`` (see its README), then copy the result to ``/phenix/images/``.

Step 3: Stage PEAT and the experiment files
===========================================
phenix *injects* files from the host into a VM's disk when the experiment starts, so the
PEAT executable and its configuration only need to exist on the host. Download the
executable, then copy the three files from PEAT's ``examples/phenix/`` directory
(:download:`peat-bennu-topology.yaml <../../examples/phenix/peat-bennu-topology.yaml>`,
:download:`peat-bennu-scenario.yaml <../../examples/phenix/peat-bennu-scenario.yaml>`, and
:download:`peat-bennu.yaml <../../examples/phenix/peat-bennu.yaml>`) to
``/phenix/topologies/peat-bennu/``:

.. code-block:: bash

   sudo curl -fLo /phenix/injects/peat https://github.com/sandialabs/PEAT/releases/latest/download/peat
   sudo chmod +x /phenix/injects/peat
   /phenix/injects/peat --version

   sudo mkdir -p /phenix/topologies/peat-bennu
   sudo cp peat-bennu-topology.yaml peat-bennu-scenario.yaml peat-bennu.yaml /phenix/topologies/peat-bennu/

The paths matter: the topology refers to ``/phenix/injects/peat`` and
``/phenix/topologies/peat-bennu/peat-bennu.yaml`` as injection sources, and the scenario
refers to ``/phenix/topologies/soap-legacy/``.

Step 4: Read the topology, the scenario, and the PEAT configuration
===================================================================
The **topology** describes the VMs and networks. Each node has an image, hardware, and
interfaces on named VLANs; phenix allocates the VLAN IDs. The ``peat`` node carries the
two injections:

.. literalinclude:: ../../examples/phenix/peat-bennu-topology.yaml
   :language: yaml
   :start-at: apiVersion:

The **scenario** attaches apps to the topology's nodes. The ``sceptre`` app (from
`sceptre-phenix-apps <https://github.com/sandialabs/sceptre-phenix-apps>`__, included in
the phenix container image) reads each host's metadata and generates its bennu
configuration and start-up script. ``provider`` runs PyPower on the ``case300`` power
system model; each ``fd-server`` lists the simulated objects it exposes over DNP3. Because
``assetDir`` points at the ``soap-legacy`` topology, the app uses that topology's
hand-written ``injects/override/rtu-1_config.xml`` and ``rtu-2_config.xml`` instead of
generated configurations, which keeps the DNP3 point addresses stable:

.. literalinclude:: ../../examples/phenix/peat-bennu-scenario.yaml
   :language: yaml
   :start-at: apiVersion:

When an RTU boots, the generated start-up script copies the running field device binary
and ``/etc/sceptre/config.xml`` into the ``sceptre`` user's home directory, which is also
the root of the device's FTP server (``vsftpd``, user ``sceptre``, password ``sceptre``),
and starts the field device daemon. That FTP directory is what PEAT's SCEPTRE module
interrogates: it identifies a device by logging in and finding a file whose name contains
``bennu``, and pulls the configuration (``*config*.xml``) and the binary. The **PEAT
configuration** names the two hosts and adjusts one option, because the binary in the FTP
directory is called ``bennu-field-deviced`` while the module's default expects
``bennu-field-deviced.firmware``, a name that only appears after a firmware update:

.. literalinclude:: ../../examples/phenix/peat-bennu.yaml
   :language: yaml
   :start-at: metadata:

Step 5: Create and start the experiment
=======================================
Load the two phenix configurations into phenix's store, create the experiment from them,
and start it:

.. code-block:: bash

   sudo phenix config create /phenix/topologies/peat-bennu/peat-bennu-topology.yaml
   sudo phenix config create /phenix/topologies/peat-bennu/peat-bennu-scenario.yaml
   sudo phenix experiment create peat-bennu -t peat-bennu -s peat-bennu
   sudo phenix experiment start peat-bennu

   sudo phenix experiment list        # "peat-bennu" with a start time and 4 VMs
   sudo phenix vm info peat-bennu     # the four VMs, "Running: true"

Starting takes a few minutes the first time. The start-up scripts generated by the
``sceptre`` app run when each VM boots; the field device daemon (``bennu-field-deviced``)
and its watcher (``bennu-watcherd``) come up on the RTUs, and the provider starts
``pybennu-power-solver``. The *Experiments* page of the web interface shows the VMs with
live screenshots.

Step 6: Log in to the PEAT workstation
======================================
In the web interface, open the ``peat-bennu`` experiment and click the ``peat`` VM's
screenshot: a new browser tab opens a VNC console. Log in as ``root``. Images built with
``phenix image`` have no root password; if this one asks for a password, use
``SiaSd3te``, which the bennu image's build script sets.

Check that PEAT is in place and that the RTUs are reachable, including the two ports PEAT
and the DNP3 masters would use:

.. code-block:: bash

   peat --version
   ping -c 1 10.117.4.101
   ncat -zv 10.117.4.101 21        # FTP: what PEAT talks to
   ncat -zv 10.117.4.101 20000     # DNP3 outstation

If the DNP3 port is not open yet, give the start-up scripts another minute.

Step 7: Scan the RTUs
=====================
The scan identifies the devices without needing the configuration file:

.. code-block:: bash

   peat scan -d sceptre -i 10.117.4.101-102

The SCEPTRE module's identification method connects to each host's FTP port, logs in as
``sceptre``, and checks the directory listing for a file whose name contains ``bennu``.
Watch for one line per RTU:

.. code-block:: text

   Identification method 'ftp' from module 'SCEPTRE' succeeded for 10.117.4.101
   Identification method 'ftp' from module 'SCEPTRE' succeeded for 10.117.4.102

The :ref:`scan summary <scan-summary>` lists both under ``hosts_verified`` with
``"peat_module": "SCEPTRE"``, vendor Sandia National Laboratories, and type ``RTU``.

Step 8: Pull from the RTUs
==========================
The pull uses the injected configuration for the ``bennu_filename`` option (and for the
host labels, which become the device directories' names):

.. code-block:: bash

   peat pull -c /root/peat-bennu.yaml -d sceptre -i 10.117.4.101-102

For each RTU, PEAT scans and identifies it as above, logs in over FTP, downloads the
``config.xml`` and the ``bennu-field-deviced`` binary into
``devices/<label>/ftp_files/``, and parses the configuration. The result for ``rtu-1``:

.. only:: html

   .. figure:: /images/terminal/sceptre_rtu1_summary.svg
      :alt: Terminal showing the start of device-data-summary.json for rtu-1: description with brand, model and product SCEPTRE and vendor Sandia National Laboratories, ip 10.117.4.101, name rtu-1, type RTU, os Canonical Ubuntu, one interface and one service, the dnp3 service on tcp port 20000 with protocol_id 10, and extra cycle_time 1000
      :figclass: peat-terminal

      ``device-data-summary.json`` for ``rtu-1``, as produced by parsing its configuration.

- ``name`` is ``rtu-1`` and ``type`` is ``RTU``, from the configuration.
- One ``service``: protocol ``dnp3``, role ``server``, TCP port 20000, with the DNP3 link
  address (``protocol_id: 10``) and the outstation's event log name.
- ``device-data-registers.jsonl`` holds the 24 DNP3 points (analog and binary inputs and
  outputs), ``device-data-tag.jsonl`` the 24 tags, and ``device-data-io.jsonl`` the 24 I/O
  points with the simulated object each one belongs to: ``bus-242.voltage``,
  ``bus-242.active``, ``generator-1_bus-242.mw``, and so on. These are the three objects
  the scenario gave ``rtu-1``.
- ``ftp_files/config.xml`` is the configuration itself. It is the same file as
  ``examples/devices/sceptre/soap/rtu-1_config.xml`` in the PEAT repository, so you can
  compare hashes, or run ``peat parse`` on the shipped copy and diff the results.

The :ref:`pull summary <pull-summary>` in ``summaries/pull-summary.json`` lists both
devices in ``pull_results``.

Step 9: Get the results out of the experiment
=============================================
The PEAT VM has no route to the outside world, by design. phenix can mount a VM's disk on
the host, which is the simplest way to copy the run directory out:

.. code-block:: bash

   # On the phenix host
   sudo phenix vm mount peat-bennu peat
   sudo cp -r /phenix/mounts/peat-bennu/peat/root/peat_results ./peat_results
   sudo phenix vm unmount peat-bennu peat

   # Then, for example, load the results into Kibana or Malcolm on another system
   peat parse -d sceptre -e http://elastic.example.net:9200 ./peat_results/*/devices/*/ftp_files/config.xml

Mounting requires the ``miniccc`` agent in the VM, which the bennu image includes. For a
repeatable workflow, :doc:`encrypt the results <isolated_network>` before they leave the
range.

Step 10: Tear down
==================
.. code-block:: bash

   sudo phenix experiment stop peat-bennu
   sudo phenix experiment delete peat-bennu

The topology and scenario stay in phenix's store for the next time
(``phenix config list all``). Starting the experiment again gives you fresh RTUs: the VMs
boot from snapshots of the image, so nothing you did inside them persists.

Going further
=============
- **Modbus instead of DNP3.** Replace ``dnp3:`` with ``modbus:`` in the scenario's RTU
  metadata and remove the ``assetDir`` line, so the ``sceptre`` app generates the
  configurations instead of using the DNP3 overrides. bennu then serves Modbus/TCP on port
  502, and PEAT parses the ``<modbus-server>`` block the same way.
- **More of SCEPTRE.** The ``soap`` topology in sceptre-phenix-topologies adds an
  Ignition HMI, four RTUs, and a network monitor to the same addresses; the
  `phenix documentation <https://phenix.sceptre.dev/latest/>`__ covers topologies,
  scenarios, and the apps in depth.
- **Live process values.** On the ``provider`` VM, ``bennu-probe --command query
  --endpoint tcp://172.16.1.2:5555`` lists the simulated objects and
  ``bennu-probe --command read --tag bus-242.voltage --endpoint tcp://172.16.1.2:5555``
  reads one. Compare the names with the I/O points PEAT extracted.
- **Repeat it monthly.** The :doc:`substation inventory tutorial <substation_inventory>`
  shows how to turn a pull like this into a scheduled, diffable baseline.

Notes and limitations
=====================
- The SCEPTRE module pulls and parses; it does not implement ``peat push``.
- PEAT identifies a bennu device over FTP, not DNP3. The protocol, port, and point
  information in the results comes from the device's configuration file.
- The experiment uses lab defaults: FTP credentials ``sceptre``/``sceptre``, a shared
  root password, and no authentication on the phenix web interface. Keep the phenix host
  off networks you don't control.
- Reaching experiment VLANs from the phenix host itself (to run PEAT on the host rather
  than in a VM) is possible with phenix's ``tap`` app, but it is an advanced setup that the
  phenix documentation describes as still being written.
