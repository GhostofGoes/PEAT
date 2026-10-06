.. _pillage:

*******************************************
Pillaging files from workstations (Pillage)
*******************************************
``peat pillage`` searches a disk image, a mounted drive, or a directory for :term:`OT`
project and configuration files worth analyzing, and copies them out for parsing and
comparison. The typical source is an **engineering workstation**: the Windows machine with
the vendor software that was used to program the devices on a network, which usually
holds project files (SEL ``.rdb`` databases, Rockwell ``.L5X`` exports, Schneider ``.apx``
projects, Woodward ``.wset`` settings, and so on) that are richer than what can be pulled
from the devices themselves.

Pillage is useful for forensics and incident response (what logic was the workstation
holding, and does it match what's on the PLC?), for seeding a baseline before devices can
be pulled, and for recovering configurations when a device is gone.

Requirements
============
- **Linux only** (tested on Ubuntu 18.04 and newer). The :doc:`container <containers>` is
  an option on other platforms, with limitations noted below.
- **Must run as root** (``sudo``), which is needed to mount images.
- ``qemu-nbd`` from the ``qemu-utils`` package, to attach disk images:
  ``sudo apt install qemu-utils``.
- The ``kmodpy`` Python package, installed automatically with PEAT on Linux, to load the
  ``nbd`` kernel module.
- When pillaging a disk image, the host kernel must support the image's filesystem (for
  example NTFS for a Windows workstation). Check ``/proc/filesystems`` and
  ``ls /lib/modules/$(uname -r)/kernel/fs``.
- A PEAT :doc:`configuration file <configure>` with a ``pillage`` section (see
  :ref:`pillage-config`). The search criteria come from this file, so it is required.

Running pillage
===============
Pillage takes the configuration file (``-c``) and the source to search (``-P``), which can
be a disk image or a directory:

.. code-block:: bash

   # Pillage a raw disk image
   sudo peat pillage -c peat-config.yaml -P raw_disk.img

   # Pillage virtual machine disk images (attached read-only with qemu-nbd)
   sudo peat pillage -c peat-config.yaml -P eng_vm.qcow2
   sudo peat pillage -c peat-config.yaml -P SomeVM.vmdk

   # Pillage a mounted drive or a local directory
   sudo peat pillage -c peat-config.yaml -P /mnt/workstation-c/
   sudo peat pillage -c peat-config.yaml -P /home/peat/pillage_this

   # Also export results to Elasticsearch
   sudo peat pillage -e http://192.0.2.21:9200 -c peat-config.yaml -P /home/peat/pillage_this

When the source is an image, PEAT loads the ``nbd`` kernel module (unless it was already
loaded), attaches the image **read-only** with ``qemu-nbd``, mounts it under
``./pillage_temp/`` in the current directory, searches it, then unmounts and detaches it
and removes the directory. Mounting occasionally fails on the first attempt; waiting a few
seconds and re-running usually works.

How files are selected
======================
The ``pillage`` section of the configuration file defines the search criteria. Every file
found under the source is checked against a ``default`` set of criteria and against each
*brand* (vendor) entry; a file is considered valid if its **file name** matches one in a
``filenames`` list, or failing that if its **extension** is in an ``extensions`` list. The
example configuration covers the common vendors:

.. literalinclude:: ../../examples/peat-config.yaml
   :language: yaml
   :start-at: pillage:
   :end-before: # -----------------------------------------------------------------------------

Options:

- ``auto_copy``: when ``true``, matching files are copied automatically; when ``false``,
  PEAT asks before copying each file. Interactive mode is useful when a pattern (such as
  ``xml``) produces many false positives.
- ``recursive``: search sub-directories (``true``) or only the top level of the source.
- ``locations``: directory paths to limit the search to. **Not yet implemented**; pillage
  currently searches all directories regardless of this list.
- ``filenames``: exact file names to look for, case-insensitive, with extension and without
  wildcards. Checked before extensions.
- ``extensions``: file extensions to look for, without the dot and without wildcards.

See :ref:`pillage-config` in the reference for the full description.

Results
=======
Valid files are copied into ``./pillage_results/`` in the current working directory,
sorted into sub-directories named after the brand whose criteria matched (plus
``DEFAULT``). A file that matches more than one brand goes into ``MULTIPLE/`` for you to
sort out. If a file with the same name already exists in the destination, the new copy is
renamed with a counter: ``set_all.1.txt``, ``set_all.2.txt``, and so on. The PEAT log
records which criteria matched each file and why it was copied.

.. code-block:: text

   pillage_results/
      SEL/
         set_all.txt
         set_all.1.txt
         breaker-1.rdb
      Modicon/
         Station.apx
      L5X/
         Line3.L5X
      MULTIPLE/
      DEFAULT/

Pillage results are collected, not yet parsed. Parse them with ``peat parse``, which can
take the whole directory:

.. code-block:: bash

   peat parse -R workstation-parse ./pillage_results/SEL/
   peat parse -R workstation-parse -d m340 ./pillage_results/Modicon/

.. note::
   Pillage output is written to ``./pillage_results/`` rather than into the run directory
   under ``peat_results/``. Integrating pillage output with the run directory and with
   ``parse`` is planned.

When things go wrong
====================
If PEAT crashes mid-run and can't clean up, detach the image manually:

.. code-block:: bash

   sudo umount pillage_temp
   sudo rm -rf pillage_temp
   sudo qemu-nbd -d /dev/nbd1
   sudo rmmod nbd

To mount an image yourself in the same way pillage does (for example to browse it, or to
work around an unsupported format):

.. code-block:: bash

   sudo modprobe nbd
   sudo mkdir -p /mnt/myimage
   sudo qemu-nbd -r -c /dev/nbd1 /path/to/disk/image.vmdk
   sudo mount -o ro /dev/nbd1p1 /mnt/myimage
   sudo peat pillage -c peat-config.yaml -P /mnt/myimage

   # Cleanup
   sudo umount /mnt/myimage
   sudo qemu-nbd -d /dev/nbd1
   sudo rmmod nbd

Notes and limitations
=====================
- Disk images must be in a format ``qemu-nbd`` understands (raw, qcow2, VMDK, VDI, VHD/VHDX
  and others). Images split into several files are not supported: convert them with
  ``qemu-img convert`` or mount them manually and pillage the mount point.
- **In a container**, pillage **does not work with Windows disk images** and may not work
  reliably with Linux disk images, because the container can't load kernel modules or
  attach block devices. Filesystems *do* work when mounted into the container with
  ``-v``. For disk images, use the Linux executable or Python package on the host.
- When running in a VMware Workstation VM, pillage can run on an image or filesystem in a
  shared folder. If mounting the shared folder is troublesome, see
  `How do I mount shared folders in Ubuntu using VMware tools? <https://askubuntu.com/a/1051620>`__.
- Searching large images takes time; the search is single-threaded and reads every file
  name.

Examples
========
The complete list of pillage examples from ``peat pillage --examples``:

.. literalinclude:: ../../peat/cli_args.py
   :language: bash
   :start-after: pillage_examples = """
   :end-before: """  # End pillage examples
