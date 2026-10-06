**********
User guide
**********
How to operate PEAT. The pages in this guide are task-oriented: each covers one command or
one aspect of running PEAT, with the options you are most likely to need and worked
examples. For an exhaustive list of command line arguments and configuration options, see
the :doc:`/reference/index`.

PEAT's primary interface is the ``peat`` command line program, which has a sub-command for
each function:

.. list-table::
   :header-rows: 1
   :widths: 22 58 20

   * - Command
     - Purpose
     - Guide
   * - ``scan``
     - Carefully discover and identify supported devices on a network or serial ports
     - :doc:`scan`
   * - ``pull``
     - Acquire artifacts from devices: configuration, logic, firmware, logs, memory
     - :doc:`pull`
   * - ``parse``
     - Extract information from device files and vendor project files, offline
     - :doc:`parse`
   * - ``push``
     - Upload configuration or firmware to a device
     - :doc:`push`
   * - ``pillage``
     - Search a disk image, drive, or directory for :term:`OT` project and configuration files
     - :doc:`pillage`
   * - ``heat``
     - Extract and parse device artifacts from network traffic captures
     - :doc:`heat`
   * - ``-e`` / ``--elastic-server``
     - Export results to Elasticsearch, OpenSearch, or Malcolm
     - :doc:`elasticsearch`, :doc:`opensearch`
   * - ``config-builder``
     - Interactively build a PEAT configuration file
     - :doc:`config_builder`
   * - ``encrypt-config``, ``decrypt-config``
     - Encrypt and decrypt a PEAT configuration file (which may hold credentials)
     - :doc:`encryption`
   * - ``encrypt-results``, ``decrypt-results``
     - Encrypt a results directory into a password-protected archive, and back
     - :doc:`encryption`

.. toctree::
   :maxdepth: 1

   cli
   configure
   output
   scan
   pull
   parse
   push
   pillage
   heat
   elasticsearch
   opensearch
   containers
   encryption
   config_builder
   third_party_modules
   troubleshooting

.. note::
   On Linux, this guide is also installed as the manual page: ``man peat``.
