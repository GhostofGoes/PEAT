*********
Tutorials
*********
End-to-end walkthroughs, each written around a realistic situation and a person in it.
They go further than the :doc:`/getting_started/quickstart`: real configurations,
complete commands, the output you should expect, and what to do with the results. Pick
the one closest to your situation.

.. list-table::
   :header-rows: 1
   :widths: 34 46 20

   * - Tutorial
     - You are...
     - Needs
   * - :doc:`openplc_lab`
     - Anyone who wants hands-on experience with scan, pull, and push against a real
       (software) PLC, with nothing but Docker.
     - :peat-icon:`docker` Docker
   * - :doc:`substation_inventory`
     - A protection engineer or OT security analyst who needs an inventory and settings
       backup of the relays and RTAC at a substation, repeatable every month.
     - :octicon:`broadcast` Network access to devices
   * - :doc:`windows_field_laptop`
     - An assessor arriving on site with a Windows laptop and a few hours to document
       what's on the control network.
     - :peat-icon:`windows` Windows laptop
   * - :doc:`engineering_workstation`
     - An incident responder with a disk image of an engineering workstation, who needs
       to know what logic it held and whether it matches the PLCs.
     - :peat-icon:`linux` Linux, root, the image
   * - :doc:`elasticsearch_dashboard`
     - An analyst who wants PEAT data in Kibana (or Malcolm) for dashboards and queries
       across devices and over time.
     - :peat-icon:`docker` Docker
   * - :doc:`heat_pcap`
     - A network defender with packet captures from an OT network, who wants the device
       files that crossed the wire.
     - :peat-icon:`docker` Docker, a PCAP
   * - :doc:`isolated_network`
     - An operator who must collect on an air-gapped network and hand results to an
       analyst elsewhere, securely.
     - :octicon:`lock` Removable media
   * - :doc:`sceptre_phenix`
     - A range builder or tool tester who wants virtual RTUs speaking real protocols, and
       PEAT running inside that environment, without any hardware.
     - :peat-icon:`sceptre` Linux host with KVM and Docker

.. toctree::
   :maxdepth: 1
   :hidden:

   openplc_lab
   substation_inventory
   windows_field_laptop
   engineering_workstation
   elasticsearch_dashboard
   heat_pcap
   isolated_network
   sceptre_phenix

Conventions
===========
- Commands are shown for Linux with ``peat`` on the ``PATH``; on Windows use
  ``.\peat.exe``, and with the container prefix commands as shown in
  :doc:`/user_guide/containers`.
- Addresses in the ``192.0.2.0/24`` and ``198.51.100.0/24`` ranges are documentation
  addresses; substitute your own.
- Example log output has been shortened. Timestamps and durations will differ.
- Every tutorial that touches devices starts with a dry run. Keep that habit.

Writing a module for a device PEAT doesn't support yet is a tutorial of its own:
the :doc:`/developer/module_developer_guide`.
