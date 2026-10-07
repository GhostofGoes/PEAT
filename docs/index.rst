:hide-toc:

******************
PEAT Documentation
******************

:Current version: |version|

PEAT (:term:`Process Extraction and Analysis Tool <PEAT>`) interrogates and maps
:term:`ICS`/:term:`OT` devices: it discovers devices on a network, pulls
:term:`artifacts <Artifact>` such as configuration, logic, firmware, and logs from them,
parses those artifacts (and project files exported from vendor software) into a
:doc:`standard data model <developer/data_model>`, and can push configuration or firmware
back to a device. It runs on Linux, Windows, and macOS, and as a :term:`container <Container>`.

.. grid:: 1 2 2 3
   :gutter: 3
   :class-container: peat-landing

   .. grid-item-card:: :octicon:`rocket` Get started
      :link: getting_started/quickstart
      :link-type: doc

      Install PEAT and run your first scan, pull, and parse in about ten minutes.

   .. grid-item-card:: :octicon:`mortar-board` Tutorials
      :link: tutorials/index
      :link-type: doc

      Story-driven, end-to-end walkthroughs: inventorying a substation network,
      investigating an engineering workstation, standing up a lab with OpenPLC,
      and more.

   .. grid-item-card:: :octicon:`book` User guide
      :link: user_guide/index
      :link-type: doc

      How to use each command (``scan``, ``pull``, ``parse``, ``push``,
      ``pillage``, ``heat``), configure PEAT, run it as a container, and
      troubleshoot problems.

   .. grid-item-card:: :octicon:`list-unordered` Reference
      :link: reference/index
      :link-type: doc

      Every command line argument, configuration option, output file,
      Elasticsearch index and field, plus device-specific reference pages and
      the glossary.

   .. grid-item-card:: :octicon:`code` Developer reference
      :link: developer/index
      :link-type: doc

      The Python API, data model, and the guide to writing a PEAT device module.

   .. grid-item-card:: :octicon:`tools` Design and contributing
      :link: design/index
      :link-type: doc

      How PEAT works internally, and how to set up a development environment,
      test, build, release, and contribute changes.

.. note::
   The documentation is a work in progress since open-sourcing, and there may be out of
   date information. If you spot anything that's obviously wrong, please
   `open an issue <https://github.com/sandialabs/PEAT/issues>`__ or a pull request.

.. toctree::
   :caption: Getting started
   :maxdepth: 1
   :hidden:

   getting_started/introduction
   getting_started/supported_devices
   getting_started/requirements
   getting_started/install
   getting_started/quickstart

.. toctree::
   :caption: Tutorials
   :maxdepth: 2
   :hidden:

   tutorials/index

.. toctree::
   :caption: User guide
   :maxdepth: 2
   :hidden:

   user_guide/index

.. toctree::
   :caption: Reference
   :maxdepth: 2
   :hidden:

   reference/index

.. toctree::
   :caption: Developer reference
   :maxdepth: 2
   :hidden:

   developer/index

.. toctree::
   :caption: Design
   :maxdepth: 2
   :hidden:

   design/index

.. toctree::
   :caption: Contributing
   :maxdepth: 2
   :hidden:

   contributing/index

.. toctree::
   :caption: Project
   :maxdepth: 1
   :hidden:

   authors
   changelog
   code_of_conduct
