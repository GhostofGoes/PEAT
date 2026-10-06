.. _heat-usage:

****************************************************
Extracting artifacts from network traffic (HEAT)
****************************************************
:term:`HEAT` (High-fidelity Extraction of Artifacts from Traffic) reconstructs
:term:`artifacts <Artifact>` such as configuration files, logic, and firmware from captured
network traffic, then parses them with PEAT exactly as if they had been pulled from the
device. It turns a :term:`PCAP` of an engineer downloading a project to a PLC into the
project file itself, plus everything PEAT can extract from it: process logic, register
mappings, protocol and network configuration, I/O points, device type and role, vendor and
model, and more.

HEAT is useful when you can observe a network but can't (or shouldn't) interrogate the
devices on it, for retrospective analysis of captures taken during an incident, and for
monitoring: a capture of a settings change contains the new settings.

How HEAT works
==============
HEAT is organized as *extractors*, one per protocol. Each extractor knows how a protocol
carries files, finds the relevant packets in the traffic, reassembles the file, and hands
it to the PEAT module that parses it. The extracted files are saved to
``peat_results/<run-dir>/heat_artifacts/`` and the parsed results are written to the run
directory (and to Elasticsearch, if enabled) like any other PEAT results.

.. code-block:: text

   PCAP file ──► Zeek ─────────────────┐
                                        ├──► HEAT extractor ──► reassembled file ──► PEAT module parser ──► device data
   PCAP ──► ingest-tshark ──► Elastic ─┘                        (heat_artifacts/)                          (devices/, Elastic)

The extractors differ in where they read the traffic from:

.. list-table::
   :header-rows: 1
   :widths: 20 24 24 32

   * - Extractor
     - Protocol
     - Devices
     - Traffic source
   * - ``FTPExtractor``
     - :term:`FTP` file transfers
     - SEL relays (settings files), other FTP-capable devices
     - PCAP files, processed with `Zeek <https://zeek.org/>`__
   * - ``TelnetExtractor``
     - Telnet sessions (SEL ASCII commands and ``file show`` output)
     - SEL relays
     - Packet data in Elasticsearch, produced by ``ingest-tshark``
   * - ``UmasExtractor``
     - :term:`UMAS` (Schneider's protocol over Modbus/TCP function code 90)
     - Schneider Modicon M340 and related PLCs (project upload/download)
     - Packet data in Elasticsearch, produced by ``ingest-tshark``

``ingest-tshark`` is a :term:`SNL`-developed tool that dissects PCAPs with ``tshark`` and
loads the packets into Elasticsearch. The Telnet and UMAS extractors query that data; the
FTP extractor processes PCAP files directly. List the extractors available in your copy of
PEAT with:

.. code-block:: bash

   peat heat --list-heat-protocols

Extracting from PCAP files (FTP)
================================
The FTP extractor runs Zeek on each PCAP to carve out transferred files, then parses them.
Zeek 6.0 must be available: **the container image bundles the correct version**, which is
why we strongly recommend running HEAT from the container. Without the container, install
Zeek 6.0 and make sure ``zeek`` is on the ``PATH`` or in ``/opt/zeek/bin/``.

.. code-block:: bash

   # Process every PCAP in ./pcaps and save the results to ./peat_results
   docker run --rm -i --network host \
       -v "$(pwd)/pcaps":/pcaps \
       -v "$(pwd)/peat_results":/peat_results \
       ghcr.io/sandialabs/peat:latest \
       heat -vV --pcaps /pcaps --heat-protocols FTPExtractor --heat-file-only

   # The same, also parsing the files and exporting results to Elasticsearch
   docker run --rm -i --network host \
       -v "$(pwd)/pcaps":/pcaps \
       -v "$(pwd)/peat_results":/peat_results \
       ghcr.io/sandialabs/peat:latest \
       heat -vV -e http://localhost:9200 --pcaps /pcaps --heat-protocols FTPExtractor

Arguments:

- ``--pcaps DIR``: directory of ``.pcap``/``.pcapng`` files to process.
- ``--heat-protocols NAME...``: extractors to run (case-insensitive partial match of the
  extractor name, e.g. ``ftp``). Defaults to all.
- ``--heat-file-only``: only extract the files; don't parse them or export to
  Elasticsearch. Files are written to ``heat_artifacts/`` (``--heat-artifacts-dir`` or
  :attr:`HEAT_ARTIFACTS_DIR <peat.settings.Configuration.HEAT_ARTIFACTS_DIR>`).
- ``--no-run-zeek`` with ``--zeek-dir DIR``: reuse Zeek output from a previous run (or
  from your own Zeek deployment) instead of running Zeek again. Zeek logs are kept in the
  run directory's ``zeek_logs/`` folder.

.. note::
   HEAT currently requires an Elasticsearch server to be configured (``-e``) even when
   only extracting files from PCAPs. Point it at any reachable server; with
   ``--heat-file-only`` nothing is written to it.

Extracting from Elasticsearch packet data (Telnet, UMAS)
========================================================
The Telnet and UMAS extractors query packet documents in Elasticsearch. The server holding
the packet data can be different from the server PEAT exports results to:

.. code-block:: bash

   # Read packets from "heat-elastic" and store results in "results-elastic"
   peat heat -e http://results-elastic:9200/ --heat-elastic-server http://heat-elastic:9200/

   # Same server for both (-e with no URL means http://localhost:9200/)
   peat heat -e

   # Limit to specific indices, a time range, or hosts
   peat heat -e --heat-index-names "packetbeat-2021.07.*"
   peat heat -e --heat-date-range "2021-07-15T00:00:00.000 - 2021-07-16T12:34:12.143"
   peat heat -e --heat-only-ips 192.0.2.0/24
   peat heat -e --heat-exclude-ips 192.0.2.10 192.0.2.20

   # Just extract the files, do not parse or export them
   peat heat -e --heat-file-only

   # Only the UMAS extractor
   peat heat -e --heat-protocols umas

Arguments:

- ``--heat-elastic-server URL``: server with the packet data. Defaults to the ``-e``
  server.
- ``--heat-index-names PATTERN``: index names or patterns with the packet data
  (default ``packets-*``).
- ``--heat-date-range "START - END"``: limit extraction to a time range.
- ``--heat-only-ips`` / ``--heat-exclude-ips``: include only, or exclude, packets with
  these addresses or subnets as source or destination.

All HEAT options can also be set in a :doc:`configuration file <configure>`
(``heat_*``, ``pcaps``, ``no_run_zeek``, ``zeek_dir``).

Results
=======
- ``heat_artifacts/``: every reconstructed file, named after the devices and session it
  came from. These are the same files a pull would have produced, so they can be parsed
  again later with ``peat parse`` or opened with the vendor's software.
- ``devices/<device-id>/``: the parsed results for each device whose artifacts were found,
  in PEAT's data model, with the device ID taken from the traffic (the device's IP).
- The usual logs and metadata. Run with ``-vV`` to see which sessions were found and
  which files were reconstructed.

Limitations
===========
- Only the protocols above are supported. Captures must contain the actual file transfers
  (an FTP data channel, a Telnet ``file show`` session, a UMAS project upload or download);
  polling traffic alone doesn't contain artifacts.
- Encrypted transfers (SFTP, HTTPS) can't be reconstructed.
- The Telnet and UMAS extractors depend on the ``ingest-tshark`` document format in
  Elasticsearch.
- HEAT is one of PEAT's less mature capabilities. Expect to use ``-vV`` and the logs, and
  please report issues.

.. seealso::

   :doc:`/developer/heat_api`
      The HEAT classes and extractor implementations

   :doc:`/reference/example_artifacts`
      Public PCAP collections with ICS protocol traffic that can be used to try HEAT

Examples
========
The complete list of HEAT examples from ``peat heat --examples``:

.. literalinclude:: ../../peat/cli_args.py
   :language: bash
   :start-after: heat_examples = """
   :end-before: """  # End HEAT examples
