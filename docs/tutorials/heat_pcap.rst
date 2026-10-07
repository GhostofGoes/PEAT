*************************************************
Recover device files from a packet capture (HEAT)
*************************************************
*A network monitoring sensor on a substation LAN has been capturing traffic for months.
During an incident review, someone asks: "A relay's settings were changed in July. What
exactly was sent to it?" The relay was updated over FTP, and FTP is plain text, so the
answer is in the PCAPs, if you can reassemble it.*

:term:`HEAT` (High-fidelity Extraction of Artifacts from Traffic) does the reassembly and
then parses the recovered files with PEAT's modules, so you get the settings file *and*
the parsed settings, the same as if you had pulled them from the relay at the time. This
tutorial uses the FTP extractor, which works on PCAP files directly with :peat-icon:`zeek` Zeek.

What you need
=============
- Docker. The PEAT container image bundles the exact version of Zeek the FTP extractor
  needs (6.0), so the container is the recommended way to run HEAT.
- PCAP files containing the transfers (``.pcap`` or ``.pcapng``). To practice without
  your own captures, public ICS traffic collections are listed in
  :doc:`/reference/example_artifacts`; captures that include FTP transfers of device
  files are what you need.
- An Elasticsearch server URL. HEAT currently requires one to be configured even when it
  only extracts files; with ``--heat-file-only`` nothing is written to it (see the note
  below).

Step 1: stage the captures
==========================
Put the relevant captures in a directory. Narrowing the time window first keeps the Zeek
run short:

.. code-block:: bash

   mkdir -p ~/heat/pcaps ~/heat/peat_results
   # Captures from the week of the change
   cp /sensor/archive/substation-a/2026-07-1{3..19}*.pcap ~/heat/pcaps/
   ls -lh ~/heat/pcaps/

Step 2: extract the files
=========================
Run HEAT from the container with the capture and results directories mounted. Start with
``--heat-file-only`` to see what is in the traffic before parsing anything:

.. code-block:: console

   $ cd ~/heat
   $ docker run --rm -i --network host \
         -v "$(pwd)/pcaps":/pcaps -v "$(pwd)/peat_results":/peat_results \
         ghcr.io/sandialabs/peat:latest \
         heat -R july-ftp -vV -e http://localhost:9200 --pcaps /pcaps --heat-protocols ftp --heat-file-only
   | Extracting artifacts from 7 PCAP files
   | Running Zeek on /pcaps/2026-07-13.pcap
   ...
   | Running Zeek on /pcaps/2026-07-16.pcap
   | Found 9 FTP file transfers in /pcaps/2026-07-16.pcap
   | Reconstructed SET_1.TXT (192.0.2.150 -> 192.0.2.22, 2026-07-16 14:02:11 UTC)
   | Reconstructed SET_L1.TXT (192.0.2.150 -> 192.0.2.22, 2026-07-16 14:02:13 UTC)
   | Reconstructed SET_ALL.TXT (192.0.2.22 -> 192.0.2.150, 2026-07-16 13:58:40 UTC)
   ...
   | Saved 9 artifacts to /peat_results/july-ftp/heat_artifacts
   | Finished run in 2 minutes and 8 seconds

.. code-block:: console

   $ ls peat_results/july-ftp/heat_artifacts/
   192.0.2.22_192.0.2.150_1752674320_SET_ALL.TXT
   192.0.2.150_192.0.2.22_1752674531_SET_1.TXT
   192.0.2.150_192.0.2.22_1752674533_SET_L1.TXT
   ...

The direction and timestamps already tell a story: at 13:58 the workstation at
``192.0.2.150`` *downloaded* the relay's complete settings (``SET_ALL.TXT``), and four
minutes later *uploaded* new ``SET_1.TXT`` and ``SET_L1.TXT`` files. The Zeek logs that
HEAT produced are in ``peat_results/july-ftp/zeek_logs/`` if you want the connection
details (who logged in with which FTP account, for example).

Step 3: parse the recovered files
=================================
Run again without ``--heat-file-only`` to have PEAT parse the artifacts with the SEL relay
module (and export to Elasticsearch, if you want the results there), or parse the
recovered files yourself:

.. code-block:: console

   $ docker run --rm -i -v "$(pwd)/peat_results":/peat_results ghcr.io/sandialabs/peat:latest \
         parse -R july-ftp-parse -d selrelay -- /peat_results/july-ftp/heat_artifacts/
   | Parsing SELRelay file '/peat_results/july-ftp/heat_artifacts/192.0.2.22_192.0.2.150_1752674320_SET_ALL.TXT'
   | Parsing SELRelay file '/peat_results/july-ftp/heat_artifacts/192.0.2.150_192.0.2.22_1752674531_SET_1.TXT'
   ...
   | Completed parsing of 9 files in 0.9 seconds

Step 4: what changed?
=====================
The downloaded ``SET_ALL.TXT`` is the relay's settings *before* the change; the uploaded
``SET_1.TXT`` is group 1 *after*. Compare the overlapping section:

.. code-block:: console

   $ cd peat_results/july-ftp/heat_artifacts/
   $ sed -n '/^\[1\]/,/^\[/p' 192.0.2.22_192.0.2.150_1752674320_SET_ALL.TXT > before_SET_1.txt
   $ diff -u before_SET_1.txt 192.0.2.150_192.0.2.22_1752674531_SET_1.TXT
   -50P1P   := 6.00
   +50P1P   := 2.00
   -TR      := 51P1T OR 50P1T OR OC
   +TR      := 51P1T OR OC

Someone lowered the instantaneous overcurrent pickup and removed its element from the
trip equation, from the engineering workstation, at 14:02 UTC on July 16th. The parsed
output in ``peat_results/july-ftp-parse/`` has the same change as structured data
(``parsed-config.json``) and the logic formatted for reading (``formatted-logic.txt``),
and if the relay was pulled since, the pull's ``SET_ALL.TXT`` shows whether the change
is still in effect.

Other protocols
===============
The Telnet extractor recovers files shown over SEL's ASCII interface (``file show``), and
the UMAS extractor recovers Modicon M340 project uploads and downloads. Both read packet
data from Elasticsearch produced by Sandia's ``ingest-tshark`` tool rather than from PCAP
files:

.. code-block:: bash

   peat heat -e http://results-elastic:9200 --heat-elastic-server http://packets-elastic:9200 \
       --heat-protocols umas --heat-date-range "2026-07-16T00:00:00.000 - 2026-07-17T00:00:00.000" \
       --heat-only-ips 192.0.2.0/24

See :doc:`/user_guide/heat` for the options.

Notes
=====
- Only unencrypted transfers can be reconstructed. SFTP and HTTPS uploads will show up in
  Zeek's connection logs but not as artifacts.
- The sensor must have seen both directions of the traffic (a SPAN port or tap on the
  right segment), and the capture must contain the whole transfer.
- HEAT is one of PEAT's less mature features; run with ``-vV`` and check
  ``logs/peat.log``. The requirement for an Elasticsearch server with
  ``--heat-file-only`` is a known limitation.
- Captures contain credentials (FTP logins are plain text) and complete device
  configurations. Handle the PCAPs and the results accordingly.
