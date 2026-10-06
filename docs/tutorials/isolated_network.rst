*************************************************
Collect on an isolated network, analyze elsewhere
*************************************************
*The control network you need to assess is air-gapped: no Internet, no path to your
analysis systems, and a strict media policy. The operator on site will run the collection;
the analysis happens at headquarters a week later. Nothing may leave the site unencrypted,
and the operator must not need to know the device credentials.*

PEAT was built for this. The executable and the container image are self-contained, every
input can be encrypted before it travels in, every output can be encrypted before it
travels out, and the Elasticsearch export is saved to files so the data can be loaded
into a server that was never reachable from the site.

What you need
=============
- Internet-connected system (yours): PEAT, to prepare the media
- Isolated system (on site): Linux or Windows with a USB port, or a Docker/Podman host
- Approved removable media, and the site's procedure for moving it in and out

Step 1: prepare the media (at the office)
=========================================
Put a self-contained PEAT on the media. The Linux executable, the Windows executable, or
the container image saved as a tar file, depending on what the site has:

.. code-block:: bash

   mkdir -p /media/transfer/peat && cd /media/transfer/peat

   # Executables and the man page from the release
   curl -fLO https://github.com/sandialabs/PEAT/releases/latest/download/peat
   curl -fLO https://github.com/sandialabs/PEAT/releases/latest/download/peat.exe
   curl -fLO https://github.com/sandialabs/PEAT/releases/latest/download/peat.1

   # Or the container image, for a site with Docker/Podman
   docker pull ghcr.io/sandialabs/peat:latest
   docker save -o peat_docker_image.tar ghcr.io/sandialabs/peat:latest

   # The HTML documentation, since the site has no Internet
   curl -fLO https://github.com/sandialabs/PEAT/releases/latest/download/peat_docs.zip

   sha256sum peat peat.exe peat.1 peat_docker_image.tar peat_docs.zip > SHA256SUMS

Step 2: write and encrypt the configuration (at the office)
===========================================================
Write the site configuration with the device credentials and the exact scope, then
encrypt it. The operator uses the encrypted file directly; PEAT asks for the password at
start-up, which you give the operator separately (and which is not the device password).

.. code-block:: yaml
   :caption: site-7.yaml

   metadata:
     name: "site-7"
     description: "Site 7 control LAN assessment, scope agreed 2026-10-01"

   # Only what's expected on site; keeps the scan short and quiet
   default_timeout: 3.0

   device_options:
     sel:
       pull_methods: [ftp, telnet]
       never_download_dirs: [EVENTS]
       credentials:
         acc: "OTTER"
         2ac: "TAIL"
     ftp:
       user: "FTPUSER"
       pass: "TAIL"
     m340:
       pull_methods: [ftp, umas]

   hosts:
     - label: "do-not-touch-safety-plc"
       comment: "Out of scope per site agreement, listed so operators recognize it"
       identifiers:
         ip: 198.51.100.9

.. code-block:: console

   $ peat encrypt-config -f site-7.yaml -p 'the-config-passphrase'
   | Done encrypting file, exiting...
   $ cp encrypted_site-7.yaml /media/transfer/peat/
   $ shred -u site-7.yaml           # Don't ship the plain text

Also write the operator a one-page run sheet (the commands in step 4, filled in), and
put it on the media.

Step 3: install on the isolated system
======================================
On site, verify the media and install, per the platform (details in
:doc:`/getting_started/install`):

.. code-block:: bash

   cd /media/transfer/peat && sha256sum -c SHA256SUMS

   # Linux executable
   sudo install -m 0755 peat /usr/local/bin/peat
   sudo install -m 0644 peat.1 /usr/local/share/man/man1/peat.1 && sudo mandb
   peat --version

   # Or the container
   docker load -i peat_docker_image.tar
   docker run --rm -i ghcr.io/sandialabs/peat:latest --version

   # The documentation, for the operator
   unzip -q peat_docs.zip -d ~/peat_docs && xdg-open ~/peat_docs/peat_docs/index.html

Step 4: collect (on site)
=========================
The run sheet, in order. The operator is prompted for the configuration passphrase on
each command.

.. code-block:: console

   $ mkdir -p ~/site-7 && cd ~/site-7

   # 1. Dry run: confirms the config decrypts and the scope is right. No packets sent.
   $ sudo peat scan --dry-run -c /media/transfer/peat/encrypted_site-7.yaml -d sel m340 -i 198.51.100.0/24
   Enter a password:
   | Configuration 'site-7' loaded from '/media/transfer/peat/encrypted_site-7.yaml'
   | WARNING: Dry run enabled, skipping calling command functions

   # 2. Inventory scan
   $ sudo peat scan -R site-7-scan -c /media/transfer/peat/encrypted_site-7.yaml -d sel m340 -i 198.51.100.0/24

   # 3. Pull from what was found (reusing the scan results as targets)
   $ sudo peat pull -R site-7-pull -c /media/transfer/peat/encrypted_site-7.yaml \
         -f peat_results/site-7-scan/summaries/scan-summary.json

   # 4. Check the outcome
   $ echo $?                       # 0 means every device succeeded
   $ grep -c "Pull failed" peat_results/site-7-pull/logs/peat.log

The Elasticsearch export (``-e``) needs a reachable server, so it isn't used on site;
the raw files and ``device-data-*.json`` in the run directory contain everything, and the
analysts load them at the office (step 6).

Step 5: encrypt and hand off (on site)
======================================
.. code-block:: console

   $ peat encrypt-results -f peat_results/site-7-scan -w /media/transfer/out/ -p 'the-results-passphrase'
   $ peat encrypt-results -f peat_results/site-7-pull -w /media/transfer/out/ -p 'the-results-passphrase'
   $ ls -lh /media/transfer/out/
   encrypted_site-7-scan.zip
   encrypted_site-7-pull.zip
   $ sha256sum /media/transfer/out/*.zip > /media/transfer/out/SHA256SUMS

   # Per site policy, remove the working copies
   $ sudo rm -rf ~/site-7/peat_results

The archives are standard AES-encrypted zip files, so the receiving side can also open
them with 7-Zip if PEAT isn't at hand. The results passphrase travels separately from the
media. Entry names inside the archive aren't encrypted, so avoid putting sensitive
information in run names.

Step 6: analyze (at the office)
===============================
.. code-block:: console

   $ sha256sum -c SHA256SUMS
   $ peat decrypt-results -f encrypted_site-7-pull.zip -w ./site-7/
   $ ls site-7/site-7-pull/
   devices  logs  peat_metadata  summaries

   # Load the results into the analysis cluster by re-parsing the raw files with -e.
   # The raw device files are kept unmodified under each device directory.
   $ peat parse -R site-7-load -e http://localhost:9200 -d selrelay -- site-7/site-7-pull/devices/*/relay_files/SET_ALL.TXT
   $ peat parse -R site-7-load-m340 -e http://localhost:9200 -d m340 -- site-7/site-7-pull/devices/*/*.apx

From here it's the same as any other results: ``device-data-summary.json`` per device,
the raw files under each device, the run's complete configuration in
``peat_metadata/peat_configuration.yaml`` (with the credentials the operator never saw),
and the data in :doc:`Kibana <elasticsearch_dashboard>`.

Checklist
=========
- [ ] Media verified with checksums on both sides
- [ ] Configuration encrypted; plain text never on the media
- [ ] Config and results passphrases delivered separately from the media
- [ ] Dry run before the scan, scan before the pull, out-of-scope hosts listed in ``hosts``
- [ ] Exit code and ``peat.log`` checked for failures before leaving
- [ ] Results encrypted, working copies removed per policy
- [ ] Raw files re-parsed with ``-e`` at the office if dashboards are wanted
