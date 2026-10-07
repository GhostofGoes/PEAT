********************************************
On site with a Windows laptop
********************************************
*You're an assessor visiting a plant for a day. You have a Windows 11 laptop, a network
drop on the control network that the plant engineer vouches for, and a few hours. You
need to leave with a defensible picture of what's on that network: vendors, models,
firmware, services.*

:peat-icon:`windows` Windows is often what you have on site, and it works well for this. The differences from
Linux are small: an Administrator PowerShell, Npcap for raw sockets, and paths.

What you need
=============
- A Windows 10 or 11 laptop you can run programs on as Administrator
- ``peat.exe`` from the `latest release <https://github.com/sandialabs/PEAT/releases>`__
  (or the ``peat_windows_<version>.zip`` bundle, which includes the example configuration
  files). Download it before you go; the plant network won't have Internet.
- `Npcap <https://npcap.com/>`__, installed in "WinPcap API-compatible mode" (also
  installed by Wireshark). Without it PEAT still works but checks hosts with TCP
  connections instead of ARP/ICMP, which is slower and misses devices.
- Optional but handy: `jq <https://jqlang.org/>`__ (``winget install jqlang.jq``) and
  Windows Terminal.

Step 1: set up
==============
Open **Windows Terminal (Admin)** or PowerShell as Administrator, and create a working
folder. Unblock the downloaded executable (Windows marks files from the Internet) and
check it runs:

.. code-block:: powershell

   New-Item -ItemType Directory -Path C:\peat -Force | Out-Null
   Set-Location C:\peat
   Copy-Item $env:USERPROFILE\Downloads\peat.exe .
   Unblock-File .\peat.exe

   .\peat.exe --version
   .\peat.exe scan --list-modules

Microsoft Defender SmartScreen may show an "unrecognized app" prompt the first time; this
is expected for a downloaded executable. If endpoint protection quarantines PEAT (a
self-extracting executable that opens many network connections looks suspicious), ask the
plant's IT to allow-list ``C:\peat``.

Step 2: know your address
=========================
Confirm which interface is on the control network and what subnet it's in, so you scan
the right thing and only the right thing:

.. code-block:: powershell

   Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, IPAddress, PrefixLength
   # Ethernet  192.0.2.150  24

Agree the scope with the plant engineer: the subnet, any addresses to avoid (a sensitive
controller mid-process), and when. Put the exclusions in writing.

Step 3: discover what's there
=============================
Scan the subnet. Start with ``--dry-run``, then the real thing. Scanning with all modules
is fine for discovery when you genuinely don't know what's on the network; it just takes
longer.

.. code-block:: powershell

   .\peat.exe scan --dry-run -i 192.0.2.0/24
   .\peat.exe scan -R plant-discovery -i 192.0.2.0/24

.. code-block:: text

   | Checking online status of 254 hosts using ARP and/or ICMP requests
   | 23 hosts are responding (checked 254 hosts in 4 seconds)
   | Scanning 23 IPs using 16 modules: ControlLogix, Easygen3500XT, Fortigate, GERTU, ...
   | 192.0.2.30   | Identification method 'cip' from module 'ControlLogix' succeeded for 192.0.2.30
   | 192.0.2.41   | Identification method 'snmp' from module 'M340' succeeded for 192.0.2.41
   | 192.0.2.60   | Identification method 'http' from module 'Totus' succeeded for 192.0.2.60
   ...
   | Completed scan of 23 devices in 3 minutes and 51 seconds (23 results)
   | Saved scan summary to peat_results\plant-discovery\summaries\scan-summary.json

If the plant uses Rockwell equipment, a broadcast scan finds ControlLogix PLCs in
seconds with a handful of packets:

.. code-block:: powershell

   .\peat.exe scan -R plant-broadcast -d controllogix -b 192.0.2.0/24

Step 4: read the results
========================
.. code-block:: powershell

   # Who is who
   Get-Content .\peat_results\plant-discovery\summaries\scan-summary.json |
       jq -r '.hosts_verified[] | [.ip, .description.vendor.name, .description.product, .peat_module] | @tsv'

   # Online but unidentified: workstations, switches, HMIs PEAT does not know
   Get-Content .\peat_results\plant-discovery\summaries\scan-summary.json | jq '.hosts_online'

   # Services seen per device
   Get-Content .\peat_results\plant-discovery\summaries\scan-summary.json |
       jq -r '.hosts_verified[] | .ip as $ip | .service[] | [$ip, .protocol, .port, .status] | @tsv'

Without ``jq``, PowerShell can do it:

.. code-block:: powershell

   $scan = Get-Content .\peat_results\plant-discovery\summaries\scan-summary.json | ConvertFrom-Json
   $scan.hosts_verified | Select-Object ip, @{n='product';e={$_.description.product}}, peat_module | Format-Table
   $scan.hosts_verified | Select-Object ip, @{n='product';e={$_.description.product}}, peat_module |
       Export-Csv -NoTypeInformation .\plant-inventory.csv

Step 5: pull details where it's appropriate
===========================================
Pulling logs into devices and downloads files. With the engineer's agreement, pull from
the devices you've identified, limited to their modules, with credentials in a
configuration file if needed (see :doc:`/user_guide/configure`):

.. code-block:: powershell

   .\peat.exe pull -R plant-pull -c .\plant.yaml -d controllogix m340 -f .\peat_results\plant-discovery\summaries\scan-summary.json

``-f`` reuses the scan results as the target list, so nothing new is touched. Watch the
log for warnings; a device that doesn't want to be pulled from (login failures, timeouts)
is itself a finding.

Step 6: leave with the evidence
===============================
Before you unplug:

.. code-block:: powershell

   # Everything from today, encrypted for transport
   .\peat.exe encrypt-results -f .\peat_results\plant-discovery -w D:\
   .\peat.exe encrypt-results -f .\peat_results\plant-pull -w D:\

   # Remove the working copies from the laptop if policy requires it
   Remove-Item -Recurse -Force .\peat_results

Back at the office, decrypt (``peat decrypt-results``), load the pulls into
:doc:`Elasticsearch <elasticsearch_dashboard>` or hand the ``device-data-summary.json``
files to whoever writes the report. Every file records the PEAT version, the run ID, and
the time, which makes for defensible provenance.

Windows notes
=============
- Run as Administrator for ARP/ICMP host checks, broadcast scans, and MAC addresses.
  As a normal user, add ``-Y`` for known addresses that don't answer the TCP check.
- The ``cmd`` prompt works, but colors render poorly; use PowerShell or Windows Terminal,
  or ``--no-color``.
- Paths: ``.\peat.exe parse -d m340 'C:\Projects\Station.apx'``. For binary project files,
  pass the path rather than piping with ``Get-Content``.
- Results are in ``.\peat_results\`` under the folder you ran from, and the log file in
  ``peat_results\<run>\logs\peat.log``. ``Get-Content -Wait`` follows it live.
- A Windows laptop usually also has the vendors' project files from past work on it.
  ``peat parse`` reads many of them directly (see :doc:`/user_guide/parse`), and on
  Linux, :doc:`pillage <engineering_workstation>` finds them.
