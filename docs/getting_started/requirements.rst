*******************
System requirements
*******************
What you need to run PEAT: supported platforms, hardware, network connectivity, and
permissions. Most users should read :ref:`platforms-section` and :ref:`network-requirements`,
then move on to :doc:`install`.

.. tip::
   The pre-built executable (``peat`` on Linux, ``peat.exe`` on Windows) is the standard
   way to run PEAT. It bundles its own Python runtime and dependencies, so **Python is not
   required** on the system. Python is only needed to use PEAT as a library or to develop
   it.

.. _platforms-section:

Supported platforms
===================
.. list-table::
   :header-rows: 1
   :widths: 22 14 14 14 36

   * - Platform
     - Executable
     - Container
     - Python API / development
     - Notes
   * - Ubuntu
     - 14.04 and newer
     - Yes
     - 22.04 and newer (Python 3.11 to 3.13)
     - Primary development and testing platform. The executable is built with
       :term:`StaticX` so it runs on old releases.
   * - Red Hat Enterprise Linux (:term:`RHEL`)
     - RHEL 6 and newer
     - Yes (``podman``)
     - RHEL 9 (Python 3.11 or 3.12)
     - Used in deployments. RHEL 6 and 7 are tested with the executable and with
       :term:`Podman` 1.0 and newer.
   * - `Kali Linux <https://www.kali.org/>`__
     - 2018 and newer
     - Yes
     - Yes
     - Relevant for exercises and sensors in emulated environments.
   * - Other Linux (Debian, Fedora, CentOS, ...)
     - Expected to work
     - Yes
     - If Python 3.11 to 3.13 is available
     - Debian and RHEL-based distributions should work but are not regularly tested. Known
       to work on Debian 9.
   * - Windows 10 (1809+) / Windows Server 2019+
     - Yes
     - Docker Desktop (untested)
     - Yes
     - Fully supported and regularly tested (CI runs the unit tests on Windows Server 2022
       and the current GitHub-hosted Windows image).
   * - Windows 11
     - Yes
     - Docker Desktop (untested)
     - Yes
     - Supported. Builds and tests run on current Windows images in CI.
   * - Windows 7, 8, and 8.1
     - No
     - No
     - No
     - PEAT's Python runtime (3.11+) requires Windows 10 or newer.
   * - `Windows Subsystem for Linux (WSL) <https://learn.microsoft.com/en-us/windows/wsl/>`__
     - Yes (Linux executable)
     - N/A
     - Yes
     - Works in any WSL distribution PEAT supports (e.g. Ubuntu, Kali). Some network
       features do not work in WSL, notably :term:`MAC` address lookups and raw-socket
       based host checks.
   * - macOS
     - No
     - Docker Desktop (untested)
     - Best effort
     - Supported on a best-effort basis to support developers who use Macs. There are
       known issues with some networking components and system dependencies.
   * - :term:`Docker` 18.03+ / :term:`Podman` 1.0+ (Linux host)
     - N/A
     - Yes
     - N/A
     - Fully supported on Linux-based hosts and regularly tested on Docker 20 and newer.
       Older Docker versions may work but are unsupported. See :doc:`/user_guide/containers`.

Architecture: the executables and the container image are built for 64-bit x86
(``x86_64``/``amd64``). The Python package is pure Python and also works on 64-bit ARM
(for example Apple Silicon Macs or ARM Linux servers) when its dependencies have wheels for
that platform.

Hardware
========
The system hardware requirements for running PEAT are minimal, and the limits vary
slightly by system.

- **CPU**: 64-bit x86 CPU. A dual-core 2.4 GHz CPU is recommended. Additional cores do not
  noticeably improve performance, since most of PEAT's time is spent waiting on devices.
- **Memory**: minimum of 64 MB of available memory (RAM). 256 MB is recommended for scanning
  very large networks or when running PEAT as a container.
- **Temporary disk space**: minimum of 50 MB in the platform's temporary directory
  (``/tmp`` on Linux, ``%LOCALAPPDATA%\Temp`` on Windows). The executable unpacks itself
  here on start-up.
- **Output disk space**: at least 100 MB in the output directory. 1 GB is recommended for
  storing multiple runs or when running with increased verbosity; 5 to 10 GB is recommended
  when pulling from 100 or more devices, especially devices with significant amounts of
  logic or configuration.

.. _network-requirements:

Network
=======
PEAT requires network connectivity to carry out any *active* operation (``scan``, ``pull``,
and ``push``). Offline operations (``parse``, ``pillage``, ``heat`` on PCAP files, and the
encryption commands) do not require network access.

- **Local subnet**: being on the same subnet as the devices (the same :term:`OSI Model`
  Layer 2 broadcast domain) is required for :ref:`broadcast scanning <broadcast-scanning>`
  and for using :term:`ARP` requests to check whether hosts are online.
- **Routed subnets**: routes to the target networks are required when the devices are not
  on the local subnet. Routers and firewalls must allow :term:`TCP` and :term:`UDP` traffic
  to the devices, and :term:`ICMP` echo requests if efficient online checks of hosts in
  non-local subnets are desired.
- **Host firewall**: the firewall on the system running PEAT must allow outbound TCP and
  UDP to the hosts and subnets being queried (and outbound ICMP for efficient online
  checks). The ports PEAT uses are listed in :doc:`/reference/protocols`.
- **Intrusion detection**: add an exception for the host running PEAT to any network
  Intrusion Detection System (:term:`IDS`). PEAT's network operations are inherently
  suspicious to an IDS, especially one tuned for :term:`OT` networks, and will likely
  generate numerous alerts during a run.
- **Elasticsearch/OpenSearch** (optional): connectivity to the server on its HTTP(S) port
  (9200 by default) if results are exported with ``-e``.

Permissions and system configuration
====================================
- A terminal is required to run PEAT. On Windows, PowerShell is preferred. PEAT runs in a
  legacy ``cmd`` window, but terminal colors and formatting may be degraded.
- **Administrator (Windows) or root (Linux) permissions are required for some network
  features**. They are *not* required for offline functions (parsing, HEAT on PCAP files).
  With elevated permissions PEAT can use raw sockets, which enables:

  - Lightweight :term:`ARP` and :term:`ICMP` requests to check which hosts are online.
    These are significantly faster and have less impact on devices than the fallback
    (TCP connection attempts to a single port, 80 by default).
  - Broadcast scanning.
  - Resolving device :term:`MAC` addresses.
  - Access to serial devices on Linux (alternatively, add your user to the ``dialout``
    group).

- **Packet capture library**: raw-socket features use libpcap. On Linux the ``tcpdump``
  and ``libpcap`` packages are recommended (PEAT warns at start-up if ``tcpdump`` is
  missing). On Windows, install `Npcap <https://npcap.com/>`__ (also installed by
  Wireshark). Without them PEAT falls back to TCP connection checks.
- **Write access** to the output directory (``./peat_results/`` by default) is required,
  unless file output is disabled (see :doc:`/user_guide/configure`).
- **Executable permissions**: the executable distribution must be able to run programs and
  to write and execute files in the temporary directory, where it unpacks itself.
- **Endpoint protection**: anti-malware software may interfere with PEAT, since a
  self-extracting executable that scans the network and opens many connections looks
  suspicious. If this happens, allow-list the PEAT executable and its output directory. In
  practice this is rare.

Optional software
=================
Some features use external tools:

- **Elasticsearch or OpenSearch** server to export results to (``-e``). PEAT is tested with
  Elasticsearch 7 and 8 and with OpenSearch 2 (including `Malcolm <https://malcolm.fyi/>`__).
  See :doc:`/user_guide/elasticsearch`.
- **Zeek 6.0** for the :term:`HEAT` FTP extractor, which processes PCAP files. The
  container image bundles Zeek; see :doc:`/user_guide/heat`.
- **qemu-utils** (``qemu-nbd``) and the ``nbd`` kernel module to pillage disk images; Linux
  only. See :doc:`/user_guide/pillage`.
- **lrzsz** (``rz``/``sz``) for YMODEM file transfers from SEL relays over serial that lack
  the ``file show`` command; Linux and macOS only. See :doc:`/reference/devices/sel`.
- **A modern web browser** (current Chrome, Edge, Firefox, or Safari) to read the HTML
  documentation.

Virtual machines
================
PEAT works well inside a virtual machine (VM). Requirements and recommendations:

- Prefer hardware passthrough of a physical network adapter connected to the network being
  scanned. A bridged adapter also works, though the host :term:`OS` may interfere with the
  adapter's configuration or apply its own firewall rules.
- PEAT has been tested with VMware Workstation Pro (14+), VirtualBox (6+), and QEMU/KVM
  as type 2 hypervisors with Linux guests (Ubuntu, :term:`RHEL`, Kali, and others). It also
  fully supports running inside a :term:`SCEPTRE` experiment, which is hosted with minimega
  and QEMU. Type 1 hypervisors (Microsoft Hyper-V, Xen, ESXi) have not been tested but
  should work.

Containers
----------
Refer to :doc:`/user_guide/containers` for requirements and limitations when using the
container distribution of PEAT (notably, ``--network host`` is required for scanning).
