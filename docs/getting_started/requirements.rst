*******************
System requirements
*******************
What you need to run PEAT: supported platforms, hardware, network connectivity, and
permissions. Most users should read :ref:`platforms-section` and :ref:`network-requirements`,
then move on to :doc:`install`.

.. tip::
   The pre-built executable (``peat`` on Linux, ``peat.exe`` on Windows, ``peat_macos_arm64``
   or ``peat_macos_x86_64`` on macOS) is the standard way to run PEAT. It bundles its own Python runtime and dependencies, so **Python is not
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
   * - :peat-icon:`ubuntu` Ubuntu
     - 14.04 and newer
     - Yes
     - 22.04 and newer (Python 3.11 to 3.13)
     - Primary development and testing platform. The executable is built with
       :term:`StaticX` so it runs on old releases.
   * - :peat-icon:`linux` Red Hat Enterprise Linux (:term:`RHEL`)
     - RHEL 6 and newer
     - Yes (``podman``)
     - RHEL 9 (Python 3.11 or 3.12)
     - Used in deployments. RHEL 6 and 7 are tested with the executable and with
       :term:`Podman` 1.0 and newer.
   * - :peat-icon:`linux` `Kali Linux <https://www.kali.org/>`__
     - 2018 and newer
     - Yes
     - Yes
     - Relevant for exercises and sensors in emulated environments.
   * - :peat-icon:`linux` Other Linux (Debian, Fedora, CentOS, ...)
     - Expected to work
     - Yes
     - If Python 3.11 to 3.13 is available
     - Debian and RHEL-based distributions should work but are not regularly tested. Known
       to work on Debian 9.
   * - :peat-icon:`windows` Windows 10 (1809+) / Windows Server 2019+
     - Yes
     - Docker Desktop (untested)
     - Yes
     - Fully supported and regularly tested (CI runs the unit tests on Windows Server 2022
       and the current GitHub-hosted Windows image).
   * - :peat-icon:`windows` Windows 11
     - Yes
     - Docker Desktop (untested)
     - Yes
     - Supported. Builds and tests run on current Windows images in CI.
   * - :peat-icon:`windows` Windows 7, 8, and 8.1
     - No
     - No
     - No
     - PEAT's Python runtime (3.11+) requires Windows 10 or newer.
   * - :peat-icon:`windows` `Windows Subsystem for Linux (WSL) <https://learn.microsoft.com/en-us/windows/wsl/>`__
     - Yes (Linux executable)
     - N/A
     - Yes
     - Works in any WSL distribution PEAT supports (e.g. Ubuntu, Kali). Some network
       features do not work in WSL, notably :term:`MAC` address lookups and raw-socket
       based host checks.
   * - :peat-icon:`apple` macOS 15 (Sequoia) and newer
     - Yes (Apple Silicon and Intel)
     - Docker Desktop (untested)
     - Yes (Python 3.11 to 3.13)
     - Fully supported. CI runs the unit tests on macOS 15 Sequoia (Apple Silicon with
       Python 3.11 to 3.13, Intel with Python 3.12) and macOS 26 Tahoe (Apple Silicon,
       Python 3.12). The
       executables are built on macOS 15 and need macOS 15 or newer; older releases may
       work with the Python package but are untested. Docker Desktop runs containers in a
       Linux VM, so the container can't scan the Mac's networks (``--network host`` reaches
       the VM): scan from a Mac with the executable or the Python package. See
       :ref:`macos-limitations`.
   * - :peat-icon:`docker` :term:`Docker` 18.03+ / :term:`Podman` 1.0+ (Linux host)
     - N/A
     - Yes
     - N/A
     - Fully supported on Linux-based hosts and regularly tested on Docker 20 and newer.
       Older Docker versions may work but are unsupported. See :doc:`/user_guide/containers`.

Architecture: the Linux and Windows executables and the container image are built for
64-bit x86 (``x86_64``/``amd64``); the macOS executables are built for Apple Silicon
(``arm64``) and Intel (``x86_64``). The Python package is pure Python and also works on
64-bit ARM Linux when its dependencies have wheels for that platform.

Hardware
========
The system hardware requirements for running PEAT are minimal, and the limits vary
slightly by system.

- **CPU**: 64-bit x86 CPU, or an Apple Silicon or 64-bit Intel CPU on macOS. A dual-core
  2.4 GHz CPU is recommended. Additional cores do not
  noticeably improve performance, since most of PEAT's time is spent waiting on devices.
- **Memory**: minimum of 64 MB of available memory (RAM). 256 MB is recommended for scanning
  very large networks or when running PEAT as a container.
- **Temporary disk space**: minimum of 50 MB in the platform's temporary directory
  (``/tmp`` on Linux, ``$TMPDIR`` on macOS, ``%LOCALAPPDATA%\Temp`` on Windows). The executable unpacks itself
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

.. _permissions:

Permissions and system configuration
====================================
- A terminal is required to run PEAT. On Windows, PowerShell is preferred. PEAT runs in a
  legacy ``cmd`` window, but terminal colors and formatting may be degraded.
- **Administrator (Windows) or root (Linux and macOS) permissions are required for some
  network features**. They are *not* required for offline functions (parsing, HEAT on PCAP files).
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
  Wireshark). On macOS, raw packets go through the BPF devices, which only root can open
  by default (see :ref:`macos-limitations`). Without them PEAT falls back to TCP
  connection checks.
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
  the ``file show`` command; Linux (``apt install lrzsz``) and macOS (``brew install
  lrzsz``) only. See :doc:`/reference/devices/sel`.
- **A modern web browser** (current Chrome, Edge, Firefox, or Safari) to read the HTML
  documentation.

.. _macos-limitations:

macOS limitations
=================
PEAT's features work the same on macOS as on Linux, with these exceptions, most of them
inherent to the platform:

- **Root is required for ARP and ICMP host checks.** Scapy sends and receives raw packets
  on macOS through Berkeley Packet Filter devices (``/dev/bpf*``), which only root can open
  by default. Run PEAT with ``sudo`` for the fastest and lightest host discovery. Without
  it, PEAT falls back to TCP SYN online checks (as for an unprivileged Linux user) and logs
  a warning. The "ChmodBPF" launch daemon that ships with
  `Wireshark <https://www.wireshark.org/>`__ gives members of the ``access_bpf`` group
  access to the BPF devices without ``sudo``, and PEAT detects and uses that access.
- **Pillaging disk images is not supported.** ``peat pillage`` on disk images needs
  Linux-specific tools (``qemu-nbd`` and kernel modules). Pillaging a directory of files
  works on macOS.
- **Serial port names differ.** macOS names serial devices after the adapter (for example
  ``/dev/cu.usbserial-1410``) instead of numbering them. Pass ``-s`` the device path or
  name (``/dev/cu.usbserial-1410`` or ``usbserial-1410``). Port numbers and ranges (``0``,
  ``0-4``) also work: on macOS they index the sorted list of ``/dev/cu.*`` devices,
  excluding the built-in Bluetooth and debug console ports. Use the ``/dev/cu.*`` "callout"
  devices, not ``/dev/tty.*``, because opening a ``tty`` device waits for a carrier-detect
  signal most devices never send.
- **YMODEM transfers to SEL relays need lrzsz**: ``brew install lrzsz``.
- **ARP cache lookups use the** ``arp`` **command.** macOS has no ``/proc/net/arp``, so
  MAC address resolution runs ``arp -an``; slightly slower than on Linux, otherwise the
  same.
- **The default filesystem (APFS) is case-insensitive.** Files that differ only by case
  (``CONFIG.TXT`` and ``config.txt`` pulled from a device) overwrite each other in PEAT's
  output. If that matters, point the output directory (``-o``) at a case-sensitive APFS
  volume.
- **The application firewall may prompt.** If it is enabled, macOS may ask whether to
  allow ``peat`` (or Python) to accept incoming connections the first time PEAT listens for
  broadcast responses. Allow it, or broadcast scanning may miss devices.
- **The executables are not signed or notarized.** The install script and ``curl``
  downloads are unaffected, but an executable downloaded with a web browser is blocked by
  Gatekeeper until its quarantine attribute is removed:
  ``xattr -d com.apple.quarantine ./peat_macos_arm64``.

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
