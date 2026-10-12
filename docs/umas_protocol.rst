.. _umas_protocol:

=============
UMAS protocol
=============

.. contents::
   :local:
   :depth: 2

Overview
========
:term:`UMAS` (Unified Messaging Application Services) is a proprietary protocol from Schneider Electric. Unity Pro and EcoStruxure Control Expert use UMAS to configure, monitor and program Modicon PLCs. These PLC families use UMAS:

- M340
- M580
- Quantum
- Premium

UMAS messages go in Modbus messages with function code 90 (``0x5A``). Thus, a PLC gets UMAS messages on the Modbus/TCP port (TCP port 502).

Schneider Electric does not publish a specification for UMAS. This page describes the parts of the protocol that PEAT uses, and the parts that public research describes. Many details are not known.

PEAT uses UMAS in the :class:`~peat.modules.schneider.m340.m340.M340` module. The code is in :mod:`peat.modules.schneider.m340.umas_packets` and :mod:`peat.modules.schneider.m340.umas_codes`.

.. warning::

   Some UMAS functions change the state of the PLC. For example, they stop the PLC, write to memory or send a new program. PEAT does not use these functions. Do not send UMAS messages that you do not understand to a PLC that controls a process.

Message format
==============
A UMAS request is the data of a Modbus request. The Modbus function code is 90 (``0x5A``).

.. code-block:: text

   +--------------------+------+-------------+---------------+-----------+
   | Modbus/TCP header  | 0x5A | Session key | UMAS function | Data      |
   | (7 bytes)          |      | (1 byte)    | (1 byte)      | (0+ bytes)|
   +--------------------+------+-------------+---------------+-----------+

.. csv-table::
   :header: "Field", "Size", "Description"
   :widths: 20, 10, 70

   "Modbus/TCP header", "7 bytes", "Transaction ID, protocol ID (0), length and unit ID. These fields are the same as in all Modbus/TCP messages."
   "Function code", "1 byte", "``0x5A`` (90). This value tells the PLC that the data is a UMAS message."
   "Session key", "1 byte", "``0x00`` if the client does not have a reservation. Otherwise, the value that the PLC sent when it gave the reservation. Refer to :ref:`umas_reservation`."
   "UMAS function", "1 byte", "The UMAS function code. Refer to :ref:`umas_function_codes`."
   "Data", "0 or more bytes", "The parameters of the function. The format changes with the function."

A UMAS response has the same format, but the byte after the session key is a status code:

.. csv-table::
   :header: "Status", "Description"

   "``0xFE``", "The request was successful."
   "``0xFD``", "The request failed. The data contains more information about the error."

Thus, a UMAS response does not contain the function code of the request. Use the Modbus transaction ID to match a response to its request.

The PEAT code uses these names for the fields:

- ``connectionCode``: the session key.
- ``commandCode``: the UMAS function code in a request, or the status code in a response.

.. _umas_reservation:

Reservation and session key
===========================
A client must reserve the PLC before it can send functions that change the PLC. Read functions do not need a reservation. Only one client can have the reservation at a time.

#. The client sends function ``0x10`` (TAKE_PLC_RESERVATION). The data contains the name of the client.
#. The PLC sends a 1-byte session key in the response.
#. The client puts the session key in all the subsequent requests.
#. The client sends function ``0x12`` (KEEP_ALIVE) at intervals to keep the reservation.
#. The client sends function ``0x11`` (RELEASE_PLC_RESERVATION) to release the reservation.

The session key is only 1 byte. Kaspersky ICS CERT tells that the M340 uses a fixed session key in firmware versions before 2.7. In newer versions, the session key is random.

Newer firmware versions also have an "enhanced" reservation (function ``0x6E``). This reservation uses the application password with a challenge and a response. Refer to :ref:`umas_sources`.

If a different client has the reservation, the PLC sends the error status ``0xFD``. For example, this occurs if Unity Pro or Control Expert is connected to the PLC. It also occurs if a different client is connected to a different communication module in the same rack.

.. _umas_function_codes:

Function codes
==============
This table shows the known UMAS function codes. The names come from :mod:`peat.modules.schneider.m340.umas_codes`. Many of these names come from public reverse engineering, but no single public source confirms all of them. The "Confirmed by" column shows which public source gives the same code for the same function. Refer to :ref:`umas_sources`.

.. csv-table::
   :header: "Code", "Name in PEAT", "Description", "PEAT uses it", "Confirmed by"
   :widths: 8, 25, 37, 10, 20

   "``0x01``", "INIT_COMM", "Start a UMAS communication. Get the communication parameters.", "No", "Kaspersky"
   "``0x02``", "READ_ID", "Get the identification of the PLC.", "Yes", "Kaspersky"
   "``0x03``", "READ_PROJECT_INFO", "Get information about the project in the PLC.", "No", "Not confirmed"
   "``0x04``", "READ_PLC_INFO", "Get the status of the PLC.", "Yes", "Kaspersky"
   "``0x06``", "READ_CARD_INFO", "Get information about the memory card.", "Yes", "Kaspersky"
   "``0x0A``", "REPEAT", "The PLC sends back the data that it gets. Possibly used for synchronization.", "No", "Not confirmed"
   "``0x10``", "TAKE_PLC_RESERVATION", "Reserve the PLC. Get a session key.", "Yes", "Kaspersky, Armis"
   "``0x11``", "RELEASE_PLC_RESERVATION", "Release the reservation.", "No", "Kaspersky"
   "``0x12``", "KEEP_ALIVE", "Keep the reservation.", "No", "Kaspersky"
   "``0x20``", "READ_MEMORY_BLOCK", "Read a memory block of the PLC.", "No", "Kaspersky, Armis"
   "``0x21``", "(not in PEAT)", "Write a memory block of the PLC.", "No", "Kaspersky, Armis"
   "``0x22``", "READ_VARIABLES", "Read system bits, system words and program variables.", "No", "Not confirmed"
   "``0x23``", "WRITE_VARIABLES", "Write system bits, system words and program variables.", "No", "Not confirmed"
   "``0x24``", "READ_COILS_REGISTERS", "Read coils and holding registers.", "No", "Not confirmed"
   "``0x25``", "WRITE_COILS_REGISTERS", "Write coils and holding registers.", "No", "Not confirmed"
   "``0x29``", "(not in PEAT)", "Write to a physical memory address.", "No", "Armis"
   "``0x30``", "INITIALIZE_UPLOAD", "Start a program transfer from the client to the PLC.", "No", "Kaspersky, Liras en la red"
   "``0x31``", "UPLOAD_BLOCK", "Send one block of the program to the PLC.", "No", "Kaspersky, Liras en la red"
   "``0x32``", "END_UPLOAD", "End a program transfer to the PLC.", "No", "Kaspersky, Liras en la red"
   "``0x33``", "INITIALIZE_DOWNLOAD", "Start a program transfer from the PLC to the client.", "Yes", "Kaspersky, Liras en la red"
   "``0x34``", "DOWNLOAD_BLOCK", "Get one block of the program from the PLC.", "Yes", "Kaspersky, Liras en la red"
   "``0x35``", "END_DOWNLOAD", "End a program transfer from the PLC.", "Yes", "Kaspersky, Liras en la red"
   "``0x38``", "(not in PEAT)", "A security function. The details are not known.", "No", "Kaspersky"
   "``0x39``", "READ_ETH_MASTER_DATA", "Read Ethernet master data.", "No", "Not confirmed"
   "``0x40``", "START_PLC", "Start the PLC.", "No", "Kaspersky"
   "``0x41``", "STOP_PLC", "Stop the PLC.", "No", "Kaspersky"
   "``0x50``", "MONITOR_PLC", "Monitor variables, system bits and system words.", "No", "Not confirmed"
   "``0x58``", "CHECK_PLC", "Get the status of the connection to the PLC.", "No", "Not confirmed"
   "``0x6D``", "(not in PEAT)", "Private message.", "No", "Armis"
   "``0x6E``", "(not in PEAT)", "Enhanced reservation, with the application password.", "No", "Armis"
   "``0x70``", "READ_IO_OBJECT", "Read an I/O object.", "No", "Not confirmed"
   "``0x71``", "WRITE_IO_OBJECT", "Write an I/O object.", "No", "Not confirmed"
   "``0x73``", "GET_STATUS_MODULE", "Get the status of a module.", "No", "Not confirmed"

.. note::

   The words "upload" and "download" have opposite meanings in different sources. In PEAT and in the Liras en la red blog, "upload" is a transfer from the client to the PLC. In the Kaspersky report, "upload" is a transfer from the PLC to the client. The function codes are the same in all sources. Use the function code, not the name, to identify a function.

How PEAT uses UMAS
==================
PEAT uses UMAS for three tasks. PEAT does not change the PLC.

Identification
--------------
The ``M340._verify_modbus()`` method uses two methods to identify an M340:

#. PEAT sends a standard Modbus "Read Device Identification" request (function code 43, ``0x2B``). If the response contains ``Schneider`` and ``BMX P34``, the device is an M340.
#. If the first method fails, PEAT sends UMAS function ``0x02`` (READ_ID) with session key ``0x00``. If the response contains ``BMX P34``, the device is an M340.

Memory card information
-----------------------
The ``_get_modbus_metadata()`` function in :mod:`~peat.modules.schneider.m340.m340_pull` sends UMAS function ``0x06`` (READ_CARD_INFO) with session key ``0x00``. PEAT gets the model of the memory card from the response. The request comes from the `Redpoint modicon-info.nse <https://github.com/digitalbond/Redpoint/blob/master/modicon-info.nse>`__ Nmap script by Digital Bond.

Project file pull
-----------------
:meth:`~peat.modules.schneider.m340.m340.M340.pull_apx_file` gets the project from the PLC. The result is an APX file. Refer to :ref:`schneider_apx_format`. PEAT sends these requests:

#. Function ``0x04`` (READ_PLC_INFO) with session key ``0x00``.
#. Function ``0x10`` (TAKE_PLC_RESERVATION) with the client name ``PEAT - Unity Loader``. The response contains the session key.
#. Function ``0x04`` (READ_PLC_INFO) with the session key.
#. Function ``0x33`` (INITIALIZE_DOWNLOAD). The response gives the total size of the project.
#. Function ``0x34`` (DOWNLOAD_BLOCK), one time for each block. The data of each request contains a block number. The block number starts at 1 and increases by 1 for each request. Each response contains one block of the APX file.
#. Function ``0x35`` (END_DOWNLOAD) after the last block.

PEAT stops step 5 when a response has a ``num`` value of 1, or when a response contains no data. PEAT joins the blocks to make the APX file.

PEAT uses session key ``0x00`` for the first request. The M340 does not accept more than one connection at the same time. If a different client has the reservation, the PLC sends ``0xFD``, and PEAT stops the pull.

PEAT uses these packet formats, as Scapy packets in :mod:`peat.modules.schneider.m340.umas_packets`:

.. csv-table::
   :header: "Packet", "Fields after the Modbus function code"
   :widths: 25, 75

   "``UMASQuery``", "Session key (1 byte), function code (1 byte), ``num`` (2 bytes, big-endian), data (2 bytes, little-endian)."
   "``UMASResponse``", "Session key (1 byte), status (1 byte), ``num`` (2 bytes, big-endian), data length (2 bytes, little-endian), then the data."
   "``UMASConnection``", "Session key (1 byte), function code ``0x10`` (1 byte), two unknown 2-byte values (``0xAF8C`` and ``0x0204``, little-endian), name length (2 bytes), name."
   "``UMASConnectionResponse``", "Session key (1 byte), status (1 byte), new session key (1 byte)."

The meaning of some fields is not known. The packet formats possibly do not agree with the public research for all functions. A comment in the code tells that these packets must be changed to agree with the current knowledge of the protocol.

PEAT writes the packets that it sends and gets to the ``umas-metadata.json`` file in the device output directory.

Security
========
Public research found these problems in UMAS:

- Basic reservation (function ``0x10``) does not authenticate the client.
- The 1-byte session key is easy to guess.
- Some functions can read or write memory without a reservation. CVE-2021-22779 (Armis, "ModiPwn") is a bypass of the enhanced reservation. An attacker can read the password hash with function ``0x20`` (READ_MEMORY_BLOCK) before the reservation.
- Other CVEs are about functions ``0x6D`` (private message), ``0x29`` (write a physical address) and the read of a physical address. Examples are CVE-2018-7852, CVE-2019-6829 and CVE-2020-7537.

Refer to the Schneider Electric security notifications for the firmware versions that remove these vulnerabilities.

.. _umas_sources:

Sources
=======
These public sources describe UMAS:

- `The secrets of Schneider Electric's UMAS protocol <https://ics-cert.kaspersky.com/publications/the-secrets-of-schneider-electrics-umas-protocol/>`__ by Kaspersky ICS CERT (2022). This report is the most complete public description of UMAS. It describes the message format, the function codes, the reservation and the session key.
- `ModiPwn <https://www.armis.com/research/modipwn/>`__ by Armis (2021). This research describes the basic and enhanced reservation, and CVE-2021-22779.
- `The Unity (UMAS) protocol (Part I) <http://lirasenlared.blogspot.com/2017/08/the-unity-umas-protocol-part-i.html>`__ on the Liras en la red blog (2017). This article describes the message format, the status codes and the program transfer functions.
- `UMAS and the cybersecurity of this communications <https://www.incibe.es/index.php/en/incibe-cert/blog/umas-and-cybersecurity-communications>`__ by INCIBE-CERT.
- *Fun with Modbus 0x5a: Nothing New, Still Relevant* by Arnaud Soullié (Wavestone), DEF CON 25 ICS Village (2017). The talk describes Modbus function code 90 and the tools that use it. Refer to the `transcript <https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20villages/DEF%20CON%2025%20villages%20captions/DEF%20CON%2025%20-%20ICS%20Village%20-%20Arnaud%20Soulli%C3%A9%20-%20Fun%20with%20Modbus%200x5a%20-%20Nothing%20New.%20Still%20Relevant.eng.txt>`__.
- *Hacking PLCs and Causing Havoc on Critical Infrastructures* by Thiago Alves, DEF CON 26 (2018). Refer to the `talk description <https://infocondb.org/con/def-con/def-con-26/hacking-plcs-and-causing-havoc-on-critical-infrastructures>`__. The talk is about vulnerabilities in the Rockwell MicroLogix 1400 and the Schneider Electric Modicon M221. Thiago Alves is also the author of `OpenPLC <https://github.com/thiagoralves/OpenPLC_v3>`__.
- `Evil PLC Attack: Weaponizing PLCs <https://claroty.com/team82/research/white-papers/evil-plc-attack-weaponizing-plcs>`__ by Claroty Team82 (2022). This white paper uses UMAS to send a changed project to a PLC.
- The `UMAS driver <https://plc4x.apache.org/plc4x/latest/users/protocols/umas.html>`__ of Apache PLC4X.
- The Metasploit module `modicon_stux_transfer <https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/scada/modicon_stux_transfer.rb>`__. This module sends and gets APX files with function code 90.
