***
SEL
***

There are many Schweitzer Engineering Laboratories (SEL) devices supported by PEAT, including Real Time Automation Controllers (RTACs), the SEL-3620 security gateway, and many types of protection relays. These are implemented by the PEAT modules :class:`~peat.modules.sel.sel_rtac.SELRTAC`, :class:`~peat.modules.sel.sel_3620.SEL3620`, and :class:`~peat.modules.sel.sel_relay.SELRelay`, respectively.

.. seealso::

   `SEL Technical Papers <https://selinc.com/literature/technical-papers/>`__

   `SEL products page <https://selinc.com/products/>`__

   `SEL-351S documentation <https://selinc.com/products/351S/docs/>`__

   :class:`~peat.modules.sel.sel_relay.SELRelay`
      PEAT :class:`~peat.device.DeviceModule` implementation for protection relays and other SEL devices

   :class:`~peat.modules.sel.sel_3620.SEL3620`
      PEAT :class:`~peat.device.DeviceModule` implementation for SEL-3620 security gateways

   :class:`~peat.modules.sel.sel_rtac.SELRTAC`
      PEAT :class:`~peat.device.DeviceModule` implementation for SEL RTACs

Terminology
-----------
- Substation Configuration Language (SCL)
- Configured IED Description (CID)

File types
----------
- IED Capability Description file (.ICD)
- System Specification Description (.SSD) file
- Substation Configuration Description file (.SCD)
- Configured IED Description file (.CID)

Data Collected
--------------
- Full device configuration file
- Firmware version and release date
- Firmware ID
- Part number
- Relay ID
- Protection schemes
- Trip logic
- Modbus and DNP3 register maps
- Sequential Events Recorder (SER) and event history, and the uptime calculated from the SER

Relays
------

Relay communications
^^^^^^^^^^^^^^^^^^^^
There are several methods PEAT can interact with a SEL relay: FTP, Telnet, HTTP/HTTPS, and directly connected via serial (currently, EIA-232/RS-232 is supported for serial communications). Devices are verified and commands are run via Telnet or serial, device configuration is pulled via HTTP, FTP, Telnet, or serial, and pushed via FTP. PEAT only restarts a relay after a push, if ``sel.restart_after_push`` is enabled (refer to `Restarting relays`_).

Command timing
^^^^^^^^^^^^^^
Over Telnet and serial, PEAT sends a SEL ASCII command and waits for the relay's prompt, which the relay sends when the command's output is complete. Before, PEAT slept for a fixed time after each command (e.g. 5 seconds for ``ID`` and 10 seconds for each ``FILE DIR``) and read whatever had arrived, which was slow, and cut off the output on slow links (a file download stopped at the first pause in the data).

- The relay sends the output of a command as a message (STX, the lines, ETX), and then the prompt as its own message, e.g. ``\x03\x02\r\n=>>\x03`` (refer to `Telnet notes`_), or ``\x03\x02 *>>\x03`` on the SEL-2032 (IM 20120126, Figure 8.1). PEAT uses the framed prompt as the end of the output. A prompt that isn't framed counts if it's at the start of a line at the end of the data, and no more data arrives within 0.3 seconds (so ``=>`` isn't taken for the beginning of ``=>>``). Text that looks like a prompt inside a message that hasn't ended (e.g. a line of a file) isn't the prompt.
- The prompt shows the access level, which PEAT tracks on Telnet and serial: ``=`` (0), ``=>`` (1), ``==>`` (B), ``P=>``, ``A=>``, ``O=>`` (P, A, O on 400 series relays), ``=>>`` (2), ``==>>`` (C), ``*``, ``*>``, ``*>>`` (SEL-2030/2032), ``#``, ``#>``, ``#>>`` (SEL-2701 Ethernet card), and ``!>`` (SELBOOT: the relay is disabled, and PEAT doesn't send anything else on the connection). A relay keeps its access level on a serial port after PEAT disconnects, so PEAT checks the prompt before it elevates, and sends ``QUIT`` before it disconnects.
- Commands with little output (e.g. ``ID``, ``ACC``) wait at most until nothing arrives for the connection timeout (``telnet.timeout`` or ``timeout``, 5 seconds by default; at least 5 seconds for ``ID``, the delay it had before). Until PEAT has seen a SEL prompt on the connection, it stops reading the output of ``ID`` after that time, even if the device keeps sending data, so scanning a device that isn't a SEL device doesn't take much longer than before. Commands with a lot of output, or that take a while to start (``SER``, ``HIS``, ``STA``, ``FILE DIR``, ``FILE SHOW``), wait as long as data keeps arriving, until nothing arrives for ``sel.ascii_idle_timeout`` seconds (30 by default; increase it for slow links).
- If the prompt doesn't arrive, PEAT logs a warning and uses the output it has. A file read with ``FILE SHOW`` is only used if the end of the file (ETX) arrived, so a file is never saved partially. Relays frame error messages with STX and ETX like a file, so a one-line message such as "Invalid File Name" is treated as an error, not as the file.
- If the relay asks a question (``(Y/N)`` or ``(Y,N)``, outside of a message) after a command that shouldn't ask one, PEAT answers ``N`` and the command fails, instead of taking the next command as the answer. For example, ``STA`` at level 2 on a SEL-400 series relay asks "Accept new hardware configuration (Y/N)?" after a board change, and ``N`` aborts it (SEL-421 IM 20130627, Table 9.125).
- Output that arrives right after the connection is opened (e.g. a banner) is read and discarded before the first command.
- With ``sel.legacy_ascii_timing: true``, PEAT uses the fixed delays of earlier versions instead of waiting for the prompt. Only use this if commands time out on a device. Logins and the restart dialog always wait for the relay's prompts.

The waiting is done by :class:`~peat.protocols.expect.Expecter` (:mod:`peat.protocols.expect`), which reads from a Telnet connection (:meth:`peat.protocols.telnet.Telnet.expect`), a socket, a pyserial port, or a SSH channel, until a regular expression matches. ``pexpect`` isn't used, since it doesn't work with serial ports on Windows.

Logins (``ACC``, ``2AC``, ``CAL``) work like this:

#. PEAT sends the command and waits for "Password: ?" or a prompt. If the relay shows a prompt instead, no password is needed (e.g. the access jumper is installed), or the level isn't allowed: "Invalid Access Level" for ``2AC`` usually means that the port's maximum access level (``MAXACC``) is lower.
#. PEAT sends the password and checks the next prompt. If the relay asks for the password again, the password was wrong: PEAT sends CAN (Ctrl+X) to end the dialog, and doesn't try another password for that level on the connection. Relays block access for 30 seconds and assert the BADPASS alarm bit after three wrong passwords in a row (SEL-351S Instruction Manual, Section 10). A password that was rejected isn't sent to the same device again until the next pull or restart.
#. If the relay doesn't show its prompt after CAN (or after ``N`` to a question), anything PEAT sends could be taken as an answer, e.g. another wrong password. PEAT then sends nothing else on the connection: commands raise :class:`~peat.modules.sel.sel_ascii.SELSessionHalted` (``halted`` says why), the pull stops running commands and downloading files, and the connection is closed without ``QUIT``. On serial this stays in effect after the port is closed, since the relay's port keeps its state.
#. PEAT's pull, push, and restart don't elevate to level C (``CAL``). Only programs that use the API do, with ``elevate(3)``.

Passwords are replaced with ``<redacted>`` in the commands PEAT records (``all_writes`` in ``logs/selascii-protocol-data_*.json``) and aren't logged. If a relay echoes a configured password, it's replaced in the recorded output (``all_output``, ``raw_output``, and ``raw-telnet-output.json``) too. Relays echo a ``*`` for each character of a password.

Default credentials
^^^^^^^^^^^^^^^^^^^
If credentials aren't configured, PEAT uses the factory default passwords for the relay's model family, from the tables in public SEL instruction manuals (:mod:`peat.modules.sel.sel_default_creds` has the details). The model is known from the ``ID`` command (which works at access level 0) or from the identification of the device.

.. list-table::
   :header-rows: 1

   * - Model family
     - 1 (``ACC``)
     - B (``BAC``)
     - 2 (``2AC``)
     - C (``CAL``)
     - Source
   * - 300 series (e.g. 311C, 351, 351S, 387, 587)
     - ``OTTER``
     - ``EDITH``
     - ``TAIL``
     - ``CLARKE``
     - SEL-351S IM 20171023, Table 10.21. The SEL-551 (IM 20151105) has no level B.
   * - 400 series (e.g. 411L, 421, 451, 487E)
     - ``OTTER``
     - ``EDITH``
     - ``TAIL``
     - ``Sel-1``
     - SEL-421 IM 20130627, Table 4.4. Also P ``AMPERE``, A ``VOLTA``, O ``WATT``.
   * - 700 series (e.g. 700G, 710, 751, 751A, 787)
     - ``OTTER``
     - (no level B)
     - ``TAIL``
     - ``CLARKE``
     - SEL-751A IM 20130329, Table 7.34; SEL-700G IM 20150521, Table 7.37
   * - SEL-2030 and SEL-2032
     - ``OTTER``
     - (no level B)
     - ``TAIL``
     - ``CLARKE``
     - SEL-2032 IM 20120126, Table 3.1
   * - Other models (e.g. SEL-2411, SEL-734 and SEL-735 meters)
     - ``OTTER``
     - ``EDITH``
     - ``TAIL``
     - ``CLARKE``
     - PEAT's previous defaults

- Configured credentials always win: ``sel.creds`` (for each level that's set), ``ftp.user`` and ``ftp.pass`` or ``ftp.creds``, and ``web.user`` and ``web.pass``, in the global ``device_options`` or the host's ``options``. They're used as they are, in the configured order. Empty values (e.g. ``creds: {}`` in the example configuration) aren't set.
- A level in ``sel.creds`` can be a list of passwords. Since each level is tried once per connection, the next password is only tried on a new connection. PEAT's pull and restart log in on one connection and don't reconnect after a failed login, so they only use the first password of the list. The others are only tried by programs that use the API and call ``elevate()`` again on new connections.
- ``CLARKE`` isn't documented for level C on the 400 series. ``sel.cal_clarke_fallback: true`` adds it after ``Sel-1``, for programs that elevate to level C on a new connection (PEAT's pull, push, and restart don't use level C).
- FTP: on 300 and 700 series relays, the user is the ``FTPUSER`` port setting (``FTPUSER`` by default) and the password is the level 2 password. The SEL-351 uses ``FTP``. On 400 series relays and SEL-2701 Ethernet cards, the user is the access level command (``2AC`` or ``ACC``) with its password. If the ``FTPUSER`` setting is known from settings PEAT parsed before, it's tried first. Anonymous FTP is only tried if the settings say it's enabled (``FTPANMS``). At most 4 default logins are tried, since many relays lock out FTP after 5 failed logins (the SEL-451, SEL-411L, and SEL-487E used to get 6).
- Web interface: ``acc`` and then ``2ac`` are tried as the user, with the level's configured or default password. PEAT only reads from the web interface. It used to also try ``bac`` and ``cal``, which made up to 4 failed logins on a relay with non-default passwords.
- The source of each credential (configured, or the default for which family) is logged, but not the password.
- The SEL-3620 module now has its own default web passwords (``admin`` and ``rtac``, guesses that aren't documented by SEL), which it got from the SELRTAC defaults before. The RTAC defaults aren't changed.

Restarting relays
^^^^^^^^^^^^^^^^^
If ``sel.restart_after_push`` is enabled, PEAT restarts the relay with ``STA C`` via Telnet after a push (:meth:`~peat.modules.sel.sel_relay.SELRelay.restart_relay`). Most settings changes don't need a restart. ``STA C`` reboots the relay like a power cycle: protection is interrupted while the relay restarts, and the relay's self-test warnings and failures are cleared.

#. PEAT connects (with up to 3 connection attempts), elevates to level 2 (a failed login isn't retried), checks that the relay shows the level 2 prompt (``=>>``), and records the FID (``ID``) and the relay's time (``DATE`` and ``TIME``).
#. PEAT sends ``STA C`` and waits for the confirmation question (on the SEL-351S: "Reboot the relay and clear status" / "Are you sure (Y/N) ?"). If the relay answers with an error (e.g. "Invalid Access Level"), shows its prompt, or doesn't ask within 10 seconds, the restart failed. A question about a new hardware configuration, firmware, or defaults is answered with ``N`` (SEL-400 series relays may ask "Accept new hardware configuration (Y/N)?").
#. PEAT answers ``Y``. The restart was initiated if the relay says it's rebooting ("Rebooting the relay"), closes the connection, doesn't respond for 10 seconds, or shows the level 0 prompt. PEAT then closes the connection without sending ``QUIT``.
#. If ``sel.restart_verify`` is enabled (the default), PEAT waits for the relay to come back: via Telnet, it checks the Telnet port every 5 seconds until it closes (up to 60 seconds) and opens again (up to ``sel.restart_timeout`` seconds, 300 by default), then connects and checks that the FID is the same. Via serial, it waits for the prompt (a relay with ``AUTO=Y`` sends a power-up message by itself, otherwise PEAT sends a carriage return every 5 seconds) and checks the FID. If PEAT didn't see the port close (or the prompt change to level 0), the restart isn't confirmed. If the relay comes back with the SELBOOT prompt (``!>``), the restart failed, and PEAT doesn't send anything to it.

The result is in ``extra.restart`` of the device: ``status`` (``initiated``, ``failed``, ``unsupported``, or ``unknown``), ``reason``, ``restart_reason``, ``initiated``, ``verified``, ``fid``, ``fid_after``, ``device_time``, ``initiated_at``, ``back_at``, ``duration_s``, ``port_went_down``, and the dialog (``transcript``). The push is only successful if the restart was initiated and, if ``sel.restart_verify`` is enabled, verified.

PEAT never uses other ways to restart a relay: ``L_D`` starts the firmware loader and disables the relay, ``R_S`` restores the factory settings, and a DNP3 cold or warm restart only restarts the DNP3 port on some relays (e.g. the SEL-421 and SEL-487B). The SEL-2030 and SEL-2032 don't have a SEL ASCII command to restart them, so they aren't supported.

.. note::
   The manuals only print the ``STA C`` dialog of the 300 series. The 700 and 400 series dialogs are matched by the ``(Y/N)`` or ``(Y,N)`` question, and haven't been tested on relays yet.

File output
^^^^^^^^^^^
While the files generated by PEAT may vary by model and device, they roughly follow the following structure:

- ``<device-address>/``

  - ``formatted-logic.txt`` : The logic sections of the configuration.
  - ``parsed-config.json`` : The parsed configuration in JSON format.
  - ``device-data-full.json`` : All data pulled from the device, including the parsed configuration, telnet data, IP and MAC address, and other information.
  - ``relay_files/``

    - ``CFG.TXT``
    - ``SET_ALL.TXT``
    - ``SETTINGS/``

      - ``... SET_*.TXT ...``

Downloaded file hashes
^^^^^^^^^^^^^^^^^^^^^^
PEAT hashes every file it downloads from a SEL device and every file it creates from those files, and records each one in the device's ``files`` (``device-data-full.json``, ``device-data-files.jsonl``, and the Elasticsearch files index). The hashes (the algorithms in the ``HASH_ALGORITHMS`` option, by default MD5, SHA1, SHA256, and SHA512) are also added to ``related.hash``. PEAT calculates the hashes from the data in memory, before text files are decoded, so files are hashed even when file output is disabled.

These files are recorded:

- Files downloaded from a relay via FTP, Telnet, or serial (``relay_files/``), including the individual settings files (``SET_*.TXT``). ``path`` is the path on the relay (e.g. ``/SETTINGS/SET_1.TXT``) and ``local_path`` is the copy saved by PEAT.
- Pages saved from a relay's web interface (``http_files/``, with the web session ID in the path replaced by ``session``) and the logic settings from those pages (``http_commands/raw_logic_group_<n>.txt``), the RTAC Sequence of Events log (``http_files/soe.csv``), and the X.509 certificates exported from a SEL-3620.
- The output of the additional Telnet and serial commands (``additional-command-outputs.json``), if ``sel.attempt_more_commands`` is enabled.
- Files PEAT creates: ``combined_SET_ALL.txt``, ``extracted_SET_ALL.txt``, and the decompressed contents of ``.CID`` files.
- When parsing (``peat parse``): the files that are parsed, and each stream for the relay in a RDB file. Streams that are outside every relay in a RDB file that has relays are not recorded. The ``path`` of a stream is its path in the RDB file, e.g. ``Relays/<relay name>/set_1.txt``.

Each file's ``extra`` has:

- ``source``: ``download`` (relay file system), ``web_page``, ``web_download``, ``command_output``, ``derived`` (created by PEAT), ``rdb_stream``, or ``parse_input``.
- ``transport``: ``ftp``, ``telnet``, ``serial``, ``http``, or ``https``.
- ``file_transfer`` (relay downloads): ``ftp``, ``file_show`` (the ``FILE SHOW`` command over Telnet or serial), or ``ymodem`` (``FILE READ`` over serial).
- ``derived_from``: the names of the files a derived file was created from.
- ``settings_class`` (settings files): the settings class from the ``[CLASSES]`` section of ``CFG.TXT``, e.g. ``{"class": "1", "name": "Group 1", "checksum": "a9dd3ac2"}``. SEL doesn't document how the checksum is calculated, so PEAT records it as-is and doesn't verify it.

Things to be aware of when comparing hashes:

- A file downloaded with ``FILE SHOW`` won't have the same hash as the same file downloaded with FTP or YMODEM. ``FILE SHOW`` sends the file as text in the terminal, and PEAT removes the start and end of text characters (``0x02`` and ``0x03``) and the terminal output around them, and re-joins the lines. Compare hashes of files that were downloaded the same way.
- ``combined_SET_ALL.txt`` and ``extracted_SET_ALL.txt`` aren't files on a relay, so their hashes won't match a ``SET_ALL.TXT`` downloaded from a relay. If there's no ``SET_ALL.TXT``, then ``logic.hash`` is the hash of the reconstructed settings.
- Some files, such as ``additional-command-outputs.json``, include the time they were collected, so their hashes change on every pull.
- If files in different directories have the same name (e.g. ``EVENTS/HISTORY.TXT`` and ``REPORTS/HISTORY.TXT`` on the 700G), both are saved and recorded. If one of them is in ``REPORTS``, that's the one PEAT parses, otherwise it's the one in the last directory (in sorted order), as before.
- If a file with the same name was already saved (e.g. the same file pulled via Telnet and FTP), the new file is saved as ``<name>.1``, and its ``local_path`` is that file.

Settings files
^^^^^^^^^^^^^^
The files recovered and/or generated vary by model and device. They may include the following:

- ``CFG.TXT``: basic device data (firmware, model) and a list of the configuration files on the device. Every *relay* has this.
- ``CFG.XML``: similar to the above, in XML format. Seen on the 700G, 710, and 751.
- ``SET_ALL.TXT``: the complete device configuration. This is essentially all of the individual configuration files merged into a single file. The file structure is roughly equivalent to INI with some eccentricities. Most relays have this.
- ``SETTINGS/``: directory containing the individual configuration files (``SET_1.TXT``, etc.). Each file begins with an identical ``[INFO]`` section with the device RELAYTYPE, FID, BFID, and part number, followed by the section for that file (e.g. ``[1]`` in ``SET_1.TXT``). Some relays don't have ``SET_ALL.TXT``. In that case, PEAT reconstructs it from ``CFG.TXT`` and the individual files. The reconstructed file is saved as ``combined_SET_ALL.txt`` (when pulling from a relay or parsing a directory of relay files).

The SEL configuration is stored in a single file called SET_ALL.TXT. This file is broken up into multiple sub files representing sections of the configuration, e.g. ``SET_1.TXT`` for the section ``[SET_1]`` in the full configuration. PEAT pulls this file and the individual files from a device via FTP and parses it into useful information. To change the device configuration, the individual files are uploaded via FTP, then the relay is restarted via a command sent over Telnet. The individual files must be sent due to ``SET_ALL.TXT`` being read-only.

Refer to section 10.26 Virtual File Interface in the SEL-351S Protection System Instruction Manual for detailed descriptions of files present on the relay.

Configuration details
^^^^^^^^^^^^^^^^^^^^^
- RID: Relay Identifier. The Relay Identifier is typically used to identify the relay or the type of protection scheme. The relay tags each report (event report, meter report, etc.) with the Relay Identifier and Terminal Identifier. RID and TID settings may include the following characters: ``0-9, A-Z, -, /, ., space``. These two settings cannot be made via the front-panel interface. (source: SEL-351S Protection System Instruction Manual). The factory default RID for most relays is ``FEEDER 1``.
- TID: Terminal Identifier. Typical Terminal Identifiers include an abbreviation of the substation name and line terminal. The factory default TID for most relays is ``STATION A``.
- SID: Station ID
- FID: Firmware ID (refer to the :ref:`sel-firmware-ids` section below)
- BFID: Boot firmware ID (refer to the :ref:`sel-firmware-ids` section below)
- CT: Current Transformer
- PT: Potential Transformer

.. COMMENT: TODO: explanation of SEL config "sections" (e.g. "SET_P1.TXT" and "[P1]" in set_all, etc.). pull from the manuals.

.. _sel-firmware-ids:

Firmware IDs
^^^^^^^^^^^^
- FID: Firmware ID
- BFID: Boot firmware ID
   - Similar to FID, but for the boot firmware

- Example FID: ``SEL-351-5-R510-V0-Z103103-D20110429``
   - Model: ``SEL-351``
   - Variant (??) : ``5`` (some devices may not have this portion)
   - Release: ``R510`` (major release, generally new or changed features)
   - Point release: ``V0`` (minor release, usually fixes or minor changes)
   - Settings version: ``Z103103`` (indicates what version of SEL ACSELERATOR software to use)
   - Firmware release date: ``D20110429``

Per SEL's documentation: "The firmware version will be either a standard release or a point release. A standard release adds new functionality to the firmware beyond the specifications of the existing version. A point release is reserved for modifying firmware functionality to conform to the specifications of the existing version."

Setting categories (configuration sections)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
- SET *(X)*: Group settings (where X := [1, 2, 3, 4])
- SEL L(X): Logic settings (where X := [1, 2, 3, 4])
- SET G: Global settings
- SET P(X): Port settings (where X := [1, 2, 3, 4, 5, F]). "F" is the front port, usually RS-232 serial. The port numberings vary by device.
- SET F: Front-Panel settings
- SET R: Report settings
- SET M: Modbus settings
- SET D: DNP3 settings

Settings file format
^^^^^^^^^^^^^^^^^^^^
Settings files are a mix of INI and CSV. Sections are INI-style headers (``[P5]``). The ``[INFO]`` section has ``KEY=VALUE`` lines. Other sections have CSV lines, where the first value is the setting name and the second is the value. The number of columns and the quoting vary by model and firmware:

.. code-block:: text

   [INFO]
   RELAYTYPE=0351S
   FID=SEL-351S-7-R516-V2-Z106105-D20190111
   [CLASSES]
   1,"Group 1","\SETTINGS\SET_1.TXT","a9dd3ac2"
   [1]
   RID,"FEEDER 7","","","","Relay Identifier (30 characters)"
   [L1]
   OUT101,"TRIP"
   [P5]
   "TPORT",23,"23,1025-65534",I,"","Telnet Port (23,1025-65534)"

- 3xx and 7xx relays generally use ``NAME,"VALUE"``, sometimes with four more columns ending in a description.
- 4xx relays generally quote the setting name and add the range and type (``"NAME",VALUE,"RANGE",TYPE,"","Description"``). The 451 truncates setting names longer than 7 characters.
- ``[CLASSES]`` lists the settings classes in the file, with the file they're from and a checksum.
- ``[STORAGE]`` (4xx) lists other files on the relay, such as ``\SWCFG.ZIP``.
- ``[DNPA]`` and ``[DNPB]`` (311L, 387) are DNP3 maps with all of the points in a single space-separated value.
- QuickSet ends each line in the settings in a RDB file with a file separator character (``0x1C``), and some files end with a substitution character (``0x1A``). PEAT removes these before parsing.

Parsing relay files
^^^^^^^^^^^^^^^^^^^
``peat parse -d selrelay`` accepts the following:

- ``SET_ALL.TXT``
- Individual settings files (``SET_1.TXT``, ``SET_P5.TXT``, etc.). A single file only has part of the settings, e.g. ``SET_P5.TXT`` has the network settings but not the logic.
- A directory of relay files, such as the ``relay_files`` directory from a PEAT pull, files downloaded from a relay with FTP, or settings files extracted from a RDB file. Sub-directories (e.g. ``SETTINGS/``) are included and filenames are case-insensitive. If there's no ``SET_ALL.TXT``, it's reconstructed from ``CFG.TXT`` and the ``SET_*.TXT`` files. Event files (``SER.TXT``, ``CSER.TXT``, ``HISTORY.TXT``, ``CHISTORY.TXT``) and ``*.CID`` files in the directory are parsed into the same device. A directory can have files from multiple relays, with each relay's files in its own sub-directory, and each relay is parsed into its own device.
- QuickSet database files (``*.rdb``), see below.
- Output of the ``SHOW`` (``SHO``) command, saved from a Telnet or serial terminal or the QuickSet terminal. See below.
- ``CFG.TXT``, ``SER.TXT``, ``CSER.TXT``, ``HISTORY.TXT``, ``CHISTORY.TXT``, and ``*.CID`` files.

.. code-block:: bash

   peat parse -d selrelay ./SET_ALL.TXT
   peat parse -d selrelay ./relay_files/
   peat parse -d selrelay ./substation.rdb
   peat parse -d selrelay ./sho_output.txt

Example files, and where they're from, are in ``tests/modules/sel/data_files/relay/``.

SHOW command output
^^^^^^^^^^^^^^^^^^^
The ``SHO`` command displays settings in a terminal. Newer relays use ``:=`` and older relays use ``=``, and there may be multiple settings on a line:

.. code-block:: text

   =>>SHO 1
   Group 1

   RID      := SEL-751
   CTR      := 120                CTRN     := 120
   TR       := 50P1T OR 51P1T OR 51G1T OR 50G1T OR SV01T OR
               REMTRIP

   =>SHO L 1
   SELogic group 1
   TR      =M1P + Z1G + 51PT + 51GT + 50P1*SH0

PEAT determines the settings class from the command (``SHO P 5`` is ``[P5]``, ``SHO L 1`` is ``[L1]``), or from the headings in the output (``Group 1``, ``Port 5``, ``SELogic group 1``, ``Global``) if the command wasn't captured. Indented lines without a setting continue the previous setting's value. The output doesn't include the FID, so the model isn't known unless an ``FID=`` line is included (e.g. from the ``ID`` command).

SEL software: RDB Project Files
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
SEL configuration software (ACSELERATOR QuickSet) stores device configurations in project files with a ``.rdb`` file extension. The ``.rdb`` SEL project files use a file structure called Compound File Binary Format, or Microsoft OLE2 File. PEAT uses the ``olefile`` method ``isOleFile()`` to check the file for the magic number at the start of the header to determine if it is the correct format.

A RDB file can have settings for multiple relays, with a storage for each relay:

.. code-block:: text

   Relays/
       <relay name>/
           Misc/
               Cfg.txt       (same as CFG.TXT on a relay)
               Device.txt    (name of the relay in QuickSet)
               Version       (QuickSet version and when the settings were saved)
               GL1.gle, ...  (logic diagrams)
           set_1.txt, set_P1.txt, ...

Filenames may be lowercase (``set_1.txt``) or uppercase (``SET_1.TXT``), and PEAT matches them without regard to case. PEAT combines each relay's ``Cfg.txt`` and settings files into the ``SET_ALL`` format (saved as ``extracted_SET_ALL.txt``), and parses it with the same code used for configurations pulled from devices. The "Saved on" date from ``Version`` is used for the logic's created and last updated times. The name of the relay in the RDB file is saved in ``extra.rdb_relay_name``.

If there are multiple relays in the file, each relay is parsed into its own device and exported to files. Only the first relay is included in the parse results summary. Relays with the same IP address (e.g. defaults in templates) are kept as separate devices, with an ID of ``<rdb file name>_<relay name>``. The other relays are also exported to Elasticsearch, if it's enabled.


Configured IED Description (.CID) Files
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
``.CID`` files are zlib-compressed text data. This may be :term:`XML` data, or it could be other data. The only file we've seen so far is ``SET_61850.CID``, and it decompresses to XML. The schema for the XML is (I think) standardized by IEC 61850-6. If you are willing to pay for a copy of the standard, then maybe you can make some use out of the XML. It's only relevant if IEC61850 or GOOSE is enabled.

If any ``.CID`` files are found during a PEAT pull, PEAT will attempt to decompress them and put the results in the device output directory with the name of ``decompressed_<filename>.xml`` (or ``.txt`` if non-XML data was extracted from the file). They can also be parsed directly with ``peat parse -d selrelay <filename>`` (e.g. ``peat parse -d selrelay ./SET_61850.CID``).

To manually extract them without using PEAT:

.. code-block:: bash

   sudo apt update
   sudo apt install qpdf
   zlib-flate -uncompress < ./SET_61850.CID > SET_61850.xml

Events and uptime
^^^^^^^^^^^^^^^^^
Relays keep two event logs: the Sequential Events Recorder (SER), which records changes of the relay elements in the SER trigger settings and automatic entries such as power-ups and settings changes, and the event history, a summary of each event report (trips and other triggers). PEAT parses them from:

- Files downloaded from the relay (FTP, ``FILE SHOW``, or YMODEM): ``SER.TXT``, falling back to ``CSER.TXT`` if ``SER.TXT`` has no events, and ``HISTORY.TXT``, falling back to ``CHISTORY.TXT``.
- The ``ser`` and ``his`` commands over Telnet or serial, if ``sel.attempt_more_commands`` is enabled.
- The ``ser`` and ``his`` pages of the relay's web interface.
- The same files when parsing a directory of relay files or a single file (``peat parse -d selrelay``). File names can have a prefix (e.g. ``192.0.2.1_SER.TXT``), and the kind of file is determined by the end of the name.

All of these use the same parsers in :mod:`peat.modules.sel.relay_parse`:

- SER rows are split into the element and state on two or more spaces, since both can have single spaces (``GROUND O/C 1 LINE 1   51S1 PICKED UP``, ``Power-up   Group 1``, ``Relay Powered Up``). Rows that can't be parsed (e.g. ``Invalid Data`` for a record corrupted by a power loss, or the analog lines of a SEL-551 SER) are skipped instead of stopping the parse.
- History reports are parsed using the columns in their header, which vary by relay family (``LOCAT``, ``CURR`` or ``CURRENT``, ``FREQ`` or ``FREQX``, ``GRP``, ``SHOT``, ``TARGETS``). Unknown values (``$$$$$$$``, e.g. the fault location if the fault locator didn't run) are left out, the targets are kept as text, and ``Invalid History Data`` rows are skipped.
- ``CSER.TXT`` and ``CHISTORY.TXT`` are Compressed ASCII (see below). Their values are mapped by the labels, so the different layouts work (e.g. ``"REC_NUM","DATE","TIME","ELEMENT","STATE"`` on the 700 series and ``"#","MONTH","DAY","YEAR",...`` on the 400 series), and the checksums are verified. A SER or history file that's Compressed ASCII is parsed as such, regardless of its name.
- The status information before the events (relay and station ID, the relay's current time, FID, serial number) is added to the device, even when there are no events (``No data available``, ``History Buffer Empty``).
- Data is decoded as UTF-8, or as Latin-1 if it isn't valid UTF-8 (e.g. a ``0xB0`` byte in a SER element name), instead of failing.

Each event is an ``Event`` in the device's ``event`` list:

- ``dataset`` is ``ser`` (SER and CSER) or ``history`` (HISTORY and CHISTORY), and ``extra.source_datasets`` lists where the event was read from (``SER.TXT``, ``SER`` for the command, ``Sequential Event Recorder ('ser')`` for the web page, etc.).
- ``extra`` has the ``element`` and ``state`` of SER events, and the ``event``, ``current``, ``frequency``, ``targets``, ``locat`` (fault location), ``group``, and ``shot`` of history events, if the relay reports them. Events from Compressed ASCII rows with a wrong checksum have ``extra.checksum_valid`` set to ``false``.
- ``sequence`` is the number in the report. ``1`` is the newest event, and the numbers change as events are added.
- The same event from different sources (e.g. ``SER.TXT`` and the ``ser`` command, or ``SER.TXT`` and ``CSER.TXT``) is merged into one event, by its kind (SER or history), time, and element and state (or event). SER and history events are never merged.
- Power-up records (``Relay newly powered up``, ``Relay Powered Up``, ``Power-up``, ``Diagnostic restart``) have the type ``start``. The whole element must be one of these, and its state can't be a Relay Word bit state (``Asserted``, ``Deasserted``), so a SER element or alias such as ``UPS POWER UP`` isn't a power-up. The SEL-551, 710, and 749M log ``Relay newly powered up or settings changed`` for both, so those have the types ``start`` and ``change``.
- Event times are the relay's local time, without a timezone. The order of the date is the relay's ``DATE_F`` setting (``MDY``, ``YMD``, or ``DMY``) if it was parsed from the settings (saved in ``extra.date_format``). Otherwise, it's inferred from the dates (a year first is ``YMD``, a first number larger than 12 is ``DMY``), with ``MDY`` as the default. The settings are parsed before the event files during a pull, so ``DATE_F`` is known.

.. warning::
   On SEL-400 series relays, transferring ``SER.TXT`` (or ``CSER.TXT``) with ``FILE READ`` performs a ``SER CV`` for that port: the SER records that were viewed are cleared for that port, so later reads of the SER from the same port won't have them (the records aren't deleted from the relay, and other ports still have them). This is documented for ``FILE READ`` in the SEL-421 instruction manual (and its virtual file table says ``SER.TXT`` "clears SER when read"). It's inferred, not confirmed, that an FTP download does the same. PEAT downloads ``SER.TXT`` as before, so keep this in mind if someone else reads the SER from the same port after a PEAT pull.

The uptime (``uptime`` and ``start_time``) of a relay isn't reported by any command, so PEAT calculates it from the SER: the uptime is the time between the newest power-up record and the relay's current time when the SER was read (the time in the header of the SER report, or if there isn't one, ``extra.device_time``). Both are from the relay's clock, so the relay's timezone doesn't matter. ``start_time`` is the time of the pull (UTC) minus the uptime. These are only set if they aren't already set. The device's ``extra`` has:

- ``uptime_source``: how the uptime (or its lower bound) was determined: ``ser_power_up``, ``ser_ambiguous_power_up``, or ``ser_oldest_record``.
- ``last_boot_device_time``: time of the newest power-up record (relay local time).
- ``uptime_lower_bound``: if the uptime can't be calculated, the minimum uptime, either since the newest ``Relay newly powered up or settings changed`` record (SEL-551, 710, 749M), or if there's no power-up record, since the oldest SER record.

Limitations of the uptime:

- The SER is a ring buffer (512 to 1024 records, depending on the model), and ``SER C`` clears it, so the power-up record may not be there. Then only the lower bound is known.
- On SEL-400 series relays, the ``ser`` command without arguments returns only the 20 newest records, so over Telnet or serial (``sel.attempt_more_commands``) the power-up record often isn't included. ``SER.TXT`` has all of the records.
- If the relay's clock was changed after the power-up (e.g. it was set from IRIG-B or SNTP after starting with the wrong time), the uptime is wrong. Negative results are ignored.
- When parsing files, the relay's current time isn't known, so only ``last_boot_device_time`` is saved.


Developer notes on SEL communications
-------------------------------------
SEL relays can communicate over Telnet, serial connection (e.g. RS-232), or a "engineering tunnel" through a SEL 3530 RTAC (I'm not aware of any relays that support SSH yet, but there might be some newer ones that do). The messages sent are part of what they call "SEL ASCII" commands, and those commands are transport-agnostic, which means the "id" command sent over Telnet will have the same response as one sent over serial or an engineering tunnel. The commands and responses are basic ASCII text, except in certain cases, where it's "Compressed ASCII" (this is rare).

In addition to "SEL ASCII" interfaces, relays also typically have :term:`FTP` and a web interface (using :term:`HTTP` and/or HTTPS), dependent on the configuration. FTP is typically disabled by default, but can be enabled. Since files can be transferred over "ASCII" or FTP, and the commands are very similar, the file transfer code has been generalized in ``peat/modules/sel/sel_comms.py``.

In PEAT, the "SEL ASCII" commands are implemented as a transport-agnostic class, :class:`~peat.modules.sel.sel_ascii.SELAscii`. The sub-classes for specific transports are :class:`~peat.modules.sel.sel_telnet.SELTelnet` and :class:`~peat.modules.sel.sel_serial.SELSerial`. We don't have support for engineering tunnels through an RTAC (yet). The code for scraping and parsing web pages is implemented by :class:`~peat.modules.sel.sel_http.SELHTTP`. Some of the web pages literally run ASCII interface commands internally and just display the results, while other pages pull data in other ways. The parsers for the output of commands only take text, so they work for output from a web page and from a Telnet/serial session (see :ref:`sel-web-parsing`). The :term:`FTP` interface isn't terribly special, except for a few quirks. The FTP functionality is implemented in ``peat/modules/sel/sel_comms.py`` with functions that call PEAT's generic :class:`~peat.protocols.ftp.FTP` class and handle a few quirks (like changing directories on older relays).

The code gets called from :class:`~peat.modules.sel.sel_relay.SELRelay` class, in the various ``pull_*`` and ``_verify_*`` methods. The ``pull_*`` methods get called by ``pull_project``, which is the function that gets called by PEAT when ``peat pull`` happens, and is defined in the :class:`~peat.device.Device` base class.

.. _sel-web-parsing:

Web interface parsing
^^^^^^^^^^^^^^^^^^^^^
:class:`~peat.modules.sel.sel_http.SELHTTP` fetches pages, and the parsing is done by pure functions that are tested with synthetic pages (``tests/modules/sel/data_files/web/``), so they can be changed without a device:

- Relay pages run an ASCII command and show its output in a ``<pre>`` section, e.g. ``static_command.html?cmd=sho&param=P%205`` on 400-series relays (``SHO P 5``) or ``shop5.html`` on the SEL-351S. :func:`~peat.modules.sel.sel_web_parse.extract_pre_text` gets the text (including text in links, and all sections if there are several), and the text is parsed by functions that also work for the output of the command over Telnet or serial: :mod:`~peat.modules.sel.relay_command_parse` (``VER``, ``ETH``, ``MAC``, ``SHO`` grouped by heading, ``MET``) and :mod:`~peat.modules.sel.relay_parse` (``STA``, ``SER``, ``HIS``, and ``SHO`` by settings class). The ``parse_*`` functions only take text, and the ``process_*`` functions put the result into the device data model. The Telnet and serial code already uses the same functions for ``STA``, ``SER``, and ``HIS``, but not yet the ones in :mod:`~peat.modules.sel.relay_command_parse`.
- RTAC pages (``device_info.sel``, ``diagnostics.sel``, ``post_summary.sel``, ``file_repository.sel``, ``user_table.sel``), the RTAC Sequence of Events log (``soe.csv``, read with the ``csv`` module so quoted commas work), and the SEL-3620 pages (``index.sel``, ``Users.sel``, ``SysLogReport.sel``, ``X509.sel``) are parsed by :mod:`~peat.modules.sel.sel_web_parse`. The RTAC and SEL-3620 user tables have the same layout and share a parser. The SOE log is a history (e.g. the firmware before an upgrade), so its ``Firmware:`` and ``Project:`` messages only fill in values the device doesn't have yet, from the newest message.
- The other SEL-3620 pages PEAT reads (LDAP, RADIUS, firewall, port mappings, etc.) are listed in :data:`~peat.modules.sel.sel_web_parse.GATEWAY_PAGES`. They're saved to ``http_files/``, but not parsed yet. :meth:`SEL3620._pull() <peat.modules.sel.sel_3620.SEL3620._pull>` calls every ``SELHTTP`` method whose name starts with ``gateway_``, so helpers must not use that prefix.
- Logins: the token in the login page is read the same way for relays, RTACs, and the SEL-3620. The relay session URL (``.../protected/N<session>/``) is derived from the response by :func:`~peat.modules.sel.sel_web_parse.derive_relay_session_url`. It must be on the same host as the relay, and on a SEL-351 the session link must be a path on the relay. If the relay doesn't reject the credentials but the session can't be determined, the login raises an error, so no other credentials are tried (they would be failed logins on the relay). :func:`~peat.modules.sel.sel_http.login_with_web_credentials` tries the cached credentials, or each configured user with each password (each combination is a login attempt, which may count towards an account lockout). The SEL-3620 uses it, and the RTAC can too.
- SEL-3620 certificate exports: absolute and relative ``Export`` links are followed, links to other hosts are skipped, and each certificate is downloaded once.
- Values: ``ETH`` counters that are too large for the relay to print (``$$$$$$$``) are ``-1``, the RTAC memory and storage sizes are converted from KB to bytes, and a ``VER`` line that says the hardware doesn't match the part number is kept in ``extra.hardware_warnings``. The ``VER`` checksum is the ``SELboot`` checksum, so it's in ``boot_firmware.checksum`` (and ``firmware.checksum``, as before).

YMODEM notes
^^^^^^^^^^^^

YMODEM is required for relays that don't have the ``file show`` command. PySerial doesn't support YMODEM, and the Python ``modem`` package hasn't been updated in over 11 years, so we're forced to subprocess and call the ``rz`` / ``sz`` commands from the ``lrzsz`` project. This is not available on Windows, but is available on Linux (``sudo apt install lrzsz``) and MacOS (``sudo brew install lrzsz``).

- ``show`` supported: 700G, 351S, 351
- ``read``: 451, 2032 (Requires Ymodem to transfer the file)


Things that don't require YMODEM and use ``fil show``

- 351S doesn't require YMODEM and uses ``fil show``.
- 351S was tested on peat rack (port F, front serial, 9600 baud)
- 351 on peat rack tested (port F, front serial, 57600 baud)
- 700G on peat rack tested (port 3, rear serial, 9600 baud)
- 751 should work with ``fil show`` according to the documentation.
- 710 should also work according to the docs
- 311C-1 has ``file show``, according to docs.

Things that DO require YMODEM for file transfer

- 451: DOES require YMODEM for file transfer. It uses ``fil read <file>`` instead of ``fil show``.
- 451: YMODEM with "file read".
- 487E: YMODEM with "file read".
- 2030 (and 2032?): YMODEM with "file read".

XMODEM devices

- NOTE: XMODEM only works for SELboot, doesn't work during normal operations, according to docs. basically lets you upload and download firmware updates.
- 300G. According to docs it doesn't have any "fil" commands, and also requires XMODEM for transfers.
- 311A. Same as above, according to docs.
- 311L-0-6. Same as above.
- 311L-1-7. Same as above.
- 387. same as above.
- 387A. same as above.
- 587Z. same as above.

Others

- 387L. Not even xmodem...
- 587. not even xmodem.

Telnet notes
^^^^^^^^^^^^

Full list of Telnet commands is in the instruction manual.

From the docs:

   "A command transmitted to the relay consists of the command followed by
   either a CR (carriage return) or a CRLF (carriage return and line feed). You
   can truncate commands to the first three characters. For example, EVENT 1
   <Enter> becomes EVE 1 <Enter>. Use upper- and lowercase characters
   without distinction, except in passwords.

   Each message begins with the start-of-transmission character (ASCII 02) and
   ends with the end-of-transmission character (ASCII 03). Each line of the
   message ends with a carriage return and line feed."

What PEAT sees (note the 0x03 and 0x02 characters):

.. code-block:: Python

   ['id', '\x02', '"FID=SEL-700G-R200-V0-Z006003-D20180629","08F0"', '"BFID=BOOTLDR-R501-V0-Z000000-D20140224","0947"', '"CID=59A0","025C"', '"DEVID=SEL-700G","0408"', '"DEVCODE=74","0312"', '"PARTNO=0700G12B1B1B7281A230","06C2"', '"CONFIG=112222010","041E"', '"SEL DISPLAY PACKAGE=1.0.50700.2000","087C"', '"CUSTOMER DISPLAY PACKAGE=1.574871567","09A2"', '"iedName=","0360"', '"type=","026F"', '"configVersion=","0609"', '"LIB61850ID=5C9A14CB","04F1"', '\x03\x02', '=>>\x03']

Compressed ASCII
^^^^^^^^^^^^^^^^
Compressed ASCII is the comma-delimited form of SEL ASCII responses, meant to be read by programs. The ``ID`` command (above) answers in this format, as do the "C" commands (``CAS``, ``CST``, ``CHI``, ``CSE``, ``CEV``, ``CSU``, ...) and the ``CSER.TXT`` and ``CHISTORY.TXT`` files. PEAT parses it with :mod:`peat.modules.sel.sel_cascii`, which has no I/O, so it works on data from Telnet, serial, files, or captures. The format, from the Compressed ASCII sections of public SEL instruction manuals (e.g. SEL-421 Reference Manual section 5, SEL-351S Appendix K, SEL-551 Appendix E):

- A message starts with STX (``0x02``) and ends with ETX (``0x03``). The relay echoes the command before it, and sends the prompt after it. Files may not have the STX and ETX, and PEAT parses them either way. XON/XOFF characters and binary SEL Fast frames (``0xA5 ...``), which can be mixed in on the same port, are removed.
- Lines end with CR LF (CR on some older relays, such as the SEL-551). Fields are separated by commas. Strings are quoted, and numbers aren't (an empty field is no value, and placeholders like ``$$$$.$$`` are kept as text). Quotes inside strings aren't escaped (e.g. in the settings in ``CEV`` output), so the CSV module can't be used.
- Each line ends with a checksum, four hex digits in quotes (upper or lower case): the sum of the bytes from the first byte of the line through the comma before the checksum, modulo 65536. For example, ``"No Data Available","0668"``. A record with a wrong checksum is kept, marked ``invalid``, and a warning is logged. A string that spans multiple lines (the ``CEV`` settings) is joined into one record. How the relay calculates the checksum of those isn't publicly documented, so if the checksum doesn't match, the record is marked ``unverified`` instead of ``invalid``.
- Label lines (all strings) name the values in the lines after them. Rows can be shorter than the labels (e.g. ``Relay Powered Up`` has no state), and are mapped to the labels by name, not position. PEAT doesn't use the ``TERSE`` option, which removes the label lines.
- ``CAS`` (``CASCII``) lists the compressed commands on the relay, the minimum access level for each, and their layout: ``"<n>H"`` lines with the labels and ``"<n>D"`` lines with the data types (``I`` integer, ``F`` float, ``<n>S`` string) and the maximum number of data lines. :func:`~peat.modules.sel.sel_cascii.parse_cas` parses it, and :func:`~peat.modules.sel.sel_cascii.parse_report` can use the layout instead of guessing which lines are labels.

``ID`` output is parsed by :func:`~peat.modules.sel.sel_cascii.parse_id_output`: each ``KEY=VALUE`` is split at the first ``=``, with the spaces removed (700-series relays print ``"iedName =TEMPLATE"``), keys without a value (``"iedName="``) are skipped, and the checksums are verified. Some relays print ``PARSE FAILURE`` as the IEC 61850 values if their CID file is invalid. Those values aren't used, and the keys are listed in ``extra.iec61850_parse_failure``. The previous parser dropped the last two lines of the output (e.g. ``LIB61850ID``) and cut off values with a ``=`` in them.
