************
General APIs
************
Functions used by device module implementations and internally by PEAT.

Datastore
---------
.. automodule:: peat.data.store
   :members:
   :private-members:

High-level APIs
---------------
The scan, pull, push, parse, pillage, and HEAT entry points and their helper functions
are documented on the :doc:`PEAT API <peat_api>` page.

Network Discovery
-----------------
.. automodule:: peat.protocols.discovery
   :members:

Address Parsing
---------------
.. automodule:: peat.protocols.addresses
   :members:

Common networking functions
---------------------------
.. automodule:: peat.protocols.common
   :members:

Communication Protocols
-----------------------

IP
^^
.. automodule:: peat.protocols.ip
   :members:

FTP
^^^
.. automodule:: peat.protocols.ftp
   :members:
   :private-members:

Telnet
^^^^^^
.. automodule:: peat.protocols.telnet
   :members:
   :private-members:

HTTP
^^^^
.. automodule:: peat.protocols.http
   :members:
   :private-members:

MySQL
^^^^^
MySQL and MariaDB are widely deployed relational database servers. In OT environments, MySQL/MariaDB instances are commonly found on historian servers, HMI backends, and engineering workstations.

PEAT supports both unauthenticated fingerprinting (via the TCP greeting packet) and authenticated enumeration (via SQL queries) using the :class:`~peat.protocols.mysql.MySQL` protocol class.

.. seealso::

   :class:`~peat.protocols.mysql.MySQL`
      PEAT protocol class for MySQL/MariaDB connections

   `MySQL Documentation <https://dev.mysql.com/doc/>`__

   `MariaDB Documentation <https://mariadb.com/docs/>`__

   `PyMySQL <https://pymysql.readthedocs.io/en/latest/>`__
      The underlying Python library used for authenticated connections

.. rubric:: Fingerprinting without credentials


MySQL sends an initial handshake packet immediately after a TCP connection is established, before any authentication takes place. This packet includes the server version string (e.g. ``8.0.32`` or ``10.6.12-MariaDB``).

:meth:`~peat.protocols.mysql.MySQL.read_greeting` reads this packet over a raw TCP socket, allowing PEAT to identify a MySQL/MariaDB server and extract its version without credentials.

.. rubric:: Data collected


When credentials are available, PEAT can enumerate the following via SQL queries:

- Server version string and parsed version tuple
- Database names visible to the authenticated user
- Table names per database
- Approximate row counts per table (from ``information_schema``)
- User accounts and their allowed hosts (from ``mysql.user``)
- Grants for each user (``SHOW GRANTS``)
- Global system variables (``SHOW GLOBAL VARIABLES``)
- Active connections and queries (``SHOW FULL PROCESSLIST``)

.. rubric:: Configuration


The protocol's options live under the ``mysql`` key of ``device_options`` in the PEAT
configuration file. Only the connection options have defaults (see
:mod:`peat.data.default_options`); no device module currently uses the class, so there is
no credential option to set:

.. code-block:: yaml

   device_options:
     mysql:
       port: 3306
       timeout: 10

.. rubric:: Developer notes


The :class:`~peat.protocols.mysql.MySQL` class uses a lazy connection pattern: the underlying PyMySQL connection is not established when the object is created, but on the first call to any query method. This avoids opening TCP connections to hosts that are later filtered or skipped before enumeration begins.

The class is designed as a base class. The :meth:`~peat.protocols.mysql.MySQL.on_connected` and :meth:`~peat.protocols.mysql.MySQL.enumerate` hooks are intended to be overridden in device-specific subclasses. ``on_connected`` runs immediately after authentication and can be used to run setup queries or populate instance attributes. ``enumerate`` should return a dict of any device-specific table data — for example, a subclass targeting a historian might query proprietary tables that have no meaning in a generic MySQL context. The base class implementations are no-ops that return nothing and an empty dict respectively.

.. automodule:: peat.protocols.mysql
   :members:
   :private-members:

SNMP
^^^^
.. automodule:: peat.protocols.snmp
   :members:

Serial
^^^^^^
.. automodule:: peat.protocols.serial
   :members:

CIP
^^^
.. automodule:: peat.protocols.cip.cip_packets
   :members:
   :private-members:

ENIP
^^^^
.. automodule:: peat.protocols.enip.enip_driver
   :members:
   :private-members:

.. automodule:: peat.protocols.enip.enip_socket
   :members:
   :private-members:

.. automodule:: peat.protocols.enip.enip_packets
   :members:
   :private-members:

PCCC
^^^^
.. automodule:: peat.protocols.pccc.pccc_functions
   :members:

Utilities/common functionality
------------------------------
.. automodule:: peat.utils
   :members:

Data Utilities
--------------
.. automodule:: peat.data.data_utils
   :members:

Logging Utils
-------------
.. automodule:: peat.log_utils
   :members:

.. _settings-api:

Settings
--------
.. automodule:: peat.settings
   :no-undoc-members:

SettingsManager
^^^^^^^^^^^^^^^
.. automodule:: peat.settings_manager
   :members:
   :private-members:

Constants
---------
.. automodule:: peat.consts
   :members:

CLI internals
-------------
.. automodule:: peat.cli_main
   :members:

cli_args
^^^^^^^^
.. automodule:: peat.cli_args
   :members:


Command Parsers
---------------

.. automodule:: peat.parsing.command_parsers
   :members:
