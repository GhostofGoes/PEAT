********
PEAT API
********
The general :term:`API` provides a generalized interface to execute the PEAT "verbs": scan, parse, pull, push, pillage, and heat. The purpose of this API is to "wrap" the device module API and provide a consistent and well-tested set of powerful interfaces into PEAT's core functionality and device modules. It is used for implementing the PEAT :term:`CLI`, as well as integration with other :term:`SNL`-developed capabilities.

High-level API
==============
.. automodule:: peat.api.scan_api
   :members: scan
   :noindex:

.. automodule:: peat.api.pull_api
   :members: pull
   :noindex:

.. automodule:: peat.api.push_api
   :members: push
   :noindex:

.. automodule:: peat.api.parse_api
   :members: parse
   :noindex:

.. automodule:: peat.api.pillage_api
   :members: pillage
   :noindex:

.. _configuration-api:

Configuration API
=================
Configuration options that are accessible from anywhere in PEAT. These are currently resident in :data:`peat.settings.config` variable, which is a singleton instance of the :class:`~peat.settings.Configuration` class. They can be accessed with ``from peat import config``.

Refer to :doc:`/user_guide/configure` for how to set configuration options, :doc:`/reference/configuration` for the available options, and :doc:`/design/configuration_and_state` for how the system works internally.

.. autoclass:: peat.settings.Configuration
   :members:

Constants
=========
Values determined at program start (platform flags such as ``WINDOWS`` and ``LINUX``, the
start time and time formats, ``RUN_ID``, ``SYSINFO``, ...) live in :mod:`peat.consts`, which is
documented in full in :doc:`general_apis`.

State API
=========
Runtime values that are used to preserve or share state across PEAT. Currently stored in :data:`peat.settings.state` variable, which is a singleton instance of the :class:`~peat.settings.State` class. They can be accessed with ``from peat import state``. The state values are saved to a file when PEAT finishes executing in ``peat_results/<run-dir>/peat_metadata/peat_state.yaml``.

.. note::
   It is possible to modify the starting state via environment variables. Environment variables beginning with ``PEAT_STATE_`` will be loaded to their corresponding variables in the global state registry. This can be useful if debugging or as a temporary patch for a issue. Modifying the state in this manner should be avoided if possible, as it could cause undefined behavior or a crash.

.. autoclass:: peat.settings.State
   :members:

Exceptions
==========
.. autoclass:: peat.consts.PeatError
   :noindex:

.. autoclass:: peat.consts.ParseError
   :noindex:

.. autoclass:: peat.consts.CommError
   :noindex:

.. autoclass:: peat.consts.DeviceError
   :noindex:
