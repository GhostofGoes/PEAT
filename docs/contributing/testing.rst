.. _test-docs:

*******
Testing
*******
Regressions are a menace, and especially so for PEAT because of its complexity. The goal
of the test suite is to cover the major features with a minimal amount of effort, so that
future changes don't cause major breakages (for example, a change in parsing logic
breaking scanning). Every change should come with tests; every module should have at
least basic parse tests with sample data.

Kinds of tests
==============
- **Quality checks**: linting, formatting, spelling, unused code, type checking
  (``pdm run lint``, ``pdm run typecheck``). Run in CI on every push and pull request.
- **Unit tests**: `pytest <https://docs.pytest.org/en/stable/>`__ tests of the CLI, the
  APIs, the data model, protocols, and modules, using sample files in ``data_files/``
  directories and mocked network interactions. Run in CI on Linux, Windows, and macOS
  across Python 3.11, 3.12, and 3.13.
- **Container-based integration tests**: tests that run against real software in a
  container, currently the OpenPLC Runtime v4 module against the official OpenPLC
  container, and the MySQL protocol against a MySQL service. Marked
  ``@pytest.mark.container``, skipped unless ``--run-container`` is given, and run in CI
  by the ``Container Tests`` workflow. This is the model for testing any module whose
  device has a simulator or software implementation.
- **Live device tests**: tests against physical devices on Sandia's PEAT device rack and
  against a live Elasticsearch server, run by an internal GitLab CI pipeline. They
  validate the end-to-end user experience with the real executable, but can't catch
  logic failures (bad output, missing files) as precisely as unit tests, and failures are
  more time consuming to debug. Marked ``@pytest.mark.gitlab_ci_only`` and
  ``@pytest.mark.broadcast_ci``; **not run on GitHub**.

Running the tests
=================
Run from the root directory of the repository.

.. code-block:: bash

   pdm install -d                 # Make sure the environment is up to date

   pdm run lint                   # Quality checks
   pdm run test                   # Unit tests, excluding slow tests (fast)
   pdm run test-full              # Unit tests including slow tests (what CI runs)

   # Any pytest invocation
   pdm run pytest -h              # pytest's own help
   pdm run pytest -k "test_some_code"
   pdm run pytest tests/modules/sandia/
   pdm run pytest -v              # Verbose
   pdm run pytest -vv             # Detailed diffs on failures
   pdm run pytest -x              # Stop at the first failure
   pdm run pytest --maxfail=2
   pdm run pytest --lf            # Only the tests that failed last time
   pdm run pytest --ff            # All tests, last failures first
   pdm run pytest --durations=10  # Slowest tests

   # Slow tests (marked @pytest.mark.slow): the CLI, SEL parsing, and a few others
   pdm run pytest --run-slow
   pdm run pytest -k "test_cli" --run-slow

   # Container-based tests (needs the container running; see below)
   pdm run pytest --run-container tests/modules/openplc/

   # A specific Python version
   pdm use -f 3.12
   pdm install -d
   pdm run test

``pdm run test`` runs tests in parallel (``-n 4``), with coverage reporting
(``htmlcov/``), doctests in the source (``--xdoctest``), and in random order
(``pytest-randomly``) to shake out hidden dependencies between tests. Setting the
``RUN_SLOW`` environment variable also enables the slow tests.

Markers and options
===================
Defined in ``pyproject.toml`` (``[tool.pytest.ini_options]``) and ``tests/conftest.py``:

.. list-table::
   :header-rows: 1
   :widths: 24 24 52

   * - Marker
     - Enabled by
     - Meaning
   * - ``slow``
     - ``--run-slow`` or ``RUN_SLOW``
     - Lower-importance tests that take a long time
   * - ``container``
     - ``--run-container``
     - Integration tests requiring a live service container (OpenPLC, MySQL)
   * - ``gitlab_ci_only``
     - ``--run-ci`` or the GitLab CI environment
     - Tests against live devices on the PEAT rack; arguments (addresses) come from
       environment variables
   * - ``broadcast_ci``
     - ``--run-broadcast-ci``
     - Live broadcast scanning tests on the PEAT rack
   * - ``live``
     - (informational)
     - Tests requiring a running OpenPLC instance or a PHENIX environment

Running the container tests locally
===================================
The OpenPLC tests need the runtime container with an ``admin`` user, exactly as the
:doc:`OpenPLC lab tutorial </tutorials/openplc_lab>` sets it up:

.. code-block:: bash

   docker run -d --name openplc-runtime -p 8443:8443 --cap-add=SYS_NICE --cap-add=SYS_RESOURCE \
       -v openplc-runtime-data:/var/run/runtime ghcr.io/autonomy-logic/openplc-runtime:latest
   until curl -k -s https://127.0.0.1:8443/api/version > /dev/null; do sleep 2; done
   curl -k -X POST https://127.0.0.1:8443/api/create-user -H "Content-Type: application/json" \
       -d '{"username": "admin", "password": "admin", "role": "user"}'

   pdm run pytest -v --run-container tests/modules/openplc/test_openplcv4_container.py

The MySQL tests expect a server described by ``MYSQL_HOST``, ``MYSQL_PORT``,
``MYSQL_USER``, and ``MYSQL_PASSWORD``:

.. code-block:: bash

   docker run -d --name mysql -p 3306:3306 -e MYSQL_ROOT_PASSWORD=testpass mysql:8.0
   MYSQL_HOST=127.0.0.1 MYSQL_PORT=3306 MYSQL_USER=root MYSQL_PASSWORD=testpass \
       pdm run pytest -v --run-container tests/protocols/test_mysql_integration.py

``.github/workflows/tests-container.yml`` is the reference for both.

Writing tests
=============
- Put tests next to what they test: ``tests/test_<module>.py`` for top-level modules,
  ``tests/api/``, ``tests/data/``, ``tests/parsing/``, ``tests/protocols/``, and
  ``tests/modules/<vendor>/`` for device modules.
- Sample inputs go in a ``data_files/`` directory beside the test, and the ``datapath``
  fixture (``tests/conftest.py``) resolves a file name to its path. Keep sample files
  small, synthetic or sanitized, and free of real credentials and addresses (use the
  ``192.0.2.0/24`` documentation range). Binary or very large files are only accepted
  from trusted contributors with verified provenance.
- Compare parsed output against an expected JSON file with ``deepdiff``;
  ``pytest_assertrepr_compare`` in ``conftest.py`` pretty-prints the differences.
  ``tests/generate_test_data_files.py`` regenerates expected outputs when the data model
  changes intentionally.
- Mock the network: ``requests-mock`` for HTTP, ``pytest-mock`` (``mocker``) for sockets,
  serial ports, and protocol classes. Unit tests must never reach a real device.
- The ``conftest.py`` disables PEAT's file output and exit handlers for the test session
  and resets the datastore between tests; look there before fighting with global state.
- Mark tests that take more than a few seconds ``@pytest.mark.slow``; keep ``pdm run test``
  fast enough to run constantly.
- Test the CLI through ``tests/test_cli*.py`` patterns (invoking ``peat`` with arguments
  and checking the summary and files), not by shelling out.

Test organization
=================
.. code-block:: text

   tests/
       conftest.py                  Configuration of pytest, fixtures, markers
       generate_test_data_files.py  Regenerates expected-output files
       test_*.py                    Unit tests for the top-level peat/*.py modules
       data_files/                  Files used by the tests at this level
       api/                         High-level API tests (scan, pull, parse, push, pillage)
       data/                        Data model, datastore, and data utilities
       modules/
           <vendor>/
               data_files/
               test_<device>.py
               test_<device>_container.py
       parsing/                     Shared parsers (command output, TC6)
       protocols/                   Protocol clients and networking helpers
           data_files/
           enip/

Tools
=====
- `pytest <https://docs.pytest.org/en/stable/>`__ with ``pytest-cov``, ``pytest-mock``,
  ``pytest-randomly``, ``pytest-xdist``, ``pytest-loguru``, ``pytest-sugar``,
  ``requests-mock``, ``xdoctest``, and ``deepdiff`` (all in the ``test`` dependency group)
- `pyenv <https://github.com/pyenv/pyenv>`__ to install several Python versions side by
  side for ``pdm use`` (note that executables can't be built with pyenv Pythons; see
  :doc:`building`)
- The documentation has its own checks (``-W`` builds, link checking, accessibility); see
  :doc:`documentation`
