**********************
Continuous integration
**********************
PEAT uses GitHub Actions for testing, building, publishing, and releasing, with an
additional internal GitLab CI pipeline at Sandia for tests against physical devices. The
workflows live in ``.github/workflows/``.

Workflows
=========
.. list-table::
   :header-rows: 1
   :widths: 24 22 54

   * - Workflow
     - Runs on
     - What it does
   * - ``tests.yml`` (Core Tests)
     - Every push and pull request; called by the release workflow
     - **Conventional Commits** check of commit messages; **Changelog Fragment Check**
       (every PR must add ``newsfragments/<PR>.*``); **Changelog Construction Check**
       (``towncrier build --draft``); **Code Quality Checks** (``pdm run lint``,
       ``check-sdist``); **Unit Tests** on a matrix of Python 3.11/3.12/3.13 and
       Ubuntu 24.04, Windows (latest and 2022), and macOS, with slow tests enabled and
       coverage uploaded as artifacts.
   * - ``tests-container.yml`` (Container Tests)
     - Every push and pull request
     - Integration tests against real software: starts the OpenPLC Runtime v4 container,
       seeds a user, and runs ``pytest --run-container`` for the OpenPLC module; runs the
       MySQL integration tests against a MySQL 8 service container.
   * - ``build.yml`` (Build)
     - Every push and pull request; called by the release workflow
     - Builds the Python package (and checks its contents), the Linux executables (PEAT
       and Sneakypeat, with StaticX), and the Windows executables, and smoke-tests each
       (``--version``, ``--list-modules``, a parse with the example module). Also builds
       the HTML docs and man page. Artifacts are uploaded for download from the run.
   * - ``documentation.yml`` (Documentation)
     - Pull requests (check), pushes to ``main`` (deploy), and dispatch from the release
       workflow
     - Builds the HTML documentation with warnings as errors, runs the accessibility
       checks, and (on ``main``) deploys to GitHub Pages. Link checking runs as a
       non-blocking job.
   * - ``docker.yml`` (Docker Build and Release)
     - Pushes to ``main`` and ``v*`` tags
     - Builds the container image and pushes it to ``ghcr.io/sandialabs/peat`` with tags
       for the branch, version, and commit.
   * - ``devcontainer.yml`` (Devcontainer Build)
     - Pushes to ``main`` that change the dependencies or devcontainer configuration
     - Builds and pushes the multi-architecture devcontainer image.
   * - ``release.yml`` (Create Release)
     - Manual dispatch by a maintainer
     - Runs tests and builds with the release version stamped in, updates the changelog
       with Towncrier, creates the tag, dispatches the documentation deploy, and creates a
       draft GitHub release with all artifacts. See :doc:`releases`.
   * - ``codeql.yml`` (CodeQL)
     - Pushes and PRs to ``main``, weekly
     - GitHub's static security analysis for Python.
   * - ``dependency-review.yml``
     - Pull requests
     - Flags dependency changes that introduce known vulnerabilities or license problems.

Conventions in the workflows
============================
- **Pinned actions.** Every ``uses:`` is pinned to a commit SHA with the version in a
  comment, to protect against tag hijacking. ``pdm run update-actions`` updates them
  (see :doc:`building`).
- **Hardened runners.** Jobs start with `step-security/harden-runner <https://github.com/step-security/harden-runner>`__.
  Most use ``egress-policy: block`` with an explicit allow-list of endpoints; jobs that
  need broad network access (building, browser downloads) use ``audit``. If a job fails
  because an endpoint is blocked, check the StepSecurity report in the job output, add
  the endpoint if it's legitimate, and keep the policy on ``block``.
- **Minimal permissions.** ``permissions: contents: read`` by default, elevated only in
  the jobs that need to write (packages, pages, releases).
- **PDM everywhere.** Jobs install with ``pdm sync -G <group>`` for just the dependency
  groups they need (``lint``, ``test``, ``exe``, ``docs``), with PDM's cache enabled.
- **Version stamping.** Build jobs accept a ``version`` input (``PDM_BUILD_SCM_VERSION``)
  so the release workflow can build artifacts for a tag that doesn't exist yet.

Internal GitLab CI
==================
Sandia runs an internal GitLab CI pipeline that executes the live tests
(``@pytest.mark.gitlab_ci_only``, ``@pytest.mark.broadcast_ci``) against the PEAT device
rack (physical relays, PLCs, and RTUs) and a live Elasticsearch server, using the built
executable. These validate the end-to-end user experience on real hardware. They are part
of the release requirements but are not visible on GitHub; maintainers run them before
cutting a release.

Running CI locally
==================
Most of what CI does can be run locally before pushing:

.. code-block:: bash

   pdm run pre-commit run --all-files    # Commit hygiene, Ruff, Towncrier fragments
   pdm run lint                          # Code quality
   pdm run test-full                     # Unit tests with slow tests
   pdm run check-sdist --inject-junk     # Package contents
   pdm run docs-html                     # Documentation with -W
   pdm run docs-a11y                     # Accessibility
   pdm run build-exe                     # The executable for this platform
   pdm run towncrier build --draft       # The changelog with pending fragments

The container tests and the Windows/macOS matrix are the pieces that generally need CI
(or the setup in :doc:`testing`).
