.. _contributor_guide:

Contributing to PEAT
********************

PEAT is an open source project, and we welcome contributions from the community: bug
reports, documentation, new device modules, and fixes. This file is the contribution
*process*. The rest of the contributor documentation (setting up a development
environment, code guidelines, logging, testing, building, continuous integration, and
releases) is in the Contributing section of the PEAT documentation:
https://sandialabs.github.io/PEAT/contributing/

.. note::
   This file (``CONTRIBUTING.rst`` in the root of the repository) is the single source of
   truth for the contribution process, and is what GitHub links to when opening issues and
   pull requests. Pull requests that don't follow this guide may be delayed until they
   comply.

- Development environment: https://sandialabs.github.io/PEAT/contributing/development_environment.html
- Code guidelines and conventions: https://sandialabs.github.io/PEAT/contributing/code_guidelines.html
- Logging: https://sandialabs.github.io/PEAT/contributing/logging.html
- Testing: https://sandialabs.github.io/PEAT/contributing/testing.html
- Documentation: https://sandialabs.github.io/PEAT/contributing/documentation.html
- Building and packaging: https://sandialabs.github.io/PEAT/contributing/building.html
- Continuous integration: https://sandialabs.github.io/PEAT/contributing/ci.html
- Releases: https://sandialabs.github.io/PEAT/contributing/releases.html
- Tour of the codebase: https://sandialabs.github.io/PEAT/contributing/codebase_tour.html
- Writing a device module: https://sandialabs.github.io/PEAT/developer/module_developer_guide.html


How to contribute
-----------------

#. **Track the work**

   Submit a bug report or feature request via the `issue tracker <https://github.com/sandialabs/PEAT/issues>`__ or `discussions <https://github.com/sandialabs/PEAT/discussions>`__ on GitHub. If the idea is new or complex, we recommend discussing it before implementation, to avoid wasting time on an idea that may not be accepted due to lack of consensus.

#. **Create a fork of PEAT**

   All changes will be made on your personal fork (a copy of the repository).

#. **Create a branch**

   Name the branch ``<type>/<short-description>``, using the same ``type`` values as for commit messages (listed below), e.g. ``fix/slow-model-processing`` or ``feat/my-new-feature``.
   Commit as you progress (``git add`` and ``git commit``).
   Ensure commits are scoped to a single change, avoid combining multiple changes into a single commit.

   Commit messages MUST adhere to `Conventional Commits <https://www.conventionalcommits.org>`_:

   .. code-block:: text

      <type>(<optional scope>): <subject>

      <optional body>

   - ``type`` MUST be one of the types listed below, and MUST be **lowercase** (e.g. ``feat``, not ``Feat`` or ``FEAT``). The Conventional Commits specification allows any case, but PEAT requires lowercase: the pre-commit hook and the CI commit check are case-sensitive and reject other forms.
   - ``scope`` is optional, and indicates the area of the codebase affected by the change, e.g. ``feat(sel): ...``
   - ``subject`` is a short description of the change
   - Add a body, separated from the subject by a blank line, if the change needs a longer explanation

   Examples: ``feat: my new feature``, ``fix(openplc): handle missing plugin status``, ``docs: fix broken links in the operate guide``.

   The available types include:

   - ``feat``: A new feature
   - ``fix`` or ``bug``: A bug fix
   - ``docs`` or ``doc``: Documentation changes
   - ``style``: Changes that do not affect the meaning of the code (white-space, formatting, missing semi-colons, etc.)
   - ``refactor``: A code change that neither fixes a bug nor adds a feature
   - ``perf``: A code change that improves performance
   - ``test`` or ``tests``: Adding missing tests or correcting existing tests
   - ``build``: Changes that affect the build system or external dependencies (example scopes: minimega, discovery)
   - ``ci``: Changes to our CI configuration files and scripts (example scopes: GitLab, GitHub)
   - ``chore``: Other changes that don't modify source or test files
   - ``revert``: Reverts a previous commit
   - ``deps`` or ``dependencies``: Changes that update dependencies
   - ``sec`` or ``security``: Changes that impact security of the system
   - ``deprecate``: Changes that deprecate some feature
   - ``minor`` or ``patch``: Accepted by the tooling, but prefer one of the more specific types above

   All contributions (code, comments, documentation, and commit messages) MUST be in English.

#. **Lint and format**

   The command ``pdm run format`` will automatically format your code, and ``pdm run lint`` will run quality checks.

#. **Document changes**

   If your change introduces new features or changes existing functionality, please update (or create) documentation in ``docs/``.
   It's difficult to keep documentation up-to-date, so there is an emphasis on ensuring that revisions and especially new functionality are well documented. The documentation builds with warnings treated as errors; see https://sandialabs.github.io/PEAT/contributing/documentation.html for how to build and check it locally.

#. **Update the CHANGELOG**

   PEAT uses `Towncrier <https://towncrier.readthedocs.io/en/stable/>`_ to manage changelog entries. Towncrier provides several benefits:

   - **Automated changelog generation**: No need to manually edit CHANGELOG.rst
   - **Avoids merge conflicts**: Multiple contributors can add their own fragment files without conflicting with each other
   - **Consistent formatting**: All entries follow the same structure
   - **Easy contribution tracking**: Each change is linked to its Pull Request or Issue
   - **Pre-commit validation**: Ensures fragments are properly formatted before commit
   - **Flexible configuration**: Fragment types can be customized in ``pyproject.toml``

   Instead of manually editing CHANGELOG.rst, you need to create at least one "news fragment" file in the ``newsfragments/`` directory.
   You can create these files manually or use ``pdm run towncrier create``. *Note that you must provide the Pull Request number
   when towncrier asks for an issue number in the prompt.* You can skip the prompt by running something like ``pdm run towncrier create 1234.feature``.

   **News Fragment Format:**

   - Filename: ``<PR_NUMBER>.<TYPE>``
   - Where ``<PR_NUMBER>`` is your Pull Request number
   - Where ``<TYPE>`` is one of: ``feature``, ``bugfix``, ``doc``, ``removal``, or ``misc``

   **Example:** ``newsfragments/1234.feature`` (no file extension, as configured by ``create_add_extension`` in ``pyproject.toml``)

   **Valid Fragment Types:**

   - ``feature``: New features
   - ``bugfix``: Bug fixes
   - ``doc``: Documentation improvements
   - ``removal``: Deprecations and removals
   - ``misc``: Miscellaneous changes (content not shown in final changelog)

   **Content:** The file should contain a brief description of your change in reStructuredText format.

   **Note:** These fragment types are configured in ``pyproject.toml`` under the ``[tool.towncrier]`` section. The configuration can be customized to add, remove, or modify fragment types as needed.

   **Example content:**

   .. code-block:: rst

      Added support for new device protocol XYZ.

      This includes parsing of device configuration and status information.

   **Pre-commit and CI Validation:**

   The pre-commit hooks run ``towncrier check`` when you add or modify files in the ``newsfragments/`` directory, which verifies that the fragments are recognized by Towncrier. CI additionally requires every pull request to add at least one fragment named after the PR number, and verifies that the changelog can be built from the accumulated fragments.

   **Release Process:**

   When a maintainer runs the Release workflow (see https://sandialabs.github.io/PEAT/contributing/releases.html), GitHub Actions builds the changelog from all accumulated news fragments and commits the updated ``CHANGELOG.rst`` before creating the release tag.

   **Manual Changelog Building (Optional):**

   If you want to preview the changelog before release, you can use:

   .. code-block:: bash

      # Preview what the changelog will look like for version X.Y.Z
      pdm run towncrier build --draft --version X.Y.Z

      # Or use the convenience script
      ./scripts/build_changelog.sh X.Y.Z

      # This shows the changes but doesn't commit them

#. **Test**

   When adding a new feature, add tests for that feature, and when changing existing code, ensure tests are updated to cover the changes made (e.g. if there are new edge cases or code paths).

   Ensure tests pass. Run ``pdm run test`` and ``pdm run test-full`` to run most of the tests. Running the tests locally *before* submitting a pull request helps catch problems early. See https://sandialabs.github.io/PEAT/contributing/testing.html.

#. **Squash and rebase**

   Ensure all changes are squashed into one or several well-formed commits, and rebase onto the upstream ``main`` branch to keep the history linear. Resolve any conflicts that arise during the rebase.

   .. code-block:: bash

      git fetch upstream
      git rebase upstream/main

      # (Optional) squash multiple commits into one. In the editor, change "pick"
      # to "squash" (or "s") for every commit after the first, then write a single
      # commit message that summarizes all of the changes.
      git rebase -i upstream/main

      # A rebase rewrites history, so a force push to your fork is required
      git push --force-with-lease origin <branch-name>

#. **Submit a Pull Request (PR) to the main branch**

   Open the pull request against the ``main`` branch of `sandialabs/PEAT <https://github.com/sandialabs/PEAT/pulls>`__. Follow the template provided when opening a request and complete all sections, and reference any related issues (e.g. ``Closes #123``).

   The PR title MUST follow the same Conventional Commits format as commit messages (**lowercase** ``type``, optional scope, short subject), e.g. ``docs: fix broken links in the operate guide``. PRs are usually squash-merged, so the PR title becomes the commit message on ``main``.

   If your code is not ready to merge, but you want to get feedback, please open the PR as a "Draft". This enables discussion of the changes, and also raises awareness for others who may be working on the same or similar feature. When the PR is ready to merge, remove the "Draft" marking.

#. **Wait for review**

   When a pull request is made, a reviewer will assess the code and write comments on your PR. All pull requests must be approved by at least one maintainer. If you know which maintainers would best understand your contribution, request their review using "Reviewers" on the right side of the PR page. Due to project restrictions, you may not be able to request specific reviewers via the UI, in which case mention them in a comment, e.g. ``@username1 @username2 Requesting review on this PR because you are SMEs on Device X``.

   Every single developer working on the project has their code reviewed, and we've come to see it as friendly conversation from which we all learn and the overall code quality benefits. Therefore, please don't let the review discourage you from contributing: its only aim is to improve the quality of the project, not to criticize. Once the code has been reviewed and all comments have been addressed, the reviewer will authorize the patch.

   After approval, any maintainer may merge (squash or rebase) the PR into ``main``.

#. **Update fork**

   After the PR is merged, you may delete the branch from your fork, and update your fork's ``main`` branch from upstream:

   .. code-block:: bash

      git branch -d <branch-name>
      git push origin --delete <branch-name>

      git checkout main
      git fetch upstream
      git merge upstream/main
      git push origin main


Requirements before merging
---------------------------

#. Your name and any other contributors to the change are in ``AUTHORS``
#. The list of authors in the relevant module-level docstring(s) is updated, including email addresses, so it is clear who to contact about a particular portion of the codebase
#. There is a minimal set of tests for the change (if applicable)
#. The GitHub Actions CI pipeline passes
#. The code has been reviewed by a PEAT maintainer (if the committer is not a PEAT maintainer)


Code of Conduct
---------------

The PEAT community has adopted a Code of Conduct to ensure that we have an open and healthy community. Please review ``CODE_OF_CONDUCT.rst`` (https://sandialabs.github.io/PEAT/code_of_conduct.html) for more information.


PR review guidelines
--------------------

These are guidelines for maintainers reviewing pull requests with changes to PEAT's code.

Maintainers should check all changes for the following:

- PEAT is deployed on sensitive networks with potential consequences on life safety and operation of critical infrastructure. All changes should be viewed through this lens.
- Trustworthiness

  - Check for backdoors, malicious changes, etc., especially from untrusted contributors.
  - Binary or very large files (e.g. test data) should only be accepted from trusted contributors with verified provenance. This is to avoid a ``xz-utils`` type of situation.

- Correctness

  - How the changes fit into the larger codebase. Are they using the correct APIs? For example, if a file is being written, then ``utils.write_file()`` or ``DeviceData.write_file()`` should be utilized in most cases.
  - Are there any issues with the code that you can see?

- Completeness

  - Tests, documentation (including ``examples/peat-config.yaml`` for new options and the supported devices table for new modules), a news fragment, and an ``AUTHORS`` entry.


License
-------

By contributing to this project, you agree that your contributions will be licensed under the `GNU General Public License v3.0 <https://github.com/sandialabs/PEAT/blob/main/LICENSE>`__ that covers the project.
