************
Dependencies
************
The Python packages PEAT depends on, with their licenses and descriptions. The table is
generated at documentation build time (``pdm run dep-doc``, using
`pip-licenses <https://github.com/raimon49/pip-licenses>`__) from the packages installed
in the documentation build environment, which contains PEAT's runtime dependencies and the
documentation tooling. The exact versions PEAT is tested and released with are pinned in
``pdm.lock`` in the repository; ``pyproject.toml`` documents why each runtime dependency
is needed and which modules use it.

.. note::
   The documentation environment overrides one runtime pin: it installs a newer
   ``requests`` (and ``urllib3`` 2.x) than PEAT itself uses, because recent Sphinx
   releases require it. See :doc:`/contributing/documentation`.

.. include:: dependencies_table.rst
