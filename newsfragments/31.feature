Add ``scripts/check_module.py`` (``pdm run check-modules``), which checks that device modules correctly implement the module API and suggests improvements for older modules (issue #47).
It finds problems such as attributes with the wrong types, methods PEAT can't call or never uses, broken identification methods, duplicate filename patterns and aliases, invalid ``annotate_fields``, and modules that aren't registered, and can parse a real file with a module to check the results.
It runs as part of ``pdm run lint``. Refer to "Checking a module" in the module developer guide.
