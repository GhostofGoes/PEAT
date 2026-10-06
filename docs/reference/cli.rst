.. NOTE: the sphinx_argparse_cli directive below creates its own section
   headings (one per sub-command) from the argument parser, so this page has no
   manual title; the directive's :title: is the page title. Keep it as the first
   thing in the file so the generated sections are nested correctly and appear
   in the table of contents.

.. _cli-reference:

.. sphinx_argparse_cli::
   :module: peat.cli_args
   :func: build_argument_parser
   :prog: peat
   :title: Command line reference
   :group_title_prefix:

.. seealso::

   :doc:`/user_guide/cli`
      Conventions shared by all commands, and how to select modules and targets

   :doc:`configuration`
      The configuration file options that most arguments correspond to
