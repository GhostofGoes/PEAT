*********************************************
Building a configuration interactively
*********************************************
``peat config-builder`` opens a text-based user interface in the terminal for assembling a
PEAT :doc:`configuration file <configure>` without hand-writing YAML. It is aimed at the
most common need, an inventory of hosts with the module and credentials to use for each,
and produces a file you can use directly with ``-c`` or refine further in an editor.

.. code-block:: bash

   peat config-builder

   # Or from the container (needs an interactive terminal: -it)
   docker run --rm -it -v "$(pwd):/work" -w /work ghcr.io/sandialabs/peat config-builder

.. only:: html

   .. figure:: /images/terminal/config_builder.svg
      :alt: The config-builder text user interface in a terminal: two hosts added (relay-7 at 192.0.2.10 using the SEL3620 module and plc-3 at 192.0.2.20 using SELRTAC), each with Add Pull Method and Delete Host buttons; below them the Add Host button with IP, Name and Module fields, an output file name field, and a footer with the d, v and s key bindings
      :figclass: peat-terminal

      The builder with two hosts added. Keys: :kbd:`v` previews the YAML, :kbd:`s` saves it.

Using the builder
=================
The interface is built with `Textual <https://textual.textualize.io/>`__ and works with
the keyboard and the mouse in any modern terminal.

1. **Add hosts.** Enter a host's IP address and a name, pick the PEAT module to use for it
   from the module list, and press *Add Host*. Repeat for each device. A host can be
   removed with its *Delete Host* button.
2. **Add pull methods and credentials.** For each host, *Add Pull Method* adds a protocol
   entry; choose the protocol (the module's supported ``pull_methods``) and fill in the
   username, password, and port. The placeholders show the module's defaults.
3. **Preview.** Press :kbd:`v` to view the generated YAML; :kbd:`Esc` closes the preview.
4. **Save.** Type an output file name in the field at the bottom (``peat_config.yaml`` in
   the current directory if left empty) and press :kbd:`s`.

Other keys: :kbd:`d` toggles dark mode; :kbd:`Ctrl+Q` (Textual's default) quits.

What it generates
=================
The output is a "simple" configuration: the ``metadata`` block, sensible general options
(debug level, timeouts, thread count, host online checks), and a ``hosts`` list with an
entry per host:

.. code-block:: yaml

   hosts:
     - label: "feeder-7"
       identifiers:
         ip: "192.0.2.23"
       peat_module: "SELRelay"
       options:
         ftp:
           user: "FTPUSER"
           pass: "TAIL"
           port: 21

Use it with any command, or as the ``hosts`` inventory for ``peat pull --skip-scan``:

.. code-block:: bash

   peat pull -c peat_config.yaml -i 192.0.2.0/24
   peat pull --skip-scan -c peat_config.yaml

Limitations
===========
- The builder covers hosts, modules, and per-protocol credentials. Module-specific options
  (for example which SEL directories to skip, or Elasticsearch settings) are added by
  editing the file afterwards; the :ref:`reference configuration <peat-config>` documents
  them all.
- Default options are read from the module's ``default_options``; protocols a module
  doesn't define defaults for show empty placeholders.
- Passwords are saved in plain text. Protect the file (see :doc:`encryption`).

The builder's Python API (:func:`~peat.api.config_builder_api.generate_simple_config`,
:func:`~peat.api.config_builder_api.generate_full_config`) can be used to generate
configuration files programmatically; see :doc:`/developer/python_examples`.
