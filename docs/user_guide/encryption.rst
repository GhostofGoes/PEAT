*******************************************
Encrypting configuration files and results
*******************************************
Two things PEAT handles routinely are sensitive: **configuration files**, which often hold
device credentials, and **results**, which contain device configurations (often with
credentials of their own), network layouts, and process logic. PEAT can encrypt both with
a password so they can be stored and transported more safely.

.. warning::
   PEAT does **not** store or recover passwords. If the password for an encrypted
   configuration or archive is lost, the contents cannot be recovered.

Encrypting a configuration file
===============================
``peat encrypt-config`` encrypts a YAML configuration file. The encrypted
copy is written to the same directory as the original, with ``encrypted_`` prepended to
the file name. The original is left untouched, so delete it (securely) once you've
confirmed the encrypted copy works.

.. code-block:: bash

   # Prompts for a password
   peat encrypt-config -f ./site.yaml
   # -> ./encrypted_site.yaml

   # Password on the command line (visible in shell history and process lists)
   peat encrypt-config -f ./site.yaml -p 'correct horse battery staple'

Encrypted configuration files are used **directly** with ``-c``; PEAT recognizes them by
their header and prompts for the password at start-up:

.. code-block:: console

   $ peat pull -c ./encrypted_site.yaml -d selrelay -i 192.0.2.0/24
   Enter a password:

To get the plain text back, decrypt it. The decrypted file is written to the current
directory (or the directory given with ``-w``) as ``decrypted_config.yaml``:

.. code-block:: bash

   peat decrypt-config -f ./encrypted_site.yaml
   peat decrypt-config -f ./encrypted_site.yaml -w ./restored/ -p 'correct horse battery staple'

The legacy aliases ``peat encrypt`` and ``peat decrypt`` still work.

How it works: the file is encrypted with `Fernet <https://cryptography.io/en/latest/fernet/>`__
(AES-128-CBC with HMAC-SHA256) using a key derived from the password with PBKDF2-HMAC-SHA256,
and prefixed with a ``PEAT_CRYPT`` marker so PEAT can recognize encrypted files.
Implementation: :mod:`peat.config_crypto`.

An example pair of files is in the repository: ``examples/encryption/example_config.yaml``
and its encrypted form ``examples/encryption/encrypted_config.yaml``.

Encrypting results
==================
``peat encrypt-results`` packs a run directory into a password-protected zip archive. Use
it when results need to leave the system they were collected on: emailed to an analyst,
carried out of a facility, or archived.

.. code-block:: bash

   # Encrypt a run directory; the archive is written to the current directory
   peat encrypt-results -f ./peat_results/site-a
   # -> ./encrypted_site-a.zip

   # Choose the output directory and give the password on the command line
   peat encrypt-results -f ./peat_results/site-a -w ./to-transfer/ -p 'correct horse battery staple'

The archive is a standard zip file with AES encryption (WinZip AES, via
`pyzipper <https://github.com/danifus/pyzipper>`__), so it can also be opened by 7-Zip,
WinZip, and other tools that support AES-encrypted zips, not only by PEAT. Note that
entry names are not encrypted.

Decrypting results
==================
``peat decrypt-results`` restores the directory, by default into the current working
directory under the run directory's original name:

.. code-block:: bash

   peat decrypt-results -f ./encrypted_site-a.zip
   peat decrypt-results -f ./encrypted_site-a.zip -w ./restored_results/ -p 'correct horse battery staple'

An example archive is in the repository, ``examples/encryption/encrypted_example_peat_results.zip``,
created from the minimal results directory ``examples/encryption/example_peat_results/``.

Handling passwords
==================
- Prefer the interactive prompt over ``-p``. Passwords given with ``-p`` end up in shell
  history and are visible to other users of the system while PEAT runs.
- In automation, pass the password through an environment variable or a secrets manager
  and feed it to the prompt, rather than hard-coding it in scripts.
- Use a strong passphrase. The key derivation is deliberately slow, but a weak password is
  still the weakest link.

Examples
========
.. literalinclude:: ../../peat/cli_args.py
   :language: bash
   :start-after: encrypt_config_examples = """
   :end-before: """  # End encrypt-config examples

.. literalinclude:: ../../peat/cli_args.py
   :language: bash
   :start-after: decrypt_config_examples = """
   :end-before: """  # End decrypt-config examples

.. literalinclude:: ../../peat/cli_args.py
   :language: bash
   :start-after: encrypt_results_examples = """
   :end-before: """  # End encrypt-results examples

.. literalinclude:: ../../peat/cli_args.py
   :language: bash
   :start-after: decrypt_results_examples = """
   :end-before: """  # End decrypt-results examples
