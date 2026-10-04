Add a file signature capability.
With this, a module can define a :class:`~peat.file_signature.FileSignature` object with a default
filename (to use for a data stream) and various signatures (magic bytes, xml tags, substrings, or
some custom logic) that it associates to a file it processes/supports.
When a data stream is processed, if the FileSignature object matches (i.e., all the defined
signatures match), the file is determined to be identified and named as provided in the signature
object instead of giving the default ``raw-unparsed-data`` filename value.
Additionally, this updates the parse API logic to test files passed to it against signatures (where
previously it only tested filename patterns).
Any file which matches on a filename pattern or a file signature will now be identified as able
to be parsed, and passed to the module for processing.

Notable, the :attr:`peat.device.DeviceModule.filename_patterns` logic has not been removed to
maintain existing behavior as the default.
So, this alternate path will only trigger if no other data stream naming/identification logic
succeeds and signatures are defined.
