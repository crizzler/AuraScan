The carrier.pyc.fixture file consists only of a recognized 16-byte CPython
3.11 header (magic 3495, flags 1, fake source hash FAKEHASH) followed by the
ASCII sentinel AURASCAN_INERT_BYTECODE_SENTINEL. It is deliberately not a
marshaled code object. No scanner or test may load or execute it.

The extra .fixture suffix prevents ordinary Python tooling from treating the
file as an import cache. The repository scanner recognizes its bounded header
without depending on its name. Separate temporary-root tests cover ordinary
non-executable .pyc/.pyo/.pyd names and __pycache__ beside benign Python source.

Presence and unchecked hash mode require review; neither proves malicious
behavior or runtime reachability. This fixture has no code execution command.
