# Curated AuraScan Fixture Pack

These fixtures exercise realistic AUR/package supply-chain scenarios without
running package code, contacting the network, installing packages, or invoking
real makepkg.

Each scenario contains an `expected.json` manifest. Static and wrapper
scenarios include a `PKGBUILD` at the scenario root. History scenarios contain
`previous/PKGBUILD` and `current/PKGBUILD`, with optional `.INSTALL` files.

Fixtures must stay defanged:

- Use `example.invalid` for URLs.
- Use fake private paths only as detection strings.
- Do not include destructive commands.
- Do not include real attacker infrastructure.
- Do not rely on live AUR, root, network, or real package execution.

Eval, systemd, and cron fixtures are text-only static-detection cases. They may
include defanged build/install-hook snippets that look like commands, but tests
must only scan those files as text. Do not run makepkg or execute the fixture
package functions. Systemd unit-file packaging fixtures should stay separate
from auto-enable/start fixtures so AuraScan can keep ordinary service-file
packaging lower severity than persistence behavior.
