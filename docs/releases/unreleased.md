# AuraScan Unreleased

Changes after v0.10.1 will be recorded here.

## AUR Repository Artifact Provenance

- This generic provenance control responds to the package-inspectability issue
  discussed in the [31 August 2026 aur-general report about packages shipping
  precompiled binaries](https://lists.archlinux.org/archives/list/aur-general%40lists.archlinux.org/thread/HI6AJSU7LMGWOELAI2JUABEMNVHPGBAG/).
  The report explicitly did not allege that the named packages were malicious;
  these findings likewise describe observable provenance and static use, not a
  confirmed compromise.
- Added an always-on, bounded, no-follow scan of regular files present beside
  the PKGBUILD. The scan runs before source acquisition and allow decisions,
  and performs no network request, native-tool invocation, archive extraction,
  or package-code execution. Its normal walk prunes VCS internals, named
  cache/dependency directories, and generated root `src/` and `pkg/` trees;
  statically resolved control paths through otherwise pruned trees are captured
  separately with the same bounds, and ambiguity fails closed.
- Supported ELF, PE, Mach-O, and opaque archive magic is classified from
  bounded stable bytes. Exact literal files declared through supported
  `source=()` forms remain represented in the snapshot and under the normal
  source-provenance workflow, but are excluded from repository-embedded-
  artifact classification. Uncorrelated generated output is presence-
  suppressed; an exact active use can still elevate it.
- Added a four-step evidence policy: MEDIUM non-hard-blocking,
  acceptance-eligible manual review through
  `AUR-REPO-OPAQUE-ARTIFACT-001`; HIGH manual review through
  `AUR-REPO-OPAQUE-BINARY-001` when the exact artifact is copied, moved, or
  installed into `$pkgdir`; CRITICAL blocking through
  `AUR-REPO-OPAQUE-BINARY-EXEC-001` when the exact artifact or installed
  destination is invoked/code-loaded or receives SUID/SGID permissions; and
  HIGH fail-closed coverage through
  `AUR-REPO-INSPECTION-INCOMPLETE-001` when bounded traversal or stable capture
  cannot complete.
- Repository snapshot identity participates in cache, wrapper revalidation,
  review, history, and trust decisions so an unchanged PKGBUILD cannot hide a
  binary-only replacement between scans or before makepkg handoff.
- The makepkg wrapper now performs a final full-input recapture, rejects options
  that substitute/reuse unscanned inputs or skip integrity verification, and
  removes direct shell/dynamic-loader code-loading variables from the handoff
  environment.
- Verbose local terminal review identifies the sanitized control file and
  one-based line (or the observed path for a presence finding) together with a
  12-character artifact SHA-256 prefix. It does not reproduce artifact bytes or
  matched command text, and the locator is not an execution claim.

## Evidence Limits

- “Repository” describes the bounded filesystem tree beside the PKGBUILD.
  AuraScan does not invoke Git and does not claim that an observed artifact was
  committed, distributed by the AUR, installed, successfully executed, or
  malicious. Presence alone stays non-blocking because legitimate firmware,
  vendored executables, archives, and test data exist.
- Unsupported, encrypted, nested, polyglot, malformed, or deliberately
  disguised formats, unknown loaders/decoders, and runtime-only path/control
  flow can remain opaque. Pruned trees are not exhaustively inspected; only
  supported exact package-control references override normal pruning. A clear
  result is not a safety guarantee, and detected incomplete traversal or
  correlation blocks as missing coverage rather than evidence of compromise.
