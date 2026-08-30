# AuraScan Unreleased

Changes after v0.9.2 will be recorded here.

- Policy-Gated Repair Agent now enforces fresh confirmation for every exact
  model-authored diagnostic or package-repair command. Legacy `whole-plan` and
  `session` settings remain readable but normalize to `each-command` at
  configuration and runtime. Its fail-closed allowlist accepts only documented
  shell output/test builtins, absolute `/usr/bin` or `/usr/sbin` read-only
  diagnostics, and constrained exact `/usr/bin/pacman` query/sync/removal
  workflows. Remote references, network/Git/AUR/build/interpreter/decode/eval
  paths, mutating diagnostic flags, expansion/redirection, custom executables,
  unsafe pacman operations, and direct AuraScan modification are rejected
  before confirmation. Root repair uses the new
  `GRANT AI ROOT REPAIR COMMANDS` phrase, and privileged calls revalidate
  package-managed sudo and AuraScan executables.
- Upgrade preflight now binds pacman, sudo, and supported AUR-helper queries to
  trusted root-owned absolute executable identities and revalidates them before
  every query and final handoff. Unsafe paths, symlinks, permission changes,
  and executable replacement fail closed.
- Planned AUR source builds now raise blocking
  `UPG-AUR-BUILD-UNSCANNED`. AuraScan uses repository-only pacman when a helper
  reports no AUR builds; otherwise it requires users to inspect/build through
  `aurascan-makepkg` instead of handing the build to an unverified helper. AI
  and `--yes` cannot override this deterministic blocker.
- Package-scanner rule version `1.4.0` adds CRITICAL, artifact-bound detection
  for remote download/clone followed by execution in PKGBUILD, declared install
  hooks, built package `.INSTALL` control text, and acquired source. Incomplete
  command correlation and built-package hook inspection are HIGH blockers
  rather than malware claims. New opaque-carrier rules also correlate local
  decode-to-artifact then execution, or active invocation of a
  media/document/data/font-named artifact as code, without flagging assets or
  file extensions alone.
- Built-package identity now uses bounded, no-follow `.PKGINFO` capture through
  an already-opened trusted `/usr/bin/bsdtar` and rejects links, replacement,
  invalid text, or oversized output without printing or persisting hostile
  bytes. Package archive cache reuse is disabled until every analyzer can share
  one immutable snapshot and digest.
- Explicit deep-static acquisition now parses the captured PKGBUILD, refuses
  every source/key network request under `--offline`, snapshots local sources
  without following links, isolates source destinations, blocks incomplete
  acquisition, and avoids stale cache reuse. Initial/final source URLs reject
  embedded credentials, localhost, and non-public IP literals; persisted URL
  metadata removes credentials, queries, and fragments.
- PKGBUILD source parsing now fails closed on malformed/dynamic/indirect source
  mutations, including namerefs, rather than evaluating Bash. Explicit Git and
  signature work use captured and revalidated `/usr/bin/git` and
  `/usr/bin/gpg`. Public keys are read as stable bounded byte snapshots; the
  private cache publishes fetched keys atomically without replacement, and GPG
  imports an exact temporary copy instead of reopening a mutable key path.
- Archive and acquired-source inspection now bind stable no-follow snapshots,
  stream bounded enumeration, enforce actual extracted byte/entry and source
  traversal/candidate limits, clean partial output transactionally, and block
  links, nested archives not recursively inspected, or any incomplete
  inspection. Images, fonts, media, and opaque blobs remain inert bytes and are
  never rendered or sent to a multimodal model.
- Package AI now receives only bounded numbered JSON data and returns a strict
  raise-only allowlist referencing supplied lines. Config-drift, incident, and
  recovery AI also use exact bounded schemas, known IDs, and bounded one-line
  interpretation. Their shared text guard now rejects recognized bare or
  obfuscated network destinations, indirect/modal action requests,
  sentence-leading imperatives, named or generic package-manager/install-helper
  advice, actionable nominalized operation/invocation wording,
  credential-copy/share language, and questions in addition to commands,
  controls, product impersonation, and unsupported trust/compromise claims.
  Rejected raw output and provider errors become fixed secret-free explanations.
  Accepted model prose remains untrusted interpretation without tool, URL,
  command, policy, or execution authority; lexical filtering is not presented
  as proof that arbitrary language is safe.
- Upgrade AI may now only raise the severity, up to HIGH, of an existing
  deterministic rule ID. It cannot create a standalone finding/action or
  change blocking policy.
- Cloud and local provider transports refuse redirects; Gemini credentials are
  sent in a header, and plain-HTTP `localhost` local endpoints normalize to
  `127.0.0.1`. Terminal presentation strips ANSI/OSC, bidi, invisible controls,
  and forged AuraScan labels from untrusted package and finding metadata.
- ClamAV and database-version checks use captured/revalidated
  `/usr/bin/clamscan` and `/usr/bin/freshclam`, a minimal environment, an option
  terminator before untrusted paths, bounded scan/process output, and no raw
  tool output in findings. An invoked scan that does not complete now blocks as
  incomplete instead of being treated as clean. Instruction Guard notifications similarly require
  trusted `/usr/bin/notify-send`, and `aurascan-makepkg` captures and
  revalidates `/usr/bin/makepkg` before handoff.
- Explicit Git/GPG acquisition now bounds combined child output as well as
  runtime. Persisted GPG status drops user IDs and diagnostics, retaining only
  allowlisted status names and hexadecimal key identifiers.
- Documentation now makes the residual boundary explicit: fixed tool identities
  and bounded parsing are not a native-parser sandbox; same-UID/root attackers,
  parser defects, DNS rebinding, steganography/unknown decoders, and the
  network/disk exposure of explicit acquisition remain out of proof.
