# AuraScan security boundaries

Status: maintained reference. This document records where untrusted input meets
authority, and what each boundary is allowed to do. It complements
[`ARCHITECTURE.md`](ARCHITECTURE.md), which records structure, and
[`../AGENTS.md`](../AGENTS.md), which is the binding contract.

Two statements apply to every boundary below.

- **A boundary is risk reduction, not a sandbox.** Same-UID malware can attack
  user configuration, cache and state. Root malware can replace AuraScan or the
  system tools it invokes. Native parser defects, DNS rebinding, steganography
  and unknown decoders remain possible.
- **A passing test does not make a boundary safe.** Tests demonstrate that a
  specific check behaves as designed. They do not prove that the check is
  sufficient, that untrusted content is benign, or that nothing executed.

## Boundary inventory

### 1. Package control text — PKGBUILD and declared install hooks

| Aspect | Detail |
| --- | --- |
| Trusted side | AuraScan policy, the rule catalog, captured evidence |
| Untrusted side | PKGBUILD text, `source=()` arrays, `.install` hooks, `.SRCINFO` |
| Validation | Bounded parse and literal-only source-array collection; malformed arrays, subscripts, namerefs, `source`/`eval` and dynamic mutation fail closed |
| Allowed authority | Produce findings; block a handoff; require review |
| Prohibited | Executing the file, `source`-ing it, evaluating shell, treating a match as proof of execution |
| Evidence | Findings cite captured text and coverage; no raw script bodies in persisted output |

`install=` targets are mandatory evidence: a missing, unreadable, symlinked,
ambiguous or unsafe declared hook fails closed. An unresolved hook never reuses
or creates an allow decision.

### 2. Acquired source — explicit `--deep-static` only

| Aspect | Detail |
| --- | --- |
| Trusted side | Acquisition transport, snapshot identity, policy |
| Untrusted side | Downloaded archives, upstream source trees, nested archives |
| Validation | Credentials, `localhost` and non-public IP literals rejected pre- and post-redirect; local sources snapshotted with no-follow reads; per-source path isolation; bounded entries and bytes |
| Allowed authority | Raise findings from acquired bytes; block uninspected declarations |
| Prohibited | Network access under `--offline`; cache reuse before acquired identities are bound; recursing without inspecting nested archives |
| Evidence | Acquisition metadata is redacted of URL userinfo, query and fragment; "not inspected" is coverage, not innocence |

A clean deep-static result never establishes that the package is safe, and the
lexical URL check does not eliminate DNS rebinding.

### 3. Built package archives — `.INSTALL` capture

| Aspect | Detail |
| --- | --- |
| Trusted side | AuraScan's bounded archive reader |
| Untrusted side | Package archive members, `.INSTALL` control text |
| Validation | No-follow reads; bounded member enumeration and bytes; stable regular UTF-8 text required |
| Allowed authority | Block on an unreadable, changing, oversized, binary or invalid hook |
| Prohibited | Executing the hook; relying on ClamAV or AI as the only install-hook check |
| Evidence | Incomplete capture is reported as incomplete coverage, never as "no hook" |

### 4. Agent-control and instruction files

| Aspect | Detail |
| --- | --- |
| Trusted side | Instruction Guard discovery, integrity manifests, private report state |
| Untrusted side | `AGENTS.md`, `SKILL.md`, Claude control files, Cursor rules, MCP and approval settings, CodeWhale/DeepSeek project TOML, discovered skill resources |
| Validation | Bounded no-follow reads under an explicit root; symlink directories never traversed; imports that escape the root are reported, not followed; credential targets and variable expansion refused |
| Allowed authority | Report content risk, integrity change and coverage; request review; offer a confirmed disable for an unchanged standalone regular instruction file |
| Prohibited | Executing, sourcing, rendering or importing file content; starting an MCP server; auto-quarantining; copying source snippets into notifications or AI requests |
| Evidence | Deterministic one-based line ranges plus fixed reasons; behavior role attributed per range; no source text in alerts or AI input |

Content risk, integrity approval, scan coverage and neutral first-seen baseline
enrollment are four distinct states and must never be collapsed into one badge.

### 5. Model input and output (package AI, instruction AI, upgrade AI)

| Aspect | Detail |
| --- | --- |
| Trusted side | Deterministic findings, allowlisted schema, user consent |
| Untrusted side | Provider responses; untrusted artifact text embedded in prompts |
| Validation | Strict duplicate-key-rejecting JSON, exact schema, known IDs, bounded prose; refused redirects; proxies disabled; loopback-only for local providers |
| Allowed authority | Raise severity on an existing deterministic finding; add explanatory prose |
| Prohibited | Lowering or clearing a deterministic result; founding trust; requesting or gaining tools, URLs, commands or permissions; raw model output retention |
| Evidence | Only accepted, bounded, secret-free fields persist; rejected raw responses and errors are discarded |

AI is opt-in per surface, needs its own key for cloud providers, and never falls
back from a failed local provider to cloud inference.

### 6. Native tools over hostile data

| Aspect | Detail |
| --- | --- |
| Trusted side | `core/trusted_executable.py` and `core/trusted_tools.py` |
| Untrusted side | The bytes handed to `git`, `gpg`, `bsdtar`, `clamscan`, `makepkg`, upgrade helpers |
| Validation | Absolute non-symlink path, root-owned non-writable components and file, identity revalidated immediately before use (see `ARCHITECTURE.md`) |
| Allowed authority | Read-only inspection within bounded input, output and runtime |
| Prohibited | Replacing the validated executable with a bare name later; unbounded expansion; treating a timed-out or errored scan as clean |
| Evidence | Timeout, bound exceeded or error is recorded as incomplete inspection |

The post-scan `makepkg` handoff executes package build logic. It is not a
bounded scanner and not a sandbox; it is a deliberate, consented handoff after
revalidation.

### 7. Privileged repair and recovery actions

| Aspect | Detail |
| --- | --- |
| Trusted side | Deterministic repair catalog, fresh consent, trusted `sudo`/`pacman` identity |
| Untrusted side | Host state, package metadata, mirror configuration, diagnostic output |
| Validation | Fresh just-in-time confirmation per exact command; fail-closed allowlist; revalidated executable identity before each call |
| Allowed authority | Documented read-only diagnostics, constrained `pacman` query/sync/removal workflows |
| Prohibited | Remote references, VCS/AUR/build tools, interpreters, decoding, expansion, redirection, arbitrary executables; describing the boundary as unrestricted execution |
| Evidence | Approved package changes remain consequential; diagnostic output may contain private data |

During a recovery build, QEMU harnesses run only through the root preflight
bootstrap and the private build attestation, from a fresh root-owned
non-writable checkout.

### 8. Intelligence updates and detection data

| Aspect | Detail |
| --- | --- |
| Trusted side | Packaged fingerprints, bounded GnuPG verification, atomic install |
| Untrusted side | Downloaded feed bytes, mirror metadata, tray status |
| Validation | Unprivileged download separated from network-isolated privileged verification; rollback, unsupported schemas, expired activation and changed same-sequence content rejected |
| Allowed authority | Update detection data inside the validated contract |
| Prohibited | Fetching or enabling from package scripts; letting tray controls download or render raw child output; live keys in tests |
| Evidence | One captured snapshot per operation, bound into reports, caches, history and review acceptance |

### 9. Filesystem repository provenance

| Aspect | Detail |
| --- | --- |
| Trusted side | `core/repository_provenance.py` bounded walk |
| Untrusted side | Files beside the PKGBUILD, generated `src`/`pkg` trees, archives, executables |
| Validation | Always-on, local, no-follow, no Git or native-tool invocation; VCS internals and named cache directories pruned; statically resolved control paths captured through pruned trees; ambiguity fails closed |
| Allowed authority | MEDIUM presence notice, HIGH exact-install, CRITICAL exact-execution or SUID/SGID, manual review |
| Prohibited | Claiming Git-tracked, AUR-distributed, installed or executed status from presence; copying artifact bytes into explanations |
| Evidence | Sanitized path, deterministic control line and short artifact hash prefix only |

### 10. User configuration and private state

| Aspect | Detail |
| --- | --- |
| Trusted side | Ownership checks, mode checks, the validated private state lock |
| Untrusted side | Config file contents, restored backups, prior reports |
| Validation | Owner and mode validated; state mutations serialized; interrupted transactions stay fail-closed until a complete scan revalidates every recorded target |
| Allowed authority | Read configuration; write bounded private state; prune retention-limited reports |
| Prohibited | Pruning manifest trust/review state; leaving a queued AI job pointing at a deleted report; silently invalidating user state |
| Evidence | Approvals are machine-and-UID bound; a rebuilt host cannot restore them |

## Prohibited capability combinations

The audit tool enforces the mechanically checkable subset (see
`ARCHITECTURE.md`). The following combinations must never appear, whether or not
a test currently catches them:

- an analyzer that executes a process;
- a pure domain or catalog module that performs I/O;
- deterministic policy that depends on an AI provider module;
- evaluation, deserialization or unpickling of untrusted bytes;
- disabled TLS verification anywhere on a network path;
- process execution with `shell=True`;
- a rule identifier decided by a UI entry point;
- any import from the production package into research tooling or the reverse;
- a third-party runtime dependency outside the declared optional extras.

## Reporting rules

Findings and explanations must state what was inspected, what was skipped, and
what the evidence cannot prove. In particular:

- a static match does not show that code ran;
- a clean scan does not show that a package is safe;
- a signature or checksum does not show that behavior is benign;
- "not detected" is not "safe", "clean", "trusted" or "approved";
- incomplete inspection is a coverage result, never an all-clear.
