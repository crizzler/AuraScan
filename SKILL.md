---
name: develop-aurascan
description: Develop and validate AuraScan scanner rules, maintenance and recovery workflows, and Agent Instruction Guard. Use for changes in the AuraScan repository, including explicitly authorized GitHub/AUR releases.
---

# Develop AuraScan

Use this workflow for changes in the AuraScan repository. First read the
canonical product orientation and repository-wide contract in `AGENTS.md`;
AuraScan's package, maintenance, recovery, instruction-file, and optional AI
features are one defense-in-depth system, but their evidence and authority
boundaries must remain separate.

For Codex with GPT-6 Astra, follow [coding-agent operation](AGENTS.md#coding-agent-operation)
for autonomy, instruction precedence, and bounded parallel work. Preserve user
intent and existing authorization; this skill does not require approval for
routine local fixes. Apply only sections relevant to the task. External release
publication and the product's fresh exact-command consent retain their explicit
requirements regardless of the agent model.

## Establish context

1. Read `AGENTS.md`, `README.md`, the relevant part of `DEVELOPING.md`, and
   nearby tests.
2. Inspect `git status` and preserve unrelated changes.
3. Classify the requested evidence surface before editing:
   - default PKGBUILD or declared install-hook text;
   - bounded filesystem provenance beside a PKGBUILD;
   - opt-in acquired source under deep-static analysis;
   - installed package, bounded pacman history, or helper-cache provenance;
   - injected-root host artifacts; or
   - bounded AI-agent instruction and skill files under an explicit root; or
   - upgrade transaction context; or
   - explicit cloud/local AI provider configuration and transport; or
   - recovery runtime, image construction, boot validation, or release
     disposition.
4. State what the evidence can and cannot prove. Keep static intent, attempted
   behavior, successful execution, and confirmed compromise distinct.

## Route the change

- Add default static rules in `aurascan/analyzers/deterministic.py`.
- Add acquired-source checks in `aurascan/analyzers/deep_static.py`.
- Put shared, secret-free correlations in a small analyzer helper.
- Keep editor-task JSON command semantics separate from shell text, and bind
  inspection to captured bytes. See [editor task and Git identity evidence](DEVELOPING.md#editor-task-and-git-identity-evidence)
  for the bounded Linux subset, execution prerequisites and deferred coverage.
- Preserve source selectors in trust-diff identity; explicit Git acquisition
  must resolve the intended namespace and verify the resulting commit.
- Keep local maintainer-comment history separate from authoritative AUR
  ownership. Changed annotations retain review and normal scanning; missing
  comments, pushes, restoration and adoption requests cannot establish adoption.
- Add exposure and host checks in `aurascan/core/security_audit.py`.
- For independently updated runtime indicators, follow the separate
  [runtime contract](tools/intelligence_repository/SCHEMA.md) and
  [publisher workflow](tools/intelligence_repository/README.md). Keep research
  quarantine separate, rights fail-closed, and corrections explicit. Snapshot
  intelligence once per operation; changed identities invalidate cache/history
  shortcuts and package review acceptance. Preserve unprivileged download,
  offline privileged verification, fixed trust, bounded no-follow transactions,
  and disabled-by-default timers. Production key provisioning, publication and
  installed-system updates remain separate authorized release work.
  Tray controls must stay asynchronous, use fixed unprivileged service clients
  and desktop authorization, and display validated local status. No menu/status
  refresh may download, enable a timer, or render raw child output. Preserve
  shared mutation/quit guards and verify observed state after requests.
- Add bounded agent-control discovery, content correlations, integrity state,
  and disable receipts in `aurascan/core/instruction_guard.py`; add CLI and
  service consent behavior in `aurascan/core/instruction_cli.py`.
- Add provider presets, readiness, URL validation, and transport behavior in
  `aurascan/core/ai_provider.py`; keep workflow consumers on the shared
  `ready` contract instead of checking API-key presence themselves.
- Update `aurascan/core/rule_metadata.py` and
  `aurascan/core/presenter.py` for every user-visible MEDIUM+ rule.
- Add focused tests beside the affected subsystem and a defanged curated
  fixture when normal fast/wrapper coverage should retain the behavior.
- For security-corpus or model-evaluation groundwork, follow
  [security model research](docs/SECURITY_MODEL_RND.md) and the separate
  [metadata contract](security-data/README.md); reuse existing injected
  analyzer/provider/test interfaces before introducing runtime abstractions.
- Use [developer intake](docs/SECURITY_DATA_INTAKE.md) for explicitly selected
  public source/fixture capture. Acquisition, candidate admission and review are
  separate operations; reviewed candidates remain quarantined and ineligible.
  Preserve exact content/revision and package-family lineage, unknown rights,
  and the distinction between scanner assessments and established labels.
- Update `README.md`, `DEVELOPING.md`, and
  `docs/releases/unreleased.md` when capabilities or contributor contracts
  change.

## Retain research evidence

When work produces a reusable finding, bypass attempt, false positive, fix or
model disagreement, consider an explicitly reviewed metadata record. Preserve
source/rights/privacy, real versus synthetic origin, parent/family lineage,
claim scope and expected versus observed outcomes; do not copy private reports
or rejected model prose. Validate manifests with the offline data-contract tool
before admission. Its structural result does not establish rights or safety.
Use explicit schema versions and reviewed migrations. Record generation and
provider provenance; verify separate rights for analysis, redistribution and
commercial training, including explicit provider permission for training on
proprietary outputs. Missing evidence keeps the affected use ineligible.

Keep training separate from evaluation, reserve private holdout lineages outside
the worktree, and record exposure before a fix or regression leaks an evaluation
case. Contamination invalidates the comparison. Model selection needs frozen,
task-specific evidence and independent cases; reduced refusal is a separate
measurement from reasoning, calibration and policy compliance. Research roles
never inherit credentials, release authority or privileged execution. Keep
reserved holdouts inaccessible to training/adversarial-example generators;
establish acceptance thresholds from development baselines before held-out scoring.

## Design threat detection

1. Prefer a behavior chain over a common binary, service, IP range, or package
   capability. Require at least one remote-access anchor before labeling a
   correlation a remote-access backdoor.
2. Keep exact incident indicators separate from generic behavioral rules so
   each finding explains its evidence and expected lifetime.
3. Emit only bounded, secret-free evidence labels. Never expose auth keys, SSH
   public keys, passwords, tokens, or entire suspicious scripts.
4. Add tests for the malicious pattern, legitimate adjacent usage, comments or
   quoted messages, phase-specific behavior, and uncertainty wording.
5. For post-compromise checks, inject the root path, refuse symlinked files,
   bound reads and enumeration, and avoid executing or importing artifacts.
6. Do not flag a routine service such as `tailscaled` alone. Correlate it with
   privileged enrollment, root SSH configuration, persistence, credential
   changes, or anti-forensics.
7. Detect AUR repository propagation only in deterministic PKGBUILD and
   declared install-hook control text. Correlate an AUR Git target, repository
   mutation/staging, and outbound push. Treat enumeration, loops, hidden hook
   names, or SSH credential access as supporting evidence, and do not apply a
   blanket rule to ordinary release tooling found only in deep-static source.
8. Scan the bounded filesystem tree beside each PKGBUILD without following
   links or invoking Git, native identification tools, the network, or package
   code. In the normal walk prune VCS internals, named cache/dependency
   directories, and generated root `src`/`pkg` trees, but capture statically
   resolved required control paths through otherwise pruned trees and fail
   closed on ambiguity or unsafe capture. Recognize supported
   executable/archive magic from stable bytes and exclude exact supported
   literal `source=()` checkout files from artifact classification. Treat
   uncorrelated, non-generated presence as MEDIUM/non-hard-blocking but
   acceptance-eligible for manual review, exact install into `$pkgdir` as
   HIGH/manual review, exact execution/code loading or SUID/SGID installation
   as CRITICAL/blocking, and incomplete inspection as fail-closed missing
   coverage. Never claim filesystem presence proves an artifact was
   Git-tracked, AUR-distributed, malicious, installed, or executed successfully.
9. Detect remote second-stage execution only when static data flow binds an
   active fetch/clone to a local artifact and later execution of that artifact
   or a bounded decoded/copied derivative. Keep unexecuted downloads, source
   arrays, documentation, ordinary picture/media assets, and path mismatches
   negative. Treat a supported local decode-to-file chain followed by exact
   execution, or direct interpreter/executable invocation of a media-,
   document-, or font-named path, as a separate opaque-carrier correlation;
   never infer hidden content from the filename alone.
10. Scan built package `.INSTALL` control text through the bounded no-follow
   archive reader. An unreadable, changing, oversized, binary, or invalid hook
   is an incomplete-inspection blocker, not evidence of compromise.
11. Inspect pnpm-related metadata as bounded data, never by installing or
    invoking dependencies. Match supported decoded fields to concrete path-escape
    components; keep ordinary scoped names and inert metadata negative. Separate
    installed-version advisory exposure from suspicious package metadata and
    disclose unsupported versions or unverified backports. Consult primary
    advisories before defining affected/fixed ranges; a historical report is
    not proof of what Arch currently ships or what a user has installed.
12. Classify precompiled Python artifacts from supported bounded magic/header
    bytes without importing, executing, deserializing, or decompiling them.
    PEP 552 source-hash headers do not authenticate bytecode bodies. Preserve
    the provenance distinction between presence, exact installation, and code
    loading. A `.pyd` filename selects a native-extension candidate; interpret
    PEP 552 only when the captured bytes independently establish that format.

For npm campaign updates, verify original researcher reports and GHSA/OSV
records before editing bundled intelligence. Keep exact observed release tuples,
broader package-advisory scope, and payload evidence hashes distinct. Parse
supported metadata and active install/network arguments without installing
dependencies. Explicit deep-static hashing must cover bounded stable regular
source bytes, including renamed non-code files, and fail closed on missing
coverage. Bind lifecycle entry scripts to their captured package root and
correlate credential access, configuration writes, and network/publication
behavior; ordinary names, comments, and Bun/Node launchers alone are insufficient.
Registry presence or publish-time scanning cannot override deterministic risk.
Hash-match tests substitute synthetic byte signatures. All fixture text stays inert.

## Design instruction-file protection

1. Treat Markdown, JSON, imports, hooks, and skill resources as untrusted data:
   never source, import, render, execute, or traverse symlink directories.
   Parse CodeWhale/legacy DeepSeek project TOML structurally with the bounded
   standard-library subset reader. Keep top-level authority changes distinct
   from quoted examples and table-scoped settings. Exclude the user-global auth
   configs from project detection and reads. Unsupported TOML is coverage.
   Preserve each imported resource's project boundary and literal path across
   continuation and recursive review; never read escaped or credential targets.
   Cursor `.mdc` and legacy rules are instruction text; MCP and approval JSON
   require structural analysis of supported command/grant fields. Reuse bounded
   reads and enrollment, keep disable/restore manual-only, and report unsupported
   configuration as coverage. Never resolve credentials, expand variables or
   launch a configured server to inspect it.
2. Restrict final regular-file targets to the selected root, use no-follow and
   `fstat` validation, detect replacement during reads, and bound enumeration,
   sizes, and elapsed time.
3. Correlate active behavior families and suppress quoted examples, fenced
   documentation, comments, and negated instructions where evidence permits.
   Preserve bounded, one-based physical line ranges for contributing active
   text. Attribute only the behavior role actually present at each range, then
   explain why the roles form a dangerous correlation; never copy the complete
   family set onto every line or expose source snippets.
4. Keep first-seen/change integrity state separate from content severity.
   Describe a clean first-seen file as neutral baseline enrollment with AI
   `not-needed`, never give a zero-finding file a LOW threat badge, and present
   suspicious instructions, scan coverage, integrity changes, and baseline
   setup as distinct states. Put line roles, the fixed deterministic reason,
   and any mapped AI rationale together under the actual finding; disclose
   bounded AI explanation counts, keep malformed configuration in scan
   coverage, and give each state a concrete next step. Wrap output without
   splitting file IDs. Clearly label an incomplete continuation page.
   Machine-and-UID-bound approval cannot be restored onto a rebuilt host.
5. Keep the periodic deterministic service offline and credential-free. AI is
   separately enabled, raise-only, tool-free, strict-JSON, and limited to
   bounded opaque evidence IDs, fixed reasons, behavior labels, and
   deterministic locations. Map advisory rationales to supplied evidence; AI
   cannot invent lines, establish trust, or claim execution or compromise.
6. Allow confirmed disable only for unchanged, user-owned, standalone regular
   instruction Markdown. Revalidate every condition at action time and restore
   only an unchanged receipt target when the original path is absent.
7. Permit batch baseline enrollment only from a complete, coverage-clear
   report containing safe clean first-seen candidates. After confirmation,
   revalidate every selected file and abort the entire action on any stale,
   changed, suspicious, restored, or unsafe baseline input before one
   serialized private-state transaction. Clean content-only Markdown is
   excluded from trust without blocking the safe baseline subset; a content or
   coverage finding in it still blocks. AI must never perform or authorize
   enrollment.
8. Use generic count/severity notifications. Interactive review may identify a
   private path, but usernames, source snippets, secrets, line details, and AI
   output must not enter notifications or other public state.
9. Keep guided triage foreground-only. Offer fixed approve, confirmed-disable,
   rescan, leave, or quit decisions only where the underlying core action is
   eligible; never execute instruction content, invoke an editor, or turn a
   model response into an action.
10. Retention may prune bounded report and alert history, but never manifest
   review state; update or remove AI-job references before deleting a report.
11. Bind every persisted continuation cursor to the matching committed cycle
   and page sequence. A cursor without that commit must restart from the root
   with review required; it must never skip the uncommitted page.
12. Do not treat Markdown quoting or fencing as a trust boundary. Suppress a
    clearly labeled example only while no later active directive references it
    for execution.
13. Keep tray monitor/AI toggles asynchronous and no-shell. Reuse the
    transactional CLI, accept review-required status as valid, serialize
    mutations, bound combined output and runtime, retire Qt children, and do
    not let the tray's own Quit action interrupt rollback.
14. Serialize all private-state mutations under the validated state lock. Bind
    triage approve/disable actions to the exact displayed report and hash, and
    keep interrupted enrollment state fail-closed until a complete scan of the
    transaction's exact root revalidates every recorded target. Never let an
    unrelated root or partial continuation clear the transaction marker.

## Preserve scanner safety

- Never run PKGBUILDs, install hooks, package payloads, downloaded malware, or
  fixture commands.
- Keep the default path offline and no-fetch; source acquisition stays explicit.
- Local AI stays explicit and loopback-only, bypasses proxies, refuses
  redirects, bounds responses/timeouts, and never falls back to cloud AI.
- Package AI is tool-free and raise-only. Send bounded numbered JSON data;
  accept only strict allowlisted fields referencing supplied lines; discard raw
  model prose, commands, URLs, and extra fields. No model response may lower a
  deterministic result or establish trust.
- Mock provider calls and local endpoints; do not require a live model server in
  tests or CI.
- Use defanged local fixtures, `example.invalid`, fake keys, and temporary roots.
- Preserve hard blockers, conservative fallback behavior, and Python 3.8+
  compatibility.
- Keep `--all-markdown` content-only, monitor opt-in, and packaged user units
  disabled until setup. Do not add command/link preflight, privileged fanotify
  interception, process monitoring, automatic quarantine, or compromise claims.
- Bump the engine rule version when changed rules could invalidate cached scan
  decisions.
- Bind the bounded repository-provenance manifest/status to cache identity,
  review, history, trust comparison, and makepkg wrapper revalidation. A
  PKGBUILD-only cache key must never hide a changed adjacent artifact, and an
  incomplete repository capture must never create or reuse an allow decision.
- Revalidate the full package snapshot immediately before makepkg handoff.
  Reject makepkg input/integrity bypass flags and strip direct shell or dynamic-
  loader code-loading environment variables; review acceptance does not permit
  either bypass.
- Keep local repository-provenance review actionable: verbose terminal output
  may show a sanitized observed/control path, the one-based deterministic
  control line, and a short artifact SHA-256 prefix. Never copy artifact bytes,
  matched command text, or secrets into the explanation, and never present a
  locator as proof of execution or compromise.
- In deep-static mode, parse only the captured PKGBUILD, refuse all network
  acquisition under `--offline`, snapshot local files with no-follow reads,
  isolate per-source paths, fail closed on uninspected declarations, and avoid
  cache reuse until acquired-source identities are part of the key.
- Reject source/key URL credentials, localhost, and non-public IP literals on
  initial and redirected requests; omit URL userinfo, query, and fragment data
  from reports and state. State the residual DNS-rebinding limit explicitly.
- Bound archive entry enumeration and actual extracted bytes; never render or
  send images, fonts, media, or opaque binaries to an AI merely to inspect
  them. Bound acquired-source tree entries/candidates and fail closed when a
  candidate cannot be captured as unchanged regular-file text or a nested
  archive was not recursively inspected.
- Validate every model-authored advisory response with duplicate-key-rejecting
  bounded JSON, exact schemas, known IDs, and non-executable one-line prose.
  Do not retain URLs, commands, terminal controls, forged AuraScan labels,
  unsupported safe/compromised claims, raw model output, or raw exceptions.
- Repair Agent `user-shell` and `root-shell` are compatibility names for a
  fail-closed local command policy, not arbitrary shell grants. Accept only
  allowlisted read-only diagnostics and exact policy-checked
  `/usr/bin/pacman` forms; reject remote references, VCS/AUR/build tools,
  interpreters/loaders, decoding/evaluation, expansion, redirection,
  sensitive paths, mutation-capable diagnostic modes, and arbitrary
  executables before showing a confirmation. Require fresh, just-in-time
  approval for every exact model-authored command regardless of legacy
  session/plan configuration.
- For native tools that parse hostile data, capture a package-managed absolute
  executable, revalidate its identity immediately before use, provide a
  minimal environment, terminate option parsing before untrusted paths, and
  bound time plus combined output. Treat an invoked ClamAV scan that times out,
  exceeds a bound, or returns an error as incomplete inspection rather than a
  clean result.
- Upgrade handoffs use revalidated trusted absolute executables. Planned AUR
  builds block unless a future implementation can prove every package is
  routed through `aurascan-makepkg`; AI and confirmation do not waive this.
- Treat each literal local `install=` target, including a dot-prefixed hook, as
  mandatory scan evidence. Missing, unreadable, unsafe, ambiguous, or any
  symlinked component of the declared relative hook path under the package
  directory fails closed. A blocker may be cached only for the same
  failure-state identity; an unresolved hook cannot reuse or create an allow
  decision or review acceptance.

## Publish GitHub and AUR releases

Use this path only when the user explicitly authorizes external publication:

1. Read `docs/RELEASE_CHECKLIST.md` and `packaging/arch/README.md`. Verify the
   GitHub and AUR remote heads, target branches, SSH identities, version, tag
   availability, and clean scope; stop on divergence rather than forcing.
2. Declare the release `recovery-bearing` or `package-only` in its versioned
   release note. Recovery runtime/recipe, boot or image tooling, image package
   dependencies, and security-boundary changes shared with recovery require a
   recovery-bearing release. A package-only release must name the exact
   retained recovery image version/tag/digest and explicitly mark ISO/UKI gates
   as not rerun. Update its packaged manifest's application version and
   `package-only` disposition while retaining and re-verifying the exact prior
   ISO version, filename, public URL, digest, and `release-ready` state. Do not
   attach renamed recovery artifacts to a package-only release. If the retained
   image would be more than 90 days old on release day, require a recovery-
   bearing release; never reset its `released_at` without new validated bytes.
3. Commit the completed implementation. Synchronize the version in
   `pyproject.toml`, the recovery CLI development fallback, release tests,
   `packaging/arch/PKGBUILD`, and `.SRCINFO`. Use `SKIP` only for this pre-tag
   release candidate.
4. For a recovery-bearing release, commit a clean candidate whose recovery
   manifest is empty/build-required. Build with every AI mode disabled in a
   fresh root-owned, non-writable checkout and fresh root-owned work/output
   roots inside a freshly provisioned, disposable, and externally
   CPU/RAM/disk-bounded Arch VM or host with no host disk or home share. Never
   elevate a builder over a user-writable checkout, profile, package repository,
   work path, or output path; use fixed trusted tools and a minimal environment,
   and never select an artifact from an earlier output directory. Run QEMU only
   through the root preflight bootstrap/launcher and private build attestation
   printed by the builder. Require the bootstrap to bind itself and the
   supervisor before the latter verifies the retained harness, guards,
   artifacts, built readiness markers, and fixed packaged/prepared firmware
   before Bash, then drops the run to an unmapped UID in a fresh network
   namespace. Internal harness checks cannot retroactively make a
   user-writable launch script trustworthy. Preserve the launcher's exact
   attested private runtime as `TMPDIR` through every nested `env -i` helper;
   guards must validate that value and the harness must write its strict smoke
   result only at the launcher-expected path below that runtime.
   Audit the exact package build inputs/outputs, package repository, assembled
   image, validation UKI, profile overlay, and expanded root. Do not classify
   the sanitized package-test HOME as shipped recovery state, but do not relax
   the expanded-root prohibition on populated user homes. Treat a link to an
   identity path as a path reference and validate the target entry's bytes
   separately.
5. Treat these exact files as one recovery candidate:
   `aurascan-recovery-VERSION-x86_64.iso`, its `.iso.sha256` sidecar, and its
   sorted `.iso.packages.txt` manifest. Require the ISO to be strictly smaller
   than 2 GiB. Boot the exact ISO under SeaBIOS and OVMF UEFI; boot the local
   UKI built from the exact candidate code/package—not an older installed
   AuraScan—under ordinary and enrolled-key Secure Boot OVMF, verify unsigned
   rejection, run the deterministic storage/network/repair/rollback fixtures,
   and audit expanded artifacts using the documented bounded byte, normalized
   path/link, PAX metadata, and decoded-xattr checks. Reject empty/short
   explicit markers and short host identities instead of omitting them.
   Require serial-readiness checks against the complete journal-bound marker and
   positive service PID. Permit only zero, one, or two trailing carriage
   returns at its line boundary to cover systemd/QEMU transport framing; do not
   strip arbitrary control bytes or accept a bare marker. Run booted platform
   scenarios when their subsystem changed or the
   release claims that live outcome; otherwise record them as `NOT RUN` in the
   public limitations. Do not publish local UKIs as universal assets, and
   never claim an unrun gate passed.
   For trusted Secure Boot signature-table helpers, cap elapsed time and
   combined stdout/stderr independently from artifact mutation. Their
   file-size resource ceiling must accommodate a complete rewrite of the
   already size-validated UKI; never reuse the smaller diagnostic-output cap
   as that artifact ceiling. Revalidate the resulting file before a boot gate
   consumes it.
   Bind the signature-stripped control to the attested unsigned base through a
   strict, bounded PE/COFF parser. Permit a difference only in the Optional
   Header's four-byte `CheckSum`, which signing or signature removal may
   recompute; require equal size and exact equality everywhere else. Keep the
   separate requirement that reattaching the detached signature reproduces
   the exact signed UKI bytes.
   Keep removable-media writing separately fail closed: require trusted bounded
   absolute `findmnt`/`lsblk` probes, identify the running root, repeat device
   eligibility after confirmation and again while the exclusive descriptor is
   held, require the same positive `DISK-SEQ` at all three inspections, reject
   malformed or incomplete `lsblk` JSON, and compare the inspected kernel
   major/minor number with the final no-follow block-device descriptor before
   writing and again before verification.
6. For a recovery-bearing release, record the exact RC commit, then pin the
   tested ISO filename, public URL, and SHA-256 in a final pre-tag commit.
   Do not rebuild the ISO after pinning. Restrict the delta from the recorded RC
   to the packaged manifest and bounded release metadata, rerun source/package
   tests, and verify that the pinned digest still matches the retained RC bytes.
   Refuse the final tag while the manifest is
   `build-required` or release metadata contains a pending artifact value. For
   either disposition, run all applicable gates, push the GitHub branch over
   the verified SSH remote, and require the Python 3.8/3.14 branch matrix to be
   green. Create and push an immutable annotated tag at the final candidate,
   then require the exact tag's Python 3.8/3.14 matrix to be green. A skipped,
   cancelled, stale, or unrelated run is not sufficient. For a recovery-bearing release, create a draft GitHub
   release, upload the exact three recovery assets, verify their remote names,
   sizes, and digests, and only then publish it; a package-only release carries
   its retained-image disclosure and no newly labeled recovery assets.
7. Download the exact public tag archive, compute its SHA-256, replace `SKIP`,
   and regenerate `.SRCINFO` using the sanitized PATH commands in
   `packaging/arch/README.md`. Explicitly disable AI so a user `makepkg` wrapper
   cannot contaminate metadata. Run the documented package build/check only for
   AuraScan's trusted recipe, then commit and push the finalized metadata.
   Never move or recreate the public tag to include this post-tag commit.
8. Use a separate clean AUR clone on `master`. Preserve its maintainer/SPDX
   headers and AUR-only tracked files, copy only finalized package metadata,
   inspect the staged diff, commit, and push through
   `ssh://aur@aur.archlinux.org/aurascan.git` without force.
9. Verify GitHub `main`, the annotated tag and release, and AUR `master` from
   public remotes. Report commit IDs, version, checksum, tests, and any release
   gate that was not run.

## Validate and report

Apply the [validation scope in AGENTS.md](AGENTS.md#validation). Use meaningful
regressions for changed behavior; documentation-only work needs consistency and
diff checks, plus skill frontmatter validation when applicable. Run focused
tests first and the full source gates for detection, parser, policy, or shared
security-boundary changes:

```bash
python -m compileall aurascan tests tools
.venv/bin/python -m pytest -q
.venv/bin/python tools/audit_presenter_coverage.py --strict
.venv/bin/python tools/audit_presenter_coverage.py --strict-medium
git diff --check
```

Report the detection surfaces added, false-positive controls, recovery or
uncertainty boundaries, files changed, and the exact validation results. Say
explicitly if any check was not run.
