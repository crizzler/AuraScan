---
name: develop-aurascan
description: Diagnose, implement, validate, and publish AuraScan package rules, AUR threat detection, Agent Instruction Guard, security audits, upgrade checks, incident recovery, CLI reporting, Arch packaging, and GitHub/AUR releases. Use for safety-sensitive changes in the AuraScan repository.
---

# Develop AuraScan

Use this workflow for changes in the AuraScan repository.

## Establish context

1. Read `AGENTS.md`, `README.md`, the relevant part of `DEVELOPING.md`, and
   nearby tests.
2. Inspect `git status` and preserve unrelated changes.
3. Classify the requested evidence surface before editing:
   - default PKGBUILD or declared install-hook text;
   - opt-in acquired source under deep-static analysis;
   - installed package, bounded pacman history, or helper-cache provenance;
   - injected-root host artifacts; or
   - bounded AI-agent instruction and skill files under an explicit root; or
   - upgrade transaction context; or
   - explicit cloud/local AI provider configuration and transport.
4. State what the evidence can and cannot prove. Keep static intent, attempted
   behavior, successful execution, and confirmed compromise distinct.

## Route the change

- Add default static rules in `aurascan/analyzers/deterministic.py`.
- Add acquired-source checks in `aurascan/analyzers/deep_static.py`.
- Put shared, secret-free correlations in a small analyzer helper.
- Add exposure and host checks in `aurascan/core/security_audit.py`.
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
- Update `README.md`, `DEVELOPING.md`, and
  `docs/releases/unreleased.md` when capabilities or contributor contracts
  change.

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
8. Detect remote second-stage execution only when static data flow binds an
   active fetch/clone to a local artifact and later execution of that artifact
   or a bounded decoded/copied derivative. Keep unexecuted downloads, source
   arrays, documentation, ordinary picture/media assets, and path mismatches
   negative. Treat a supported local decode-to-file chain followed by exact
   execution, or direct interpreter/executable invocation of a media-,
   document-, or font-named path, as a separate opaque-carrier correlation;
   never infer hidden content from the filename alone.
9. Scan built package `.INSTALL` control text through the bounded no-follow
   archive reader. An unreadable, changing, oversized, binary, or invalid hook
   is an incomplete-inspection blocker, not evidence of compromise.

## Design instruction-file protection

1. Treat Markdown, JSON, imports, hooks, and skill resources as untrusted data:
   never source, import, render, execute, or traverse symlink directories.
2. Restrict final regular-file targets to the selected root, use no-follow and
   `fstat` validation, detect replacement during reads, and bound enumeration,
   sizes, and elapsed time.
3. Correlate active behavior families and suppress quoted examples, fenced
   documentation, comments, and negated instructions where evidence permits.
   Preserve bounded, one-based physical line ranges for contributing active
   text and report semantic behavior labels and fixed reasons without source
   snippets.
4. Keep first-seen/change integrity review separate from content severity.
   Describe a clean first-seen file as integrity-only review with AI
   `not-needed`; prioritize actual suspicious findings in terminal output and
   clearly label an incomplete continuation page. Machine-and-UID-bound
   approval cannot be restored onto a rebuilt host.
5. Keep the periodic deterministic service offline and credential-free. AI is
   separately enabled, raise-only, tool-free, strict-JSON, and limited to
   bounded opaque evidence IDs, fixed reasons, behavior labels, and
   deterministic locations. Map advisory rationales to supplied evidence; AI
   cannot invent lines, establish trust, or claim execution or compromise.
6. Allow confirmed disable only for unchanged, user-owned, standalone regular
   instruction Markdown. Revalidate every condition at action time and restore
   only an unchanged receipt target when the original path is absent.
7. Use generic count/severity notifications. Interactive review may identify a
   private path, but usernames, source snippets, secrets, line details, and AI
   output must not enter notifications or other public state.
8. Retention may prune bounded report and alert history, but never manifest
   review state; update or remove AI-job references before deleting a report.
9. Bind every persisted continuation cursor to the matching committed cycle
   and page sequence. A cursor without that commit must restart from the root
   with review required; it must never skip the uncommitted page.
10. Do not treat Markdown quoting or fencing as a trust boundary. Suppress a
    clearly labeled example only while no later active directive references it
    for execution.
11. Keep tray monitor/AI toggles asynchronous and no-shell. Reuse the
    transactional CLI, accept review-required status as valid, serialize
    mutations, bound combined output and runtime, retire Qt children, and do
    not let the tray's own Quit action interrupt rollback.

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
2. Commit the completed implementation. Prepare a versioned release note and
   synchronize the version in `pyproject.toml`, the recovery CLI development
   fallback, release tests, `packaging/arch/PKGBUILD`, and `.SRCINFO`. Use
   `SKIP` only for this pre-tag release candidate.
3. Run all release gates, create an annotated tag, and push the GitHub branch
   and tag over the verified SSH remote. Publish the matching GitHub release
   before advertising the package source.
4. Download the exact public tag archive, compute its SHA-256, replace `SKIP`,
   and regenerate `.SRCINFO` using the sanitized PATH commands in
   `packaging/arch/README.md`. Explicitly disable AI so a user `makepkg` wrapper
   cannot contaminate metadata. Run the documented package build/check only for
   AuraScan's trusted recipe, then commit and push the finalized metadata.
5. Use a separate clean AUR clone on `master`. Preserve its maintainer/SPDX
   headers and AUR-only tracked files, copy only finalized package metadata,
   inspect the staged diff, commit, and push through
   `ssh://aur@aur.archlinux.org/aurascan.git` without force.
6. Verify GitHub `main`, the annotated tag and release, and AUR `master` from
   public remotes. Report commit IDs, version, checksum, tests, and any release
   gate that was not run.

## Validate and report

Run focused tests first, then:

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
