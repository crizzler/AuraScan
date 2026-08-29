---
name: develop-aurascan
description: Diagnose, implement, validate, and publish AuraScan package rules, AUR threat detection, security audits, upgrade checks, incident recovery, CLI reporting, Arch packaging, and GitHub/AUR releases. Use for safety-sensitive changes in the AuraScan repository.
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
   - upgrade transaction context; or
   - explicit cloud/local AI provider configuration and transport.
4. State what the evidence can and cannot prove. Keep static intent, attempted
   behavior, successful execution, and confirmed compromise distinct.

## Route the change

- Add default static rules in `aurascan/analyzers/deterministic.py`.
- Add acquired-source checks in `aurascan/analyzers/deep_static.py`.
- Put shared, secret-free correlations in a small analyzer helper.
- Add exposure and host checks in `aurascan/core/security_audit.py`.
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

## Preserve scanner safety

- Never run PKGBUILDs, install hooks, package payloads, downloaded malware, or
  fixture commands.
- Keep the default path offline and no-fetch; source acquisition stays explicit.
- Local AI stays explicit and loopback-only, bypasses proxies, refuses
  redirects, bounds responses/timeouts, and never falls back to cloud AI.
- Mock provider calls and local endpoints; do not require a live model server in
  tests or CI.
- Use defanged local fixtures, `example.invalid`, fake keys, and temporary roots.
- Preserve hard blockers, conservative fallback behavior, and Python 3.8+
  compatibility.
- Bump the engine rule version when changed rules could invalidate cached scan
  decisions.

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
