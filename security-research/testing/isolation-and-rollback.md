# Isolation, cleanup, and rollback

Status: rules for the initial harness and for any later round. This round
executed only analyzer-level tests in the repository's test process.

## 1. What runs, and where

The corpus test never executes a fixture. It copies the fixture directory into
pytest's `tmp_path`, reads the bytes, and passes the text to an analyzer
function. The analyzers used here — `DeterministicAnalyzer`,
`SourceMetadataAnalyzer`, `audit_npm_install`, and the bounded install-hook
resolver — are static text consumers. They do not invoke a shell, package
manager, interpreter, or network client.

Isolation properties of the current harness:

- **Temporary root.** All per-case work happens under pytest's `tmp_path`,
  which lives below pytest's `--basetemp` (normally the platform temporary
  directory). The committed corpus is opened read-only for hashing and copying.
- **No home-directory state.** The corpus test calls analyzers directly and
  does not use the engine's audit-log path. The wrapper and MCP tests it is run
  alongside inject their own temporary paths.
- **No network.** No fixture is fetched, resolved, or contacted.
- **No privilege.** No test calls `sudo`, `pacman`, `makepkg`, `arch-chroot`, a
  root broker, a recovery action, or a disk/USB operation.
- **No secret material.** Fixtures contain only `example.invalid` hosts and
  synthetic values. No real credentials, tokens, keys, or user data.

## 2. Running in a temporary directory

From the repository root:

```bash
# The test harness creates and owns its temporary tree.
.venv/bin/python -m pytest -q tests/security_research/test_detector_corpus.py
```

For a manual, non-pytest run of the metrics report, export a scratch `TMPDIR`
so the copy root is explicit and easy to remove:

```bash
export TMPDIR="$(mktemp -d "${XDG_CACHE_HOME:-$HOME/.cache}/aurascan-corpus.XXXXXX")"
.venv/bin/python tests/security_research/test_detector_corpus.py
rm -rf -- "$TMPDIR"
```

Do not run the harness with a repository-relative `TMPDIR`, and do not point it
at a directory that contains unrelated work. The report script uses
`tempfile.TemporaryDirectory`, so it removes its own tree on normal exit; the
explicit `TMPDIR` is only a belt-and-braces boundary.

## 3. What is never executed

The following are forbidden in every round of this harness, not only this one:

- PKGBUILD bodies, `build()`/`package()`/`prepare()` functions, or any shell
  text from a fixture.
- `.install` hook bodies, including hooks that look harmless.
- npm lifecycle scripts (`preinstall`, `install`, `postinstall`, `prepare`) and
  JavaScript entry files.
- `makepkg`, `npm`, `node`, `pnpm`, `yarn`, `pacman`, `yay`, `paru`, `sudo`,
  `arch-chroot`, `mkfs`, `dd`, or a recovery recipe.
- Any agent instruction file, Cursor/MCP configuration, editor task, archive,
  bytecode object, or downloaded source.
- Any URL or hostname in a fixture. Fixtures use `example.invalid`; nothing
  resolves it.
- Any AI provider or model endpoint.

If a proposed probe needs one of these to run, it is not a harness probe. It
belongs to a separate, owner-approved disposable-environment card.

## 4. Cleanup

| Artifact | Cleanup |
|---|---|
| Per-test copies | Removed automatically by pytest after the test session (subject to pytest's `tmp_path` retention policy). |
| Manual metrics run | `tempfile.TemporaryDirectory` removes its tree, or `rm -rf -- "$TMPDIR"` as shown above. |
| Python bytecode | `tests/security_research/__pycache__` and `aurascan/**/__pycache__` are repository-cache artifacts; remove with `find ... -name __pycache__ -type d -prune -exec rm -rf {} +` if a clean tree is required. Do not commit them. |
| Corpus fixtures | Never modified by a test. If a hash check fails, treat it as a corpus change and review it; do not "fix" it in place without a manifest update. |
| Evidence documents | Intentionally retained and version-controlled. Hashes are recorded in `security-research/evidence/evidence-index.md`. |

This round created no build products, no package archives, no extracted
payloads, no logs, and no state outside the repository test cache and the
`security-research/`/`tests/security_research/` paths.

## 5. Rollback

- **Repository content.** The change is uncommitted. Revert only your own paths
  if needed: `git checkout -- tests/security_research security-research/testing
  security-research/evidence`. Do not revert another owner's files.
- **Temporary state.** Delete the `TMPDIR` used for a manual run. Pytest's
  temporary directories are disposable by design.
- **Later disposable-environment round.** Take a VM/container snapshot before
  the run, keep the run inside that snapshot, and destroy the environment
  afterwards. Do not attempt to "clean" a host that was used for privileged
  testing; rebuild it or restore the snapshot.

## 6. What requires a disposable container or VM, and owner approval

The following cannot be done safely in the repository test process and are
excluded from this card:

1. Replacing, renaming, or symlinking a real trusted executable
   (`/usr/bin/makepkg`, `/usr/bin/pacman`, `/usr/bin/sudo`, recovery tools).
2. Racing validation and execution (TOCTOU) with a concurrent adversary.
3. Starting a genuinely privileged root broker or a second unprivileged process
   with a stolen capability.
4. Running a real AUR/PKGBUILD build, including the opt-in devtools sandbox.
5. Mounting, scanning, repairing, or rolling back a real or simulated target
   disk; writing a USB device; booting a recovery image.
6. Any test that needs `sudo`, kernel capabilities, a modified host PATH, or a
   modified host `/usr/bin`.
7. Any network acquisition, registry query, or live AI/provider call.

Minimum conditions for such a round, all of which need explicit owner approval
before it starts:

- A freshly provisioned, disposable Arch VM or container, dedicated to the
  test, with no host home-directory share and no host disk passthrough.
- An unprivileged test user for non-privileged probes; any privileged step is
  confined to the disposable guest and documented before execution.
- CPU, memory, disk, and wall-clock bounds; a snapshot taken before the first
  privileged step.
- Network disabled unless the test explicitly requires a controlled endpoint;
  no live malicious infrastructure, no third-party targets, no production
  services.
- A pre-written test plan naming each command, expected outcome, and stop
  condition. No exploratory privileged commands.
- Post-run destruction of the environment and a written record of every command
  and exit code, including failures.

## 7. Stop conditions

Stop the run and report immediately if any of the following occurs:

- A fixture, hook, script, or instruction is executed rather than read.
- A write occurs outside the declared temporary root.
- A network connection is attempted.
- A privilege boundary changes (UID/EUID, capabilities, `no_new_privs`, mount
  namespace) without an approved step.
- A test would need host state, a real package manager, or a real disk.
- Evidence would require retaining a secret, credential, private path, or
  working payload.

Do not continue "to see what happens". Record the condition, the exact command,
and the observed output, then stop. A stopped test is reported as `NOT
EXECUTED` or `BLOCKED`, never as a pass.
