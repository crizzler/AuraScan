# AuraScan Desktop UI Design

Status: design accepted. Phases 1 through 4 are implemented in the working tree
and not released. AUR publication of the desktop package remains outstanding;
the recipe is a reference only. Nothing in this document describes shipped
behavior until the phase table marks a phase released.

## Why a desktop UI

AuraScan already produces the hard part: deterministic evidence with explicit
uncertainty, a stable rule catalog, and bounded JSON output on `doctor`,
`upgrade`, `incidents`, `config-drift`, `security-audit`, `intelligence`,
`instruction-audit`, and `evidence`. What it does not offer is a place where a
human can see the whole state of a machine at once, understand what was
checked, and act on the small number of things that need attention.

The UI's job is therefore narrow and unusually strict:

- present evidence that the scanner already computed;
- make coverage and uncertainty as visible as findings;
- route a small set of fixed actions through the existing consent-bound core.

It is not a second scanner, not a policy engine, and not a trust signal.

## Goals and non-goals

Goals:

- one screen that answers "is this machine healthy, what changed, what needs
  attention, and what did AuraScan not check";
- a reading surface for scan reports that keeps rule ID, severity, confidence,
  evidence quality, and coverage distinct;
- a fixed action surface that can only request operations the CLI already
  supports, each revalidated by the core;
- the same renderer in a browser (development and tests) and in a desktop
  shell, so design work is not duplicated and CI does not need a window server.

Non-goals:

- certifying a package, host, or configuration as safe;
- executing package code, hooks, fixtures, or instruction files;
- computing or lowering severity, confidence, or coverage in TypeScript;
- running as root, installing a privileged helper, or adding passwordless
  policy;
- contacting a model, registry, or update endpoint on its own;
- replacing the CLI, the tray, or the pacman hook.

## Product model

Three vocabularies stay physically and visually distinct:

| Family | Values | Source |
| --- | --- | --- |
| Deterministic severity | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` | rules and `core/risk.py` |
| Evidence confidence | `high`, `medium`, `low` | rule metadata |
| Scan coverage | `complete`, `incomplete`, `not scanned` | snapshot/phase status |

A finding is never described as "safe", "clean", "trusted", or "approved". The
absence of findings is "no additional concerns" and is always accompanied by
what was and was not inspected. AI text, when configured and enabled, is
advisory, labelled, and never rendered as an instruction or an action.

## Information architecture

```text
┌──────────────┬───────────────────────────────────────────────┐
│ Sources      │  Overview                                     │
│  Overview    │   health · coverage · intelligence · attention│
│  Checks      │                                               │
│  Incidents   │  [main pane]                                  │
│  About       │                                               │
└──────────────┴───────────────────────────────────────────────┘
```

- **Overview** — snapshot identity, check totals by status, the detection-data
  identity, and pending incident counts. Answers "what state is this machine
  in".
- **Checks** — every doctor check grouped by subsystem, filterable by status
  and searchable by name. Answers "what was verified and what needs action".
- **Incidents** — pending and unseen marker counts, highest severity, and the
  neutral empty state. Answers "does anything need me now".
- Later phases add **Scan** (report reading) and **Actions** (fixed verbs).

Inspired by the Hermes desktop shell's density, single-accent palette, one
badge component, and explicit loading/empty/error states. Not copied: Hermes
renders conversations and supervises a long-lived gateway; AuraScan renders
evidence and uses one-shot commands.

## Contract v1: `aurascan-ui/1`

`aurascan ui --json` prints one JSON object and exits 0. It is a snapshot, not
a gate: `doctor.ok` carries the health conclusion, so a UI never has to treat
"needs attention" as a command failure.

```json
{
  "contract": "aurascan-ui/1",
  "generated_at": 1792757134,
  "app": { "version": "0.11.0", "python": "3.14.0", "platform": "linux" },
  "doctor": { "ok": true, "checks": [DoctorCheck, ...] },
  "intelligence": {
    "status": "bundled", "source": "bundled", "digest": "...",
    "identity": "...", "update_channel": "unconfigured"
  },
  "incidents": { "pending": 0, "unseen": 0, "highest_severity": null }
}
```

`DoctorCheck` is the existing doctor shape and is reused verbatim:
`{ "name": string, "status": "ok"|"warn"|"error", "message": string,
"details"?: object }`.

Rules:

- **Additive only.** New keys may appear without a contract bump. Removing,
  renaming, or retyping a key, or changing a status vocabulary, requires
  `aurascan-ui/2` and a matching parser update.
- **Fail closed.** A renderer that sees an unknown contract string, a missing
  required object, an unknown check status, or more than
  `MAX_CHECKS` (1000) entries refuses to render and shows the contract error
  instead of a partial or optimistic view.
- **Bounded and secret-free.** No marker IDs, marker paths, environment
  values, credentials, or raw package bytes. Counts, names, statuses, and
  already-public tool paths only.
- **No side effects.** No state mutation, service operation, AI call, package
  manager invocation, or network request beyond what each composed check
  already performs.
- **Local only.** The snapshot is written to the caller's stdout. It is never
  uploaded, cached remotely, or included in telemetry.

`incidents.highest_severity` is `null` when no markers are pending.

At least one evidence section (`doctor` or `report`) must be present; a snapshot
carrying neither is rejected.

### Report mode

`aurascan ui --report FILE --json` projects one saved AuraScan JSON report into
the same envelope and skips live evidence collection entirely:

```json
{
  "contract": "aurascan-ui/1",
  "generated_at": 1792757134,
  "app": { "version": "0.11.0", "python": "3.14.0", "platform": "linux" },
  "report": {
    "schema_version": "1.0",
    "scanner_version": "2.6.0",
    "package": { "name": "example-pkg", "version": "1.0-1",
                 "pkgbase": "", "maintainer": "" },
    "risk": { "severity": "HIGH", "action": "MANUAL_REVIEW",
              "blocks_installation": false, "requires_manual_review": true,
              "recommended_action": "manual_review", "reason": "..." },
    "counts": { "total": 2, "by_severity": { "LOW": 1, "MEDIUM": 0,
                 "HIGH": 1, "CRITICAL": 0 }, "blocking": 0,
                "manual_review": 1, "truncated": false },
    "findings": [ReportFinding, "..."],
    "messages": ["Scanned"],
    "context": { "scan_policy": "full" }
  }
}
```

`ReportFinding` carries the rule ID, severity, confidence, evidence quality,
phase, source, a basename-only location, the one-based line number, title,
summary, recommendation, checked and not-checked text, and the two policy
flags.

Projection rules are deliberately stricter than the raw report:

- raw package bytes are never copied: `evidence_snippet`, `raw_output` and
  `technical_details` stay in the terminal;
- absolute paths are reduced to the basename, so a saved snapshot does not leak
  a build root or a user name;
- finding identifiers, file hashes and source-acquisition internals are dropped;
- display text passes `core/text_safety.sanitize_terminal_text`;
- the file read is bounded to 16 MiB and display to 500 findings; counts always
  cover the full report and `truncated` is disclosed. Messages are limited to
  20 entries of 300 characters;
- an unknown severity, confidence, risk action, rule-identifier shape, or a
  non-object finding rejects the whole snapshot;
- no doctor run, intelligence read, incident read, AI call or package-manager
  invocation happens in report mode.

### Action catalog

`aurascan ui --actions --json` returns the only actions the desktop shell may
run. IDs live in `aurascan/core/ui_actions.py`:

```json
{
  "contract": "aurascan-ui/1",
  "generated_at": 1792757134,
  "app": { "version": "0.11.0", "python": "3.14.0", "platform": "linux" },
  "actions": [
    {
      "id": "scan_package",
      "label": "Scan a package archive",
      "summary": "...",
      "kind": "read_only",
      "confirmation": "none",
      "renderer_may_request": true,
      "arguments": [{ "name": "package_path", "kind": "existing_file",
                      "label": "Package archive" }],
      "argv_preview": ["aurascan", "--pkg", "{package_path}", "--json"],
      "notes": "..."
    }
  ]
}
```

Rules:

- Action IDs are fixed in the catalog. A renderer that receives an unknown ID
  must not invent one, and the catalog is never assembled by the renderer.
- The renderer supplies an ID and only the declared arguments. It never supplies
  an executable, a flag, or a command string.
- `read_only` actions (`scan_package`, `scan_pkgbuild`, `project_report`,
  `refresh_snapshot`) may be requested. `terminal_only` actions
  (`repair_runtime_links`, `repair_hung_application`) install or downgrade
  packages through sudo and stay in the terminal.
- `argv_preview` is display text produced by the core. It is shown for
  transparency; it is not a command the renderer may run.
- `build_action_argv` validates every substituted value before use: absolute
  path, no leading dash, no control characters, bounded length, and no
  undeclared argument names.
- Any future renderer-requestable mutation must set `confirmation: "hash_bound"`
  and call `verify_report_binding` with the exact report bytes the user saw
  before the core acts. A mismatch fails closed.

## Transport and process model

```text
Renderer (React, no Node)  ──intent──▶  Shell  ──fixed argv──▶  aurascan ui --json
        ▲                                    │                    aurascan <verb> --json
        └───────── schema-versioned JSON ◀───┘
```

- One-shot child processes with fixed argument vectors. No shell, no `PATH`
  lookup, no user-supplied executable.
- **No local HTTP gateway.** AuraScan operations are request/response, so the
  Hermes pattern of spawning a `serve --host 127.0.0.1 --port 0` backend is not
  needed and is explicitly rejected for v1: it adds a network listener, a
  token, and a lifecycle to a security tool for no benefit.
- If live state is ever required, the next step is NDJSON on stdout, then a
  Unix socket under `$XDG_RUNTIME_DIR` with `0700` permissions and peer
  credential checks. Never TCP.
- The shell passes `AURASCAN_*` environment through unchanged and never adds
  `AURASCAN_AI_ENABLED=1` on its own.

## Shell boundary (Electron)

Electron is acceptable only as a dumb renderer host:

- `nodeIntegration: false`, `contextIsolation: true`, `sandbox: true`,
  `webSecurity: true`, `allowRunningInsecureContent: false`, no `<webview>`;
- `will-navigate` denied, `setWindowOpenHandler` returns `{ action: "deny" }`,
  external links are not opened automatically;
- strict CSP: `default-src 'self'; script-src 'self'; style-src 'self';
  img-src 'self' data:; connect-src 'none'; object-src 'none';
  frame-ancestors 'none'` for the shipped bundle (development allows the Vite
  origin only);
- preload exposes a frozen, enumerated bridge: `getSnapshot()`,
  `requestAction(actionId)` where `actionId` is a fixed union; never
  `exec(command)`, never an arbitrary path or argument;
- `autoUpdater` disabled. Updates ship through pacman/AUR, never from a
  network endpoint inside the app;
- no `eval`, no remote code, no custom protocol that maps arbitrary paths.

The preload bridge is a request surface, not an execution surface. Every action
is revalidated by the Python core, which keeps the existing consent rules:
fresh confirmation for each exact command, report-hash binding for guided
mutations, and no AI- or UI-supplied authority.

Tauri with `webkit2gtk` is the documented alternative if binary size or the
bundled-Chromium CVE stream outweighs ecosystem fit. The renderer is buildable
for either shell because it only depends on the contract.

### Implemented shell

`desktop/electron/main.cjs`, `preload.cjs`, and `argv.cjs` implement the
boundary above. What the shell can do today:

- run exactly two operations: refresh the live snapshot, or project a report
  the user picks in a native dialog. The chosen path never reaches the
  renderer, and the renderer never supplies one;
- spawn only the packaged `/usr/bin/aurascan` with a fixed argument vector. A
  development override is accepted only when absolute, control-free, and not
  flag-like, and is ignored entirely once packaged;
- pass an allowlisted environment (home, locale, XDG paths) with a fixed
  `PATH=/usr/bin:/bin`. AI and provider key variables are never forwarded;
- drain stderr without storing or forwarding it, bound stdout to 8 MiB, and
  kill the child after 20 seconds;
- reject any output whose `contract` string is not `aurascan-ui/1` before the
  renderer sees it;
- deny popups, navigation, webviews, and every permission request.

`AURASCAN_DESKTOP_SELF_TEST=1 electron .` runs a headless smoke test that
spawns the CLI, checks the contract, loads the built renderer in a hidden
window, and waits for the live snapshot to render. Packaging, signing, and an
end-to-end window test remain outstanding.

## Threat model additions

New attack surface: a Chromium/Node runtime in the user session, a renderer
that displays untrusted-in-origin data, and an IPC bridge.

Mitigations: renderer is a pure view over vetted JSON; no privileged path; no
network; strict CSP; no remote content; actions enumerated and revalidated.
Residual risk, stated plainly: a compromised renderer can display false
information but cannot change a deterministic result or install anything; the
shell runs at user privilege, so same-UID malware can still tamper with user
state; Electron and its dependencies carry their own CVE stream and must be
updated through the distribution.

## Design language

Borrowed principles from the Hermes desktop app, adapted to evidence:

- dark, low-chrome, high-density layout; one accent for selection and focus;
- a single badge component with three families (severity, confidence,
  coverage) that are never merged into one pill;
- monospace for rule IDs, digests, and versions; tabular numbers for counts;
- explicit loading, empty, error, and "not scanned" states — "not scanned" is
  never styled as success;
- keyboard-first: `Ctrl/Cmd+K` opens an action palette whose entries are the
  fixed action allowlist, not free text;
- no decorative motion around status changes; motion is limited to panel
  transitions and must respect `prefers-reduced-motion`.

Tokens live in `desktop/src/styles.css` as CSS custom properties. Palette:
graphite surfaces, one cool accent, severity colors that remain legible and
are always paired with text (never color alone).

## Packaging and release disposition

- The renderer and shell ship as a separate optional package
  (`aurascan-desktop`), architecture-specific, with its own release cadence.
- The reference recipe lives in `packaging/desktop/`. It is not published,
  installs `/usr/bin/aurascan-desktop` plus the shell under
  `/usr/lib/aurascan-desktop`, and depends on `aurascan` and `electron`. The
  build needs registry access for the pinned Vite/TypeScript toolchain and
  skips Electron's own binary download.
- **Publication gate:** do not push the desktop recipe until an AuraScan release
  ships `aurascan ui`. The current published scanner has no `ui` command, so the
  shell would have nothing to read.
- `aurascan` stays `arch=('any')`, stdlib-only Python. The desktop app is never
  a runtime dependency of the scanner, and the scanner never imports it.
- Adding the app alone does not change recovery runtime. The first shipped
  release is classified in the release note: package-only while the app is a
  read-only consumer of the CLI, recovery-bearing if a contract change touches
  code shared with recovery.
- The app version and contract version are displayed in the UI and in
  `aurascan ui --json` so a mismatch is diagnosable.

## Testing strategy

- **Contract tests (Python, `tests/test_ui_contract.py`)** pin the snapshot
  envelope, the doctor payload fields the renderer parses, counts and severity
  bounds, deterministic output under injected providers, and the absence of
  side effects. These fail when a backend change would break the UI.
- **Renderer unit tests (Vitest)** cover the fail-closed parser: valid
  snapshot, wrong contract, missing doctor, unknown check status, oversized
  check list, and tolerated unknown keys.
- **No network, no Electron, no window server in tests.** The renderer builds
  and tests headlessly; Playwright against the static build is added when the
  shell lands.
- **CI** gains a Node job only when the app starts shipping; until then the
  renderer is verified locally with `npm run typecheck`, `npm test`, and
  `npm run build`.

## Phases

| Phase | Scope | Exit criteria | Status |
| --- | --- | --- | --- |
| 0 | This design document | reviewed, contract frozen as `aurascan-ui/1` | done |
| 1 | `aurascan ui --json` snapshot + contract tests | bounded, side-effect-free, pinned by tests | implemented, unreleased |
| 2 | Read-only renderer over the real snapshot | overview, checks, incidents; fail-closed parser | prototype implemented, unreleased |
| 3 | Scan report reading + action center | fixed action IDs, hash-bound consent, revalidation tests | implemented; action execution lands with the shell |
| 4 | Electron shell + `aurascan-desktop` packaging | sandbox/CSP preflight, e2e on static build | shell, reference package, and CI checks implemented; publication pending |

Phases 1 and 2 exist in the working tree but are not released and are not part
of any package. Phases 3 and 4 do not exist in any form.

## Open decisions

- Electron versus Tauri for the first shipped shell (tracked, not blocking
  phases 1–2).
- Whether the action center ships per-action consent inside the UI or always
  hands off to the terminal; the CLI's existing fresh-confirmation rule must
  hold either way.
- Whether `aurascan ui` grows a `--section` filter once reports are included.
