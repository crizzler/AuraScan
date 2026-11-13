# Reviewer verdict — Agent Guard plan (`design/agent-guard-plan.md`)

Task: t_7e2ad551 · Review date: 2026-11-14 · Reviewer of record: reviewer
Scope: adjudication of `design/agent-guard/10-architect-review.md` (architect,
APPROVE WITH CONDITIONS) and `design/agent-guard/20-red-review.md` (Red, CHANGES
REQUIRED) over the plan **as a design input**. The plan, both reviews and all
code were read only; no code, plan or review text was modified. No model,
endpoint, agent, MCP server, real credential or article payload was used.

**Verdict: `CHANGES REQUESTED`** — for the plan as the design input to Slice A.
This adopts Red's disposition over the architect's, on one decisive point
(B1): the plan's machine-readable interface contract can emit a false pass and
contradicts the plan's own test 3. A design input whose exit table can tell CI
the opposite of the truth is not approvable as written. The plan's premise,
threat framing and architecture are affirmed (Q1/Q2/Q5); the revision set is
bounded (Blockers 1–7), and once it lands, the **smallest falsifiable slice
(A0-core, §7 below) is fundable without a second full review round**.

Evidence tags: `[Verified]` = confirmed in this run against plan/code with the
executed output or exact read cited; `[Inference]` = reasoned from verified
evidence; `[Speculation]` = plausible, unverified. Line citations to the plan
are `plan:N`; to code, `path:N`.

---

## 0. Finding verification (finding-verifier run over `red-findings.json`)

Per procedure: `verify.py prep findings/agent-guard/red-findings.json` → 13
`confirmed` findings into `verify-plan.json`; each was adversarially tested
against the plan text and the cited current-tree code; `verify.py check` →
`ok: upheld=13` (exit 0). For this design-only gate an "upheld" means **the
specification gap is verified** (missing contract/grammar/acceptance rule),
not that an exploit was executed — no implementation of the audit exists yet.

| ID | Verdict | Decisive evidence (executed this run) |
| --- | --- | --- |
| B1 | upheld | `plan:152` "0: audit completed and no HIGH finding" vs `plan:118` INCOMPLETE=MEDIUM vs `plan:155-156` exit 3 only on "could not complete"; plan's own test 3 (`plan:286-287`) demands "not a pass" the table cannot express |
| H2 | upheld | `plan:110-119` has no hook/MCP rule; `plan:248-250` excludes command strings; `instruction_guard.py:3798-3822` (`IG-ACTIVE-DANGEROUS-HOOK` HIGH, quote below) and `:4156-4190` already treat this evidence as in scope |
| H3 | upheld | `plan:226-231` lists layers with no merge rule; `instruction_guard.py:4088` itself: "Repository-controlled settings can cross a project trust boundary; effective permissions depend on Cursor mode and higher-priority policy." |
| H4 | upheld | `plan:116`/`:244-246` omit env/auth-store/VCS/socket classes; `agent.py:138-148` `AGENT_SENSITIVE_PATH_RE` is broader (`:142` covers `/proc/(self,N)/environ`); `agent.py:1943-1960` `minimal_agent_environment` shows the repo treats inherited env as an authority channel |
| H5 | upheld | `plan:117` asserts HIGH "unrestricted" from ambiguity; `plan:246` treats "sandbox/egress claims" as facts; `article-notes.md:21-24` (allowlist lesson) |
| H6 | upheld | `plan:116` `.env*` glob matches `.env.example/.template/.sample` by glob semantics; `plan:119` aggregate needs only shell + secret class + egress, and `plan:117` makes egress near-universal via ambiguity. Prevalence is `[Inference]` (Red concedes this); the calibration defect is `[Verified]` |
| H7 | upheld | `plan:271-273` digests the *report* only; full-plan read finds no per-input digest, `captured_at` or freshness; `article-notes.md:19-20` (operator-swappable payload) |
| H8 | upheld | `plan:114`: a "locally approved trust entry" removes the finding — consent is not verification |
| M2 | upheld | `plan:233-236` bounds parsers only; `guards.py:75-76` rejects directories/FIFO/socket/device — no walker primitive exists |
| M3 | upheld | `plan:271-273` "Report integrity" adjacent to `plan:269-270` same-UID admission; digest computed by the same unprivileged code |
| M5 | upheld | `plan:96` `PATH_OR_URL` with no hashing bound and no URL userinfo/query rule (`plan:252-257` covers raw paths only) |
| M6 | upheld | `plan:277-302`: the ten tests omit exit-code-with-incomplete, defaults, precedence, hooks/MCP exec, env secrets, tree bounds, oracle, terminal injection, post-audit change, URL components |
| L1 | upheld | `plan:38-42` claim vs `instruction_guard.py:1577-1613` (classifies `settings.json`/`settings.local.json`/`.mcp.json`/`mcp.json`), `:3621-3643`, `:4156-4190`; `plan:269-270` "The audit reduces reachability" is wrong — an audit reports, only remediation or a sandbox reduces |

Disproof attempts that failed (kept honest): **B1** — tried reading the
`plan:155-156` parenthetical ("incomplete coverage is reported, not silently
converted to a pass") as making every incomplete run exit 3; the explicit table
at `plan:152` wins and nothing maps a MEDIUM coverage finding to non-zero.
**H6** — tried to argue the aggregate's egress precondition saves the signal;
`plan:117`'s ambiguity clause makes egress present on almost any run. Nothing
in the confirmed set was disproved.

Carried separately, original uncertainty preserved (needs_validation in
`red-findings.json`, **not** promoted): **H1** (vendor default toolsets not
fetched — the plan gap "not-mentioned ≠ absent" is `[Verified]`, the vendor
tables are `[Inference]`); **H9** (Slice B model-channel exfiltration —
`[Inference]` design path, conditional on a remote/attacker-readable endpoint);
**H10** (MCP detection-oracle — exposure `[Verified]`, model behavior
`[Inference]`); **M1** (Harden action — no implementation exists to test);
**M4** (report injection — "sanitized" undefined at `plan:104-107` is
`[Verified]`, exploit unproven; `agent.py:1963-1964` `sanitize_terminal_output`
exists and should be mandated); **I1** (scorecard).

---

## 1. Q1 — Does the plan answer the actual threat? Detection vs blast radius

**Yes in framing; three sentences blur the separation.** `[Verified]` The plan
states the question correctly: not trigger detection (`plan:24-26`), and "an
audit is not containment" (`plan:66`). Slice A is detection/awareness (it
*reports* what a compromised model could reach); Slice B is blast-radius
reduction (OS boundary, `plan:124-139`). The threat — a backdoored model
driving an external agent's shell/tool surface to read and exfiltrate
credentials (`article-notes.md:16-18`) — is the one the aggregate rule names
(`plan:119`).

Blurred statements that must change:
- `[Verified]` `plan:269-270` "The audit reduces reachability" — false (L1).
  The audit *reports* reachability; only remediation or Slice B reduces it.
- `[Verified]` `plan:117` turns incomplete detection into a detection
  ("unrestricted" from ambiguity) — this is the plan's own doctrine violation
  (`docs/SECURITY_BOUNDARIES.md:325` incomplete inspection "is a coverage
  result, never an all-clear" — and equally never a claim).
- `[Verified]` `plan:138-139` Slice B's "a promise that the model's shell
  cannot reach the host or the network" is unqualified: H9's model-channel path
  (tool result → model request → endpoint) carries secrets with zero shell
  socket calls. Narrow to "shell descendants", gate on Red §7's probe matrix.

## 2. Q2 — Is Slice A the right smallest slice? Does Red's attack invalidate it?

**Right kind of slice; wrong contract. Red's attacks do not invalidate the
premise — Red itself concedes "Slice A (read-only preflight) is worth
building" (`20-red-review.md:8-9`) — but they do invalidate the slice as
specified.** `[Verified]` As written, the rule set + exit table can report a
clean pass on configurations the article's demo class uses and that in-tree
AuraScan already flags HIGH: a `SessionStart` hook running `curl … | sh` with
`permissions.deny: ["Bash"]` yields `IG-ACTIVE-DANGEROUS-HOOK` HIGH
(`instruction_guard.py:3798-3822`) while the plan's audit sees no shell tool
and exits 0 (`plan:115`, `plan:152`). Same false-clean class: omission-reads-
as-absence (H1), project-over-user override (H3), env-only secrets (H4).

What must change before the slice is fundable: Blockers 1–7 below. The smallest
fundable shape is **A0-core (§7)**: explicit `--root` + explicit surface, named
well-known files only (no directory walk), execution authority complete
(shell/exec + hooks + MCP stdio commands), host-relative capability facts,
coverage-first exit codes, calibrated aggregate. Dropped from the funded core:
`--model`/trust store (H8/M5), MCP tool (H10), desktop view (architect U7),
home-surface discovery (M2 walker). Where architect (U1–U6) and Red (A0)
disagree on scope, I side with **Red's A0 scope**, with two architect
adoptions: the **calibrated aggregate stays** (as a blast-radius statement, not
a "risk verdict"), and **project-local file resolution inside `--root` stays**
(named paths, bounded, no walk).

## 3. Q3 — Honest findings, interfaces, non-goals? Claims that overstate

Non-goals (`plan:68-76`) are honest — Red's cleared list (§8) and the architect
agree. The following claims overstate and must not ship (each with the fix):

1. `[Verified]` `plan:152` "no HIGH finding" → exit 0 reads as *pass* while
   `plan:118`'s MEDIUM coverage finding can coexist (B1). Fix: coverage-first
   exit contract (Blocker 1).
2. `[Verified]` `plan:117` "too ambiguous to prove that egress is denied" as
   HIGH *unrestricted* asserts an unobserved fact (H5; architect §4.1 calls it
   "the biggest false-precision defect"). Fix: Blocker 5.
3. `[Verified]` `plan:115` "no usable approval setting" conflates explicit
   `never` with an absent setting whose effective default is unknown (architect
   §4.1). Fix: `evidence: observed|inferred|unknown` per fact; no HIGH with
   `evidence: unknown`.
4. `[Verified]` `plan:114` + rule name: a user trust entry suppressing
   `…-UNVERIFIED-001` invites "no model finding = model verified" (H8). Fix:
   defer `--model` from the core; when it lands, the finding survives any
   trust entry and the report carries "model safety was not verified".
5. `[Verified]` `plan:269-270` "reduces reachability" (L1) and `plan:38-42`
   understating Instruction Guard (L1). Fix: wording + an explicit
   non-overlap/reuse statement for IG.
6. `[Verified]` `plan:271-273` "Report integrity" (M3). Fix: call it a
   consistency/corruption check; never let a valid digest suppress a coverage
   warning.
7. `[Verified]` `plan:138-139` Slice B promise (H9). Fix: "shell descendants",
   probe matrix, model-channel qualifier.
8. `[Verified]` `plan:320` "Catches the article-shaped mistake" is true only
   with H1–H3 coverage; state "reports the configuration facts the demo depends
   on" (Red §5.9).
9. `[Verified]` `plan:104-107` "sanitized path" is undefined (M4). Fix: mandate
   the existing `sanitize_terminal_output` discipline (`agent.py:1963-1964`,
   `ANSI_ESCAPE_RE` `agent.py:125-127`) for every rendered string.

## 4. Q4 — Are "no execution, no secret values, no network, fail closed" testable and complete?

**The requirements are the right ones (plan:259-268); the test plan asserts
them without proving them (M6, architect Q5).** `[Verified]` The in-tree harness
to prove them exists but has gaps: `tests/test_mcp_no_io.py:17-40` replaces
`socket.socket`, `socket.create_connection`, `urllib.request.urlopen`, and
(optionally) `subprocess.run` only — `subprocess.Popen`, `os.system`,
`os.exec*`, `os.spawn*` and `pty` slip through. `plan:289`'s sentinel test is
weaker than it reads: secret stores are never opened (plan:99-100), so a
sentinel *inside a secret file* trivially stays absent.

Exact probes required before the slice's claims are considered tested
(architect §7's twelve classes + Red A0 §4 tests; the union, trimmed to core):

1. **Execution/network tripwire** — full CLI audit over the article-shaped
   fixture under a widened `sitecustomize` shim
   (`subprocess.Popen/run/call/check_output`, `os.system/exec*/spawn*`, `pty`,
   `http.client`, `asyncio` connect) **and** `sys.addaudithook` recording
   `subprocess.Popen`/`socket.connect`/`os.exec`; assert zero events, including
   with a remote-looking `--model` string.
2. **`strace -f -e trace=network,process`** around the CLI → no `execve`, no
   non-local `connect` (Red A0 test 7).
3. **Sentinel matrix** — sentinel as config value, key, comment, filename,
   symlink target string, UTF-escaped bytes, over-cap boundary; absent from
   JSON, human output, coverage text, **error strings**, and every future
   adapter payload (architect Q5.4).
4. **Digest-oracle** — a weak known secret in config; no reported digest can
   confirm it (digest covers the sanitized projection only) (architect Q5.5).
5. **Hang resistance** — FIFO / `/dev/zero`-class file at a config path →
   typed coverage failure in bounded time (architect Q5.2; `guards.py:97`
   `O_NONBLOCK|O_NOFOLLOW` pattern).
6. **TOCTOU swap** — swap config and secret-store symlink between resolve and
   read → `path_changed`-class coverage (`guards.py:108-109` identity binding);
   swapped bytes never parsed; secret target never opened.
7. **Unknown-key false-clean** — approval override under an unrecognized vendor
   key → INCOMPLETE coverage, never "no shell tool observed".
8. **Defaults/omission** — empty config for an agent with a built-in shell →
   `1` or `3`, never `0` (Red A0 test 2).
9. **Precedence** — user deny + project allow → `1` (or `3` if precedence
   unknown), never `0` (Red A0 test 1).
10. **Hooks/MCP commands** — hook command with `Bash` deny → `1`; MCP stdio
    `command` with no tool entries → `1` (Red A0 tests 3–4).
11. **Exit-code matrix** — table-driven: HIGH-only → 1; incomplete-only → 3;
    HIGH+incomplete → 3 (documented composition); usage → 2; schema failure →
    4 **unreachable from hostile input** (parsers return typed coverage
    errors).
12. **Parity mutation** — delete one `AGENT_FORBIDDEN_PROGRAMS` entry → exactly
    the two-way parity tests fail (architect Q5.9).
13. **Bounded-parser corpus + `--root /`** — deep nesting, 2^k sizes, duplicate
    keys (reuse the `instruction_guard.py:3911-3912` rejection), NUL bytes,
    huge lines; `--root /` and `--root ~` bounded with explicit coverage.

## 5. Q5 — Buildable without destabilizing agent.py / Instruction Guard / MCP / desktop?

**Yes for A0-core, under the architect's O2 discipline.** `[Verified]`:

- `agent.py` untouched. Acceptance gate: `git diff` touches no
  `aurascan/core/agent.py`; `tests/test_agent.py` (1787 lines / 46 tests)
  unmodified and green. `docs/ARCHITECTURE.md:933` records why extraction is
  forbidden: "Command allowlisting, consent and execution are one security
  boundary; separating them without a policy/adapter interface risks weakening
  the fail-closed path." The plan's extract-the-policy branch
  (`plan:213-218`) must be closed as O2: **read-only import of
  `AGENT_REMOTE_REFERENCE_RE`/`AGENT_SENSITIVE_PATH_RE`/`AGENT_FORBIDDEN_PROGRAMS`
  + two-way category parity tests** (architect §3). `[Verified]` the reuse is
  data-only: `AGENT_FORBIDDEN_PROGRAMS` is one flat set whose four categories
  are comments (`agent.py:150`, `:176`, `:233`, `:268`, `:276`), and
  `_agent_sensitive_path` is not pure (`Path.cwd()` `agent.py:1015`,
  `resolve` `:1038`, `stat` `:1044`) — extracted "pure predicates" is a
  fiction. Import precedent: `aurascan/cli.py:9`
  (`from aurascan.core.agent import run_agent, …`) already imports it eagerly.
- Instruction Guard: **read-only parser reuse**, no edits. `[Verified]`
  `audit_agent_config_text` is pure ("Pure: no file is opened, no process is
  run, no state is written", `instruction_guard.py:4208-4212`) and is the
  single router for manifest findings (Red L1's reuse note). Hook/MCP evidence
  labels should be shared, not re-derived.
- MCP: **deferred out of the core**, so the closed import allowlist
  (`[Verified]` `tests/test_mcp_architecture.py:16-23`, exactly six modules;
  `test_43` `:71`) is not touched by the funded slice. When the tool lands,
  the `ALLOWED_AURASCAN` extension is a documented architecture change and
  `test_44` (`:90`, no presenter/CLI imports) and `test_45` (`:109`, no
  rule-ID literals) constrain the adapter (architect §6.2).
- Desktop: **deferred entirely** (architect U7). The "Harden this setup"
  action is cut from Slice A by both reviews (architect §6.3: Slice B coupling;
  Red M1: undefined terminal/command surface). Nothing desktop-side destabilizes.
- Sequencing stays architect's U1→U5 (rule catalog → pure parsers →
  no-follow capture → policy/aggregate → CLI+docs), with U6 (MCP) and U7
  (desktop) unfunded follow-ups. Cache/rule version bump (`AGENTS.md:485`) in
  U1.

## 6. Q6 — Blockers for the recommended slice (everything else is follow-up)

**Blocking (all are plan-text revisions; each states what "fixed" means):**

1. **B1 — exit/coverage contract** (`plan:152`, `:155-156` vs `:117-118`).
   Fixed when: exit `0` only if every selected surface parsed AND no execution
   authority observed; `3` on any incomplete/unknown surface or precedence;
   `1` when execution authority is present; `3 > 1 > 0` composition documented;
   JSON and human output carry `coverage_complete` and "this is not a
   model-safety verdict"; CI docs key on `3`, not `0`.
2. **H2 — execution-authority completeness** (`plan:110-119`, `:248-250`).
   Fixed when: presence of any hook command or MCP stdio `command`/`args`
   counts as execution authority (config fact, no command-string evaluation),
   with new rule(s) or a widened `AGENT-TOOL-SHELL-AUTOAPPROVE-001`,
   aggregate-eligible, presenter templates and rule metadata added, and the
   hook-based false-clean fixture (§4 probe 10) passes.
3. **H1/H3 — no-clean-on-omission** (`plan:115`, `:226-231`, `:284-285`).
   Fixed when: "not mentioned" resolves to `default`/`unknown`, never `absent`;
   every supported config layer per agent is enumerated with a merge rule or
   `unknown → coverage`; an unknown agent/version is INCOMPLETE; probes 8–9
   pass. (Pinned vendor default/precedence tables are follow-up research; the
   core requirement is that their absence can never produce a clean result.)
4. **H5 — host-relative capability model** (`plan:117`, `:246`).
   Fixed when: the report carries `execution_authority` (shell tool, hook
   command, MCP stdio command), `host_isolation: none|unknown|os_proven`, and
   `secret_classes_readable`; config-declared sandbox/egress/approval values
   are recorded as claims (secondary facts), never as proof; ambiguity is
   `unknown` coverage, never a HIGH "unrestricted" detection;
   `AGENT-EGRESS-UNRESTRICTED-001` fires only on observed configuration, and
   no HIGH finding carries `evidence: unknown` (architect §4.1).
5. **H4 — secret-class completeness** (`plan:116`, `:244-246`).
   Fixed when: classes cover environment variables, agent auth stores
   (`~/.claude/.credentials.json`, `~/.codex/auth.json`, …), VCS/package
   credentials (`.git-credentials`, `gh/hosts.yml`, `.npmrc`, `.docker`,
   `.kube`), sockets/agents (ssh-agent, gpg-agent), and reachability is stated
   as "readable by the agent's UID", not "inside `--root`"; when a shell is
   present the honest line is "this account's secrets are readable".
6. **H6 — aggregate calibration** (`plan:116-119`).
   Fixed when: inventory (MEDIUM/INFO, class + count, example/template/`.envrc`
   samples excluded) is separated from capability (HIGH); the aggregate is a
   blast-radius statement with `status: confirmed|cannot-rule-out|not-observed`
   (architect §4.1 structure, Red §5 wording), and a calibration corpus shows
   it does not fire on a clean checkout + ordinary `~/.ssh` (probe: safe
   fixture with a deny-only config stays quiet). If the corpus shows it still
   fires everywhere after fixes 2–5, demote it per Red H6 to a baseline fact.
7. **L1/M3/M4 + snapshot honesty — claim fixes** (`plan:38-42`, `:269-273`,
   `:104-107`). Fixed when: "reduces reachability" is corrected to "reports";
   the Instruction Guard relationship is stated (reuse `audit_agent_config_text`
   and hook/MCP evidence labels; no duplicated contradictory analysis);
   "Report integrity" is renamed a consistency check with per-input digests
   (`path, dev/ino, size, sha256`) and `captured_at` + a snapshot warning (H7's
   cheap half); "sanitized" is defined by mandating the
   `sanitize_terminal_output` discipline on every rendered string with a
   control-character output test.

**Follow-ups (explicitly not blocking):** `--model` provenance + trust store
(H8, M5 — rule must keep the finding for every remote endpoint regardless of
trust entry); MCP `audit_agent_runtime` (H10 — operator-only gate, aggregate
counts only, no paths/surface lists, oracle documented; architect's
`ALLOWED_AURASCAN`/test_43/44/45 constraints apply); desktop view (U7, digest
binding per `docs/DESKTOP_CONTROL_CENTER.md:59-61`); home-surface discovery
(M2 bounded walker + prune list + race tests); H1's pinned vendor default
tables; H7's revalidate-before-run (belongs to Slice B); **all of Slice B**
(H9 model-channel broker/DLP/mount policy, Red §7's nine probe classes, the
narrowed "shell descendants" claim).

## 7. Smallest falsifiable slice (A0-core) and verdict

```
aurascan agent-audit --root PATH --surface codex|claude|cursor|mcp [--json] [--explain]
```

- Explicit `--root` (default cwd) and explicit `--surface`; only the named
  surface's well-known files are read (no directory walk); home surfaces are
  out of scope in the funded core.
- Reports the four facts: `execution_authority` (shell/exec tool with
  approval-mode *facts*, hook commands, MCP stdio `command`/`args`),
  `secret_classes_readable` (Blocker 5 classes; counts and classes only),
  `host_isolation` (mostly `none`/`unknown` in v1), `coverage` (top-level
  `coverage_complete`), plus the calibrated aggregate (Blocker 6) and the
  mandatory "this is not a model-safety verdict" banner.
- Exit contract per Blocker 1 (`0` all-parsed-and-no-exec; `1` exec authority;
  `3` any incomplete/unknown; `2` usage; `4` schema failure, unreachable from
  hostile input).
- Acceptance = the thirteen probes in §4 (each a named regression with
  positive and negative assertions), the two-way parity mutation, and
  `tests/test_agent.py` green and unmodified, full source gates
  (`python -m compileall aurascan tests tools`; `.venv/bin/python -m pytest
  -q`; `tools/audit_presenter_coverage.py --strict` and `--strict-medium`;
  `git diff --check`).

This slice is falsifiable: probes 8–10 (defaults, precedence, hooks) each
fail it on the exact false-clean classes the article-shaped demo needs, and
probe 1/2 falsify any accidental execution or network access.

**Verdict again: `CHANGES REQUESTED`.** Sides picked where the reviews
disagree: Red on disposition (B1 is dispositive), Red on slice scope (A0),
Red on the egress/capability model (host-relative), Red on MCP/desktop/`--model`
deferral; architect on policy reuse (O2 read-only import + parity tests), on
keeping the aggregate (calibrated, `confirmed`/`cannot-rule-out`), on
explicit-first discovery with project-local named-file resolution, and on the
U1–U5 sequencing. Once Blockers 1–7 land in the plan text, A0-core is fundable
as the first release with the §4/§7 probe set as acceptance criteria; no
second full review round is required, only confirmation that the seven fixes
appear in the plan.

## 8. `not_verified`

- Vendor default toolsets, default approval modes and project-vs-user config
  precedence for Codex/Claude Code/Cursor/generic MCP (H1/H3 runtime severity).
- Vendor config formats (Codex TOML, Claude settings, Cursor JSONC); the JSONC
  concern is `[Speculation]`.
- Import-time purity of `core.agent` (verified statically and by the
  `cli.py:9` precedent only, not by an import tripwire).
- Live agent/model/endpoint/MCP behavior (none used); no real credential, home
  scan or article payload (not run, per `article-notes.md:26-31`).
- Slice B sandbox probes (no sandbox built); H9's model-channel path is
  design reasoning, not an executed bypass.
- Home-scan prevalence of the aggregate on real developer machines (H6
  prevalence is `[Inference]`; no home scan performed — privacy).
- Article content beyond `findings/agent-guard/article-notes.md` (URL not
  fetched).
- Test suites were not run (this is a read-only design adjudication; the only
  executed artifacts are the finding-verifier prep/check and static reads).
  `tests/test_agent.py`'s per-rule coverage was not enumerated.

## 9. Commands and paths used (all read-only except the two verdict artifacts)

- `read_file`: `design/agent-guard-plan.md` (full), `design/agent-guard/10-architect-review.md`
  (full), `design/agent-guard/20-red-review.md` (full), `findings/agent-guard/article-notes.md`,
  `aurascan/core/agent.py` (:125-304, :1005-1059, :1938-1967),
  `aurascan/core/instruction_guard.py` (:1575-1619, :2520-2554, :3600-3659,
  :3790-3834, :3898-3922, :4082-4096, :4140-4234),
  `tests/test_mcp_architecture.py` (full), `tests/test_mcp_no_io.py` (:15-59),
  `aurascan/mcp/guards.py` (:40-114), `docs/ARCHITECTURE.md` (:925-939).
- `terminal`: `sed -n` on `aurascan/cli.py:1-15`, `tools/architecture_audit.py:90-112`;
  `git status --short` (pre-existing `M AGENTS.md`, `M docs/RELEASE_CHECKLIST.md`
  untouched); `python3 …/finding-verifier/scripts/verify.py prep
  findings/agent-guard/red-findings.json` → 13 confirmed → `verify-plan.json`;
  `python3 …/verify.py check verify-plan.json` → `ok: upheld=13`, exit 0.
- Deliverables: this file and `findings/agent-guard/reviewer-verify-plan.json`
  (the filled verification plan).
