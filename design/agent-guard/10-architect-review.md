# Architect review — Agent Guard plan (`design/agent-guard-plan.md`)

Task: t_c1b39efe (read-only preflight). Reviewer of record: architect.
Scope: the plan as a **design input**, with emphasis on Slice A
(`aurascan agent-audit`, read-only preflight) and on keeping Slice B cleanly
separable. No code was changed, no payload was run, nothing was committed.

Evidence tags: `[Verified]` = confirmed against the current tree with the
commands listed at the end; `[Inference]` = reasoned from verified evidence;
`[Speculation]` = plausible but unverified.

---

## 1. Decision

Build Slice A as a **new, self-contained read-only audit engine**
(`core/agent_runtime_audit.py`) that reuses `core/agent.py`'s policy vocabulary
by **read-only import of its constant blocks plus two-way parity tests** — do
**not** extract the command-policy functions from `agent.py`, and do **not**
duplicate the constants. Restrict v1 discovery to an explicit `--root` with
explicit surface opt-in for anything outside it, count MCP stdio `command`
surfaces as exec authority, split "unproven" from "observed" in every rule so
the report never asserts an unobserved fact, and ship Slice A as U1–U6 below
with the desktop view and the "Harden this setup" action **dropped** from the
first release (they are Slice B vocabulary or non-essential surface). Sequence:
rule catalog → pure parsers → bounded no-follow capture → policy/aggregate →
CLI+docs → MCP. Everything Slice B needs (launcher, sandbox, bypass matrix) is
untouched and unfunded by this plan except one desktop action, which must be
cut (see §4.4).

---

## 2. Constraints (what must not change)

- `[Verified]` **`core/agent.py`'s fail-closed repair path must not change
  behavior.** `docs/ARCHITECTURE.md:933` records it as deliberately
  unrefactored: "Command allowlisting, consent and execution are one security
  boundary; separating them without a policy/adapter interface risks weakening
  the fail-closed path." The 46-test, 1787-line `tests/test_agent.py` suite must
  stay green and unedited.
- `[Verified]` **The MCP import allowlist is closed.**
  `tests/test_mcp_architecture.py:17-23` pins exactly six importable package
  modules (`analyzers.injection`, `core.models`, `core.instruction_guard`,
  `core.security_audit`, `core.rule_metadata`, `core.redaction`) and
  `tests/test_mcp_architecture.py:71` (`test_43_import_allowlist_is_stdlib_plus_six_named_modules`)
  enforces it. Any new MCP tool handler importing `core.agent_runtime_audit` is
  an architecture change to that list, not a detail.
- `[Verified]` **MCP code may carry no rule-ID literals and no presenter/CLI
  imports.** `tests/test_mcp_architecture.py:90` (`test_44`) forbids
  `*_presenter`/`*_cli` imports in `aurascan/mcp/**`;
  `tests/test_mcp_architecture.py:109` (`test_45`, regex at line 14) forbids
  rule-ID string literals there. New rules must live in
  `core/rule_metadata.py` (`aurascan/core/rule_metadata.py:27-33`,
  `520-581`) and MEDIUM+ rules need presenter templates
  (`AGENTS.md:471-473`), enforced by
  `tools/audit_presenter_coverage.py --strict-medium`.
- `[Verified]` **Deterministic policy stays authoritative; AI stays opt-in and
  raise-only** (`AGENTS.md:124-128`, `docs/SECURITY_BOUNDARIES.md:93-116`).
  Slice A must be fully useful with no AI provider (plan goal 2, plan:60-61).
- `[Verified]` **Untrusted input is data.** The audit must never execute,
  source, import, or start anything it reads (`AGENTS.md:112-122`;
  `docs/SECURITY_BOUNDARIES.md:79-91`). Static evidence must never be phrased
  as execution or compromise (`AGENTS.md:210-211`,
  `docs/SECURITY_BOUNDARIES.md:316-325`).
- `[Verified]` **Secret-free evidence.** No key/password/value in any output,
  persisted field, or error string (`AGENTS.md:140-141`).
- `[Verified]` **The desktop is a fixed-action console.** The renderer never
  describes a command; main owns argv; fresh consent per exact action; bind to
  what was displayed (`docs/DESKTOP_CONTROL_CENTER.md:49-71`).
- `[Verified]` **Runtime is Python 3.8+, standard library only**
  (`AGENTS.md:488`), and changed detection semantics require a cache/rule
  version bump (`AGENTS.md:485`).
- The review itself must not edit `AGENTS.md`, a live Hermes profile, or any
  user agent config. Nothing below requires that either: Slice A only *reads*
  agent configs; its only writes are optional private reports, which fall under
  `docs/SECURITY_BOUNDARIES.md:217-226` (machine+UID-bound private state).

---

## 3. Q1 — Module split: coherent? Extract or duplicate?

**Answer: the split is coherent but its reuse story is wrong in both proposed
branches. Neither extract-the-policy nor duplicate-the-policy; reuse the
constants read-only and prove category parity with tests.**

- `[Verified]` The plan states the audit "evaluates configuration facts, not
  actual command strings" (plan:249-250). The `agent.py` validation chain the
  plan would extract — `_lex_agent_command` (agent.py:1056-1072),
  `_agent_command_segments` (1075-1094), `_agent_program_and_args`
  (1097-1128), `_validate_agent_segment` (1571-1597),
  `_validate_agent_command_policy` (1600-1617) — validates *proposed command
  strings* for the repair loop. The audit never lexes a command string, so
  extracted validators would be dead code on the audit side and a re-tested
  moved surface on the agent side.
- `[Verified]` What the audit actually needs is three constant blocks:
  `AGENT_REMOTE_REFERENCE_RE` (agent.py:128-133),
  `AGENT_SENSITIVE_PATH_RE` (agent.py:138-148), and
  `AGENT_FORBIDDEN_PROGRAMS` (agent.py:149-294).
- `[Verified]` The "same categories as `agent.py`" (plan:240-242) do not exist
  as data. `AGENT_FORBIDDEN_PROGRAMS` is one flat set whose four categories
  (network clients / AUR+build tools / interpreters / decoders) are **comments**
  at `agent.py:150`, `176`, `233`, `268`, `276`. A category-keyed audit cannot
  "reuse" comment text; someone must either restructure the set inside
  `agent.py` (touches the security boundary) or define category data in the new
  module and pin it to the flat set by test.
- `[Verified]` `_agent_sensitive_path` is not a pure predicate: it calls
  `Path.cwd()` (agent.py:1015), `Path.resolve()` (1038) and `stat()` (1044).
  "The pure command policy" as a phrase overstates what is separable.
- `[Verified]` Precedent for read-only import of `core.agent` exists:
  `aurascan/cli.py:9`, `aurascan/core/incident_cli.py:29`,
  `aurascan/setup_wizard.py:30` import its entry points without destabilizing
  it. Importing is not executing; `agent.py`'s module level is constants,
  regexes, dataclasses and imports (static read of agent.py:1-120).
- `[Inference]` Full extraction (`core/agent_policy.py` moving both constants
  and predicates) is the highest-risk option with zero functional gain for
  Slice A: every moved line re-opens the fail-closed path
  (`docs/ARCHITECTURE.md:933`) for code the audit does not call.
- `[Inference]` Full duplication is drift-prone and contradicts plan goal 4
  (plan:64-65 "Reuse AuraScan's existing policy vocabulary rather than
  inventing a second contradictory command policy").

**Recommended resolution (plan open question 3):** Slice A imports
`AGENT_REMOTE_REFERENCE_RE`, `AGENT_SENSITIVE_PATH_RE`, `AGENT_FORBIDDEN_PROGRAMS`
from `aurascan.core.agent` as read-only data. Category labels live in
`agent_runtime_audit.py` as a category-keyed mapping with a **two-way parity
test**: (a) the union of audit categories equals `AGENT_FORBIDDEN_PROGRAMS`
exactly; (b) every entry in `AGENT_FORBIDDEN_PROGRAMS` appears in exactly one
audit category. A mutation that drops one deny entry must fail exactly the
parity tests (plan test 10 has the right instinct, plan:297-299 — pin the
count). Record this as a documented residual shared vocabulary, not a
duplication. If a later release wants the constants physically separated, do
the repo's established verbatim-move (AST-identity comparison + full
`tests/test_agent.py` green) as its own change — not inside this feature.

Residual risk of the recommendation, stated honestly: `core/agent.py` is a
process-capable module (`docs/ARCHITECTURE.md:198`; `stream_shell_command` at
agent.py:1967). Importing it for constants couples the audit's import closure
to that module. This is import coupling only — no authority moves — and
`aurascan/cli.py:9` already imports `core.agent` eagerly.

---

## 4. Q2 — `agent-runtime-audit/1.0` schema and rule set

**Answer: sufficient to express the blast-radius *shape*; five precision gaps
must close before the schema is honest.**

### 4.1 Ambiguity is being asserted as fact (the biggest false-precision defect)

- `[Verified]` `AGENT-EGRESS-UNRESTRICTED-001` fires HIGH when "the
  configuration is too ambiguous to prove that egress is denied" (plan:117).
  That asserts *unrestricted egress* — an unobserved fact — from *absence of
  proof*. The repo's doctrine is symmetric: incomplete inspection "is a
  coverage result, never an all-clear" (`docs/SECURITY_BOUNDARIES.md:325`) —
  and equally never a claim. Same defect in `AGENT-TOOL-SHELL-AUTOAPPROVE-001`:
  "or with no usable approval setting" (plan:115) conflates an explicit
  `approval: never` with an absent setting whose effective default the audit
  cannot know.
- Fix: (a) restrict `AGENT-EGRESS-UNRESTRICTED-001` to *observed* unrestricted
  egress configuration; unprovable egress becomes a
  `AGENT-RUNTIME-CONFIG-INCOMPLETE-001`/coverage entry; (b) give every finding
  `evidence: observed|inferred|unknown`; (c) give the aggregate a `status` of
  `confirmed` (all three contributing facts observed) vs `cannot-rule-out`
  (one fact unknown). Fail-closed is preserved — `cannot-rule-out` is never a
  clean result and drives exit 3 — without printing a false fact.

### 4.2 MCP stdio servers are exec authority and are missing from the aggregate

- `[Verified]` The article's demo reached the payload through an
  `exec_command` tool call (`findings/agent-guard/article-notes.md:17-18`), and
  an MCP server configured with `command`/`args` executes arbitrary programs
  regardless of the agent's built-in shell tool (the in-tree correlation logic
  for exactly this is `audit_agent_config_text`,
  `aurascan/core/instruction_guard.py:4208` and the `AGENT_CONFIG_SURFACES`
  allowlist at `instruction_guard.py:4201`).
- Fix: `AGENT-TOOL-SHELL-AUTOAPPROVE-001` (or a sibling rule) must count MCP
  stdio `command`/`args` surfaces as shell/exec authority. Missing today.

### 4.3 Secret-reachability severity calibration

- `[Verified]` `AGENT-SECRET-REACHABLE-001` is HIGH standalone (plan:116), and
  the plan itself admits the same-UID reality (plan:269-270): any developer
  home with `~/.ssh` and a project `.env` trips it. Standalone HIGH on ordinary
  machines is alert fatigue; the *aggregate* is where HIGH belongs.
- Fix (calibration, not scope): standalone MEDIUM as a presence fact ("class X
  exists and no isolation config was observed"), HIGH via
  `AGENT-CREDENTIAL-EXFIL-RISK-001` — mirroring how the plan already escalates
  `AGENT-MODEL-SOURCE-UNVERIFIED-001` (plan:114).

### 4.4 Missing fields / undefined state

1. `[Verified]` **Trust-entry store undefined.** `AGENT-MODEL-SOURCE-UNVERIFIED-001`
   references "a locally approved trust entry" (plan:114) but no field names
   its identity, storage, writer, or staleness. Add
   `model_ref: {kind: local-dir|local-file|https, sanitized_locator,
   digest|size-prefix, pinned: bool, trust_entry: {state:
   approved|absent|stale}}`. Any such store is new private state and must sit
   under `docs/SECURITY_BOUNDARIES.md:217-226` (machine+UID bound). For a local
   model directory, define the hashing bound (entry count / byte cap) — a
   multi-GB shard set cannot be "the hash" without a rule.
   `[Inference]` This is the hidden cost of the model-provenance rule; see §6
   for why v1 should take local `--model PATH` only.
2. `[Verified]` **Digest scope undefined** (plan:272-273). If the "evidence
   digest" covers raw captured config bytes, a short hash prefix of
   secret-bearing bytes is a weak-secret confirmation oracle (the plan wants
   short prefixes, plan:257). Digest must cover the **sanitized report
   projection**; any content hash over raw config must be full-length or
   salted and labeled guessable. Define whether `generated_at` is inside or
   outside the digest (deterministic-ordering test, plan:293, implies the
   digest must be reproducible).
3. `[Verified]` **`not_verified` is MCP-only** in the plan (plan:167). The CLI
   JSON must carry the same `coverage` + `not_verified` + `limitations` block;
   the human view must print it (reporting rules,
   `docs/SECURITY_BOUNDARIES.md:316-325`).
4. `[Verified]` **Exit-code composition undefined** (plan:150-157): a HIGH
   finding *and* incomplete coverage maps to 1 or 3? Define precedence
   (recommend 3 > 1 > 0: an incomplete audit cannot claim a completed HIGH
   scan) or document the rule.
5. `[Verified]` **Per-finding source binding.** The rule table's output row
   (plan:105) has path + line range, but the desktop digest binding needs a
   per-finding `source: {surface, sanitized_path, line_start, line_end,
   sha256_prefix}` so a changed file invalidates the view
   (`docs/DESKTOP_CONTROL_CENTER.md:59-61`).
6. `[Inference]` Vendor approval vocabularies drift (Codex `approvalPolicy`,
   Claude `permissions`, Cursor allow-lists). The schema needs a versioned
   `surface_schema` marker per recognized surface and a normalized
   `approval_mode` **plus** the bounded raw token, so an unrecognized token is
   `unknown`, never `never`-or-`always`.

**Rule-set sufficiency verdict:** with §4.1–4.4 fixed, the six rules express
the article's demo without overreach (plan §6 handling is honest: it reports
facts, not the trigger). Without them, the report prints HIGH findings that
assert facts nobody observed — the exact failure mode this product forbids.

---

## 5. Q3 — Discovery strategy (automatic surfaces vs explicit `--root`)

**Answer: safe and implementable only if v1 is explicit-first; the plan's own
open question 1 should be answered "explicit".**

- `[Verified]` The Instruction Guard contract for reading agent-adjacent files
  is "bounded no-follow reads under an explicit root; symlink directories never
  traversed" (`docs/SECURITY_BOUNDARIES.md:85`), and its tests must never scan
  a real home (`AGENTS.md`, working method 6). Automatic discovery of
  `~/.codex`, `~/.claude`, `~/.cursor` (plan:93-96, 228-231) runs *outside*
  `--root` and outside that contract.
- Recommendation: v1 auto-discovers only recognized **project-local** configs
  inside `--root` (e.g. `.claude/settings.json`, `.cursor/mcp.json`); home-tree
  surfaces require an explicit `--surface` **and** an explicit opt-in flag
  (e.g. `--include-home-surfaces`), with every discovered surface root printed
  in the coverage section. This also keeps the MCP tool's `root` guard
  meaningful (§4.4 of Q4 below).
- `[Verified]` Parser posture has a strict in-tree precedent:
  `aurascan/core/agent_config.py` bounds bytes/keys/depth/arrays
  (`agent_config.py:14-21`), rejects duplicate tables and keys
  (`agent_config.py:218`, `240-241`), refuses unsupported syntax explicitly
  rather than approximating (`agent_config.py:233-236`), and treats any
  deviation as `AgentConfigError` = incomplete inspection
  (`agent_config.py:44-51`). The plan's grammar requirement (plan:233-236)
  matches this; Codex TOML can reuse the shape.
- `[Speculation]` **Cursor config is commonly JSONC** (comments, trailing
  commas). Strict JSON will fail on ordinary Cursor files, making every Cursor
  audit `AGENT-RUNTIME-CONFIG-INCOMPLETE-001`. Decide explicitly: a bounded
  comment-strip subset parser (mirroring `agent_config.py`'s discipline) or
  honest universal coverage-failure for JSONC surfaces. Vendor formats were
  not verified in this review (see `not_verified`).
- `[Verified]` **Unknown vendor keys must be retained as unknown structural
  facts, not dropped.** Dropping an unrecognized approval override key would
  turn a permissive config into "no shell tool observed" — a false clean, the
  one outcome the plan forbids (plan:118, 234-235).

Permission and race risks the plan names only generically ("races … become
coverage/finding state", plan:267-268):

1. `[Verified]` **TOCTOU swap between discovery and read.** The proven fix in
   this tree is the `mcp/guards.py` identity pattern: `resolve_regular_file`
   (`aurascan/mcp/guards.py:43`) then `read_capped` (`guards.py:82-109`) opens
   with `O_NOFOLLOW` and refuses unless `fstat` still shows the same
   `(st_dev, st_ino, size)` (`path_changed`). This is the L1 fix recorded at
   `docs/ARCHITECTURE.md:218-222`. The audit's capture layer must implement the
   same discipline (a core module cannot import `mcp.guards`; copy the pattern
   or share a helper).
2. `[Verified]` **Non-regular files.** A FIFO named like a config blocks a
   naive open forever. `lstat`-regular check before open; refuse
   device/socket/FIFO to coverage. `agent.py:1047` already refuses non-regular
   targets in its own path check — same instinct needed here.
3. `[Verified]` **Secret stores must never be opened.** `AGENT-SECRET-REACHABLE-001`
   is a name/metadata classification: `lstat`/`stat` only, never read an SSH
   key, `.env`, or `~/.config/aurascan/.env`
   (`AGENTS.md:140-141`; plan:99-100 agrees — the tests must *prove* it, see
   Q5).
4. `[Verified]` **Symlinks.** Plan:235-236 (no directory traversal, no-follow
   reads, permission failures are coverage) matches
   `docs/SECURITY_BOUNDARIES.md:85` and the repository-provenance link rules.
   A symlink *file* at a config path must yield link text only or coverage —
   never a followed read.
5. `[Inference]` A hostile same-UID actor can rewrite a config after the audit;
   the report is a point-in-time observation. The captured-evidence digests
   (Q2 #2/#5) plus explicit "point-in-time" wording are the honest answer —
   the audit does not create a boundary (plan:269-270 is correct and must stay).

---

## 6. Q4 — CLI / MCP / desktop vs the authority model

**Answer: all three fit the fixed-action contract with two named exceptions and
one required architecture change.**

### 6.1 CLI — compatible
- `[Verified]` `aurascan agent-audit` follows the established subcommand
  pattern: dispatch from `main` (`aurascan/cli.py:514`) exactly like
  `npm-audit` (`cli.py:525-526`), implemented in a new presentation entry
  module (cf. `core/npm_audit_cli.py`), which must be added to
  `UI_ENTRY_SUFFIXES` (`tools/architecture_audit.py:95-108`) so INV-007
  (`docs/ARCHITECTURE.md:322`) keeps application code from importing it back.
  Fixed argv, no command strings, no new general command surface.
- `[Inference]` **`--explain` is ambiguous** (plan:146-148): the repo already
  has an "interactive finding explanation" that is a separate opt-in,
  display-only AI surface (`docs/SECURITY_BOUNDARIES.md:106-116`). Slice A's
  `--explain` must be defined as deterministic presenter prose (rule-metadata
  templates); if AI explanation is ever attached it is separately opt-in and
  cannot touch the report. Fix the wording.

### 6.2 MCP — compatible, but it is an architecture change and a host-scope decision
- `[Verified]` A fixed tool with `readOnlyHint: true` fits the registry exactly
  (`aurascan/mcp/registry.py:25`, `243-293`); `audit_agent_config` remains the
  single-document primitive (`mcp/tools/audit_agent_config.py:13-31`).
- `[Verified]` **Required change #1:** `mcp/tools/audit_agent_runtime.py` may
  not import `core.agent_runtime_audit` until
  `tests/test_mcp_architecture.py:17-23` (`ALLOWED_AURASCAN`) is deliberately
  extended and `test_43` (line 71, name says "six") updated. State this in the
  plan; it is a documented architecture change, not a detail.
- `[Verified]` **Required change #2:** the handler cannot import
  `agent_audit_presenter` (`test_44`, tests/test_mcp_architecture.py:90) and
  cannot name rule IDs (`test_45`, line 109). The report→dict projection must
  live in `agent_runtime_audit.py`; rule IDs flow from `core.rule_metadata`.
- `[Verified]` **Host-scope disclosure:** `security_audit` precedent shows the
  pattern — host-local evidence behind an explicit flag with "a result pasted
  into a chat discloses this host's layout" in the tool description
  (`registry.py:189-193`). `audit_agent_runtime` over home surfaces is the same
  disclosure class. Recommend MCP v1 = project-root scope only; if home
  surfaces are exposed, require an explicit `include_home_surfaces` input with
  the same description warning. A remote MCP client must not silently gain a
  home-config probe.

### 6.3 Desktop — one interface must be cut (this is the Slice B leak)
- `[Verified]` A `readAgentAudit` fixed action with digest binding matches the
  authority model (`docs/DESKTOP_CONTROL_CENTER.md:49-71`, binding rule at
  59-61) and the npm-audit precedent (read-only fixed vector, main-process
  path choice, `desktop/electron/main.cjs` owns argv, :163-168).
- `[Verified]` **Exception — the "Harden this setup" action** (plan:183-185):
  "opens the exact terminal command with the proposed `agent-guard` profile".
  This (a) couples Slice A UI to a Slice B launcher that will not exist in the
  Slice A release, violating separability, and (b) is one design decision away
  from becoming a new general command surface if the command or profile string
  ever derives from the report or renderer. Terminal handoff is an allowed
  pattern for *privileged existing* commands (`docs/DESKTOP_CONTROL_CENTER.md:113-122`),
  but there is nothing to hand off to in Slice A. **Cut this action from Slice
  A**; the Slice A desktop view (if kept at all) shows facts plus copyable
  advice the user applies by hand ("no automatic config write" — plan:186 — is
  correct and stays).
- `[Verified]` Minor: "a root token" (plan:190) is undefined vocabulary; the
  desktop contract's binding is to the displayed report/digest, not to a
  "token". Rename or define.

### 6.4 `--model PATH_OR_URL`
- `[Verified]` "A remote model reference is checked as a URL and trust state,
  not fetched" (plan:265-266) is the right offline posture. The URL check must
  inherit the source-acquisition lexical rules: reject credentials, localhost
  and non-public IP literals pre-transport, redact userinfo/query/fragment from
  anything persisted (`docs/SECURITY_BOUNDARIES.md:41`, `44`), no DNS, no
  fetch. Recommend v1 accepts local `--model PATH` only and defers URL/trust
  entries (Q2 #4) — it needs its own trust-store decision (plan open question
  2) and its own boundary note.

### 6.5 Slice B separability verdict
- `[Inference]` **Mostly clean**: separate binary surface (`agent-guard run`),
  separate funding gate and bypass matrix (plan:124-139, 308-309), report
  schema reserves no launcher fields. The only leak is the desktop action in
  §6.3 (cut it) and the `AGENT-EGRESS-UNRESTRICTED-001` ambiguity wording
  (§4.1), which bakes an enforcement expectation into Slice A language. With
  those two fixed, Slice B can be funded or dropped without touching Slice A.

---

## 7. Q5 — Test plan: does it *prove* no-execution / no-secret / no-network?

**Answer: it asserts the properties; it does not yet prove them. The harness to
prove them already exists in-tree and must be extended.**

- `[Verified]` `tests/test_mcp_no_io.py` runs tools in a child process with a
  `sitecustomize` shim that replaces `socket.socket`, `socket.create_connection`
  and `urllib.request.urlopen` (test_mcp_no_io.py:17-24), optionally
  `subprocess.run` (27-35), and asserts a full sweep changes no files and
  writes no state (tests at lines 60-112). This is the right pattern.
- `[Verified]` **The shim has gaps**: it does not replace `subprocess.Popen`,
  `subprocess.call/check_output`, `os.system`, `os.exec*`, `os.spawn*`, or
  `pty`. A call through `Popen` would slip past `test_27`. The plan's test 8
  ("MCP parity … no I/O, no execution", plan:294) inherits this gap.
- `[Verified]` Plan test 5 ("Sentinel secret in a config/secret file", plan:289)
  is weaker than it reads: secret files are never opened (Q3 #3), so a sentinel
  in a *secret file* trivially never appears. The meaningful probe is a
  sentinel inside **config text the parser actually consumes**, plus every
  boundary of the output surface.

**Missing adversarial tests (name them; these are the acceptance probes):**

1. **Execution/network tripwire over a full audit run** — run the CLI and the
   MCP tool over the article-shaped fixture under (a) the widened
   `sitecustomize` shim (`subprocess.Popen/run/call/check_output`,
   `os.system/exec*/spawn*`, `socket.*`, `urllib`, `http.client`,
   `asyncio` connect) and (b) `sys.addaudithook` recording
   `subprocess.Popen`, `socket.connect`, `os.exec` events; assert **zero**
   events, including with `--model https://…`.
2. **Hang resistance**: a FIFO or `/dev/zero`-class file at a discovered
   config path → typed coverage failure in bounded time, no hang.
3. **TOCTOU swap**: swap the config (and separately a secret-store symlink)
   between resolve and read → `path_changed`-class coverage; swapped bytes are
   never parsed and the secret target is never opened.
4. **Sentinel matrix**: sentinel as a config *value*, JSON *key*, *comment*,
   *filename*, symlink *target string*, UTF-escaped bytes, and
   over-the-byte-cap boundary; assert absence from `--json`, human output,
   coverage/notes text, **exception/error strings**, the MCP payload, and the
   desktop parser output.
5. **Digest-oracle test**: a weak known secret in config; assert no reported
   digest can confirm it (digest covers the sanitized projection; any raw
   content hash is full-length or absent).
6. **Unknown-key false-clean test**: an approval override under an unrecognized
   vendor key → INCOMPLETE coverage, never "no shell tool" (the specific false
   clean of §5).
7. **Aggregate honesty**: ambiguity-only egress → no "unrestricted" assertion;
   `confirmed` vs `cannot-rule-out` distinction; no HIGH finding carries
   `evidence: unknown`.
8. **Exit-code composition**: HIGH-only → 1; incomplete-only → 3; HIGH +
   incomplete → the documented winner; usage → 2; schema corruption → 4; and
   exit 4 must be unreachable from hostile input (parsers return typed
   coverage errors, never uncaught exceptions).
9. **Parity mutation**: delete one entry from `AGENT_FORBIDDEN_PROGRAMS` →
   exactly the two-way parity tests fail (pinned count).
10. **MCP authority tests**: `test_43/44/45` extended for the new module;
    `test_mcp_no_io.py` extended to call `audit_agent_runtime`; state-root
    emptiness (`test_29/30` pattern).
11. **Desktop**: digest mismatch → refuse; renderer-supplied path/command →
    refuse; malicious strings in report fields; the handoff/advice command is
    a main.cjs constant (argv-constant test) — though per §6.3 there should be
    no handoff in Slice A.
12. **Bounded-parser corpus**: deep nesting, 2^k sizes, duplicate keys, CRLF
    mixes, NUL bytes, 4-byte UTF-8, huge line counts → typed INCOMPLETE.

Regression stays as the plan has it (plan:297-299): `tests/test_agent.py`
(1787 lines / 46 tests) unchanged and green.

---

## 8. Q6 — Slice A sequencing (smallest buildable units)

| Unit | Content | Acceptance criteria |
| --- | --- | --- |
| **U1** Rule catalog + schema | `core/rule_metadata.py` + `core/presenter.py` entries for the 6 rules (fixed reasons, categories, severity per §4.3), `agent-runtime-audit/1.0` schema constants, cache/rule version bump (`AGENTS.md:485`) | `tools/audit_presenter_coverage.py --strict` and `--strict-medium` pass; `tests/test_mcp_architecture.py` rule-ID hygiene passes; diff touches only catalog/presenter/tests |
| **U2** Pure bounded parsers + fact model | Codex-TOML-subset, Claude-settings, Cursor-JSON(C) decision, MCP-manifest reuse of `audit_agent_config_text` (`instruction_guard.py:4208`); text → structural facts; unknown keys retained (§5) | Article/safe/malformed/duplicate-key/oversize/nested fixtures; all parse tests green under the no-network/no-process shim; parser functions perform zero I/O |
| **U3** Discovery + no-follow capture | Explicit `--root`; project-local auto-discovery only; home surfaces behind explicit opt-in; `resolve_regular_file`/`read_capped`-style identity capture (`mcp/guards.py:43-109` pattern); secret stores lstat-only | Symlink/FIFO/TOCTOU/permission-denied tests; tripwire shows only open/lstat/read(≤cap) and **zero** secret-path opens; every surface root appears in coverage |
| **U4** Policy evaluation + aggregate + report | Category parity with `agent.py` constants (§3); `confirmed`/`cannot-rule-out` aggregate (§4.1); digest over sanitized projection (§4.2); deterministic ordering | Article fixture → aggregate + each contributing rule; safe fixture → no HIGH + complete coverage; ambiguity never clean and never false-fact; sentinel matrix + digest-oracle tests green |
| **U5** CLI + docs | `agent-audit` dispatch (`cli.py:514` pattern), `core/agent_audit_cli.py` in `UI_ENTRY_SUFFIXES`, human/JSON presenters, exit-code composition, README row, `docs/AGENT_GUARD.md`, new `docs/SECURITY_BOUNDARIES.md` boundary section | CLI exit-code tests; `python -m compileall aurascan tests tools`; `.venv/bin/python -m pytest -q`; both presenter-coverage gates; `git diff --check` (`AGENTS.md:495-503`) |
| **U6** MCP `audit_agent_runtime` | Registry entry + `readOnlyHint`, `ALLOWED_AURASCAN` extension (documented), projection in the audit module (no presenter import, no rule-ID literals), root guard | `test_43/44/45` updated and green; `test_mcp_no_io.py` widened shim covers the new tool; `tests/test_mcp_schemas.py` + `tests/test_mcp_tools.py` parity |
| **U7** ~~Desktop view + digest binding~~ | **Deferred** | — |

**Drop from the first release:** U7 (desktop view), the "Harden this setup"
action (Slice B coupling, §6.3), `--model` URL + trust-entry store (needs the
plan's open-question-2 decision and its own boundary note; local `--model PATH`
stays in U4), and home-surface auto-discovery (explicit opt-in only). These are
all reversible additions; none is load-bearing for the article-shaped result,
which is delivered by U2–U5 alone.

---

## 9. Q7 — Options table, recommendation, what would change my mind

The load-bearing decision is the policy-reuse axis (Q1). All three options keep
the same U1–U6 sequence.

| Option | Effort | Risk | Benefit | Reversibility |
| --- | --- | --- | --- | --- |
| **O1. Extract `core/agent_policy.py`** (constants + pure predicates moved, `agent.py` imports them) | Medium (AST-identical move + full regression + mutation test) | **High** — re-opens the deliberate non-separation of `agent.py`'s fail-closed path (`docs/ARCHITECTURE.md:933`) for zero audit-side need | One vocabulary home; no import coupling to a process-capable module | Medium — verbatim-move discipline makes it undoable, but it churns a security boundary |
| **O2. Read-only import of the constant blocks + category data in the audit module + two-way parity tests** (recommended) | Low | Low — no behavior change to `agent.py`; drift caught by pinned parity tests | Satisfies goal 4 (one vocabulary); audit stays self-contained; extraction can still happen later | **High** — additive only; swap to O1 later without touching audit logic |
| **O3. Duplicate the policy vocabulary in the audit module** | Low | Medium — silent divergence from the repair-agent deny list over time; contradicts plan goal 4 | Zero coupling | High per-file, but drift is discovered late (in production, by a reviewer) |

**Unconditional recommendation: O2.** It is the only option that changes no
security boundary, keeps the audit buildable inside Slice A's budget, and makes
divergence a test failure instead of a production surprise. O1 is a legitimate
*future* standalone change under the repo's verbatim-move discipline; O3 is
acceptable only for strings the audit must own anyway (its own fixed reason
texts, surface names).

**What would change my mind:** (a) if an import-time tripwire test shows
`import aurascan.core.agent` has observable side effects or drags a
network/process call into the MCP server's import closure, O2's coupling
argument collapses and O1 (verbatim constant-only move, functions untouched)
becomes the recommendation; (b) if the Red review demonstrates a concrete
bypass that lives specifically in the shared constants (e.g. a sensitive-path
class the audit needs but `agent.py` must not have), the vocabulary boundary
must be redrawn per-surface rather than shared, and I would re-review.

---

## 10. Interfaces the implementer should produce

```
aurascan/core/agent_runtime_audit.py      # discovery, bounded parsers, policy,
                                          # aggregate, report builder, report_to_dict
aurascan/core/agent_audit_cli.py          # CLI entry (UI_ENTRY_SUFFIXES member)
aurascan/mcp/tools/audit_agent_runtime.py # thin adapter: guards + projection call only
aurascan/core/rule_metadata.py            # + 6 rule entries (edit)
aurascan/core/presenter.py                # + MEDIUM+ templates (edit)
tests/test_agent_runtime_audit.py         # U2-U4 fixtures + tripwire + sentinel matrix
tests/test_mcp_schemas.py, test_mcp_tools.py, test_mcp_architecture.py,
tests/test_mcp_no_io.py                   # extended (edits)
docs/AGENT_GUARD.md, docs/SECURITY_BOUNDARIES.md (new boundary section),
README.md (capability row)                # docs
```

Schema sketch (v1.0, additive fields only):

```json
{
  "schema": "agent-runtime-audit/1.0",
  "root": "<sanitized>", "surfaces": [{"surface": "codex", "sanitized_path": "...",
    "sha256_prefix": "...", "status": "inspected|incomplete|skipped", "reason": "..."}],
  "facts": {
    "model_ref": {"kind": "...", "sanitized_locator": "...", "pinned": false,
                  "trust_entry": {"state": "absent"}},
    "exec_authority": {"observed": true, "evidence": "observed",
                       "approval_mode": {"normalized": "never", "raw": "..."}},
    "secret_classes": [{"class": "ssh-private-key", "count": 1, "evidence": "observed"}],
    "egress": {"state": "unrestricted|denied|unknown", "evidence": "observed"}
  },
  "findings": [{"rule_id": "...", "severity": "...", "confidence": "...",
                "evidence": "observed|inferred|unknown", "reason_id": "...",
                "source": {"surface": "...", "sanitized_path": "...",
                           "line_start": 0, "line_end": 0, "sha256_prefix": "..."}}],
  "aggregate": {"rule_id": "AGENT-CREDENTIAL-EXFIL-RISK-001",
                "status": "confirmed|cannot-rule-out|not-observed",
                "contributing": ["..."]},
  "coverage": {"inspected": ["..."], "not_inspected": ["..."], "reasons": ["..."]},
  "not_verified": ["..."],
  "evidence_digest": "<digest of THIS sanitized projection>"
}
```

## 11. Acceptance criteria (the Reviewer's checklist)

1. `tests/test_agent.py` (46 tests) passes **unmodified**; `git diff` touches
   no `aurascan/core/agent.py`.
2. Two-way category parity tests exist and the mutation probe (delete one deny
   entry) fails exactly those tests.
3. Article-shaped fixture fires `AGENT-CREDENTIAL-EXFIL-RISK-001` with status
   `confirmed` and each contributing rule; safe fixture yields no HIGH and a
   complete coverage record.
4. No output anywhere (JSON, human, MCP, errors, coverage text) asserts an
   unobserved fact: no HIGH with `evidence: unknown`; ambiguity yields
   `cannot-rule-out` + coverage, never "unrestricted".
5. Tripwire run (widened shim + `sys.addaudithook`) shows zero process and zero
   network events for CLI and MCP, including with a remote `--model`.
6. Sentinel matrix (values, keys, comments, filenames, link targets, escapes,
   error strings) — sentinel absent from every output surface.
7. FIFO/symlink/TOCTOU/permission fixtures produce typed coverage failures in
   bounded time; secret-store paths are never opened (audit-hook proof).
8. Exit codes 0/1/2/3/4 behave per the documented composition; hostile input
   never reaches 4.
9. `ALLOWED_AURASCAN` extension is documented in the plan/docs; `test_43/44/45`
   green; MCP tool is `readOnlyHint: true` and writes no state root.
10. Full source gates pass: `python -m compileall aurascan tests tools`,
    `.venv/bin/python -m pytest -q`,
    `tools/audit_presenter_coverage.py --strict` and `--strict-medium`,
    `git diff --check`.
11. Docs agree: README row, `docs/AGENT_GUARD.md`, new
    `SECURITY_BOUNDARIES.md` boundary, and the report's own `not_verified`
    wording never claim detection of a backdoor, containment, or safety.

## 12. `not_verified`

- The ProjectDiscovery article's empirical claims (100% trigger fire / clean
  accuracy, LoRA size) — accepted as recorded in
  `findings/agent-guard/article-notes.md:12-14`; the payload was not run and
  the source not fetched (per `article-notes.md:26-32`).
- Vendor config formats (Codex TOML, Claude settings, Cursor JSONC) — not
  verified against vendor docs; only the in-tree CodeWhale TOML subset
  (`aurascan/core/agent_config.py`) was verified. The JSONC concern in §5 is
  `[Speculation]`.
- Import-time purity of `core.agent` — verified statically only (module-level
  defs; eager import precedent at `aurascan/cli.py:9`); not proven by an
  import tripwire.
- Exact role of `instruction_guard.py:5720` (cited by the plan) — the
  neighborhood was read; the precise anchor semantics were not audited.
- `desktop/electron/main.cjs` source — the contract document
  (`docs/DESKTOP_CONTROL_CENTER.md`) was read, not the Electron code.
- `tests/test_agent.py` internals — line/test counts executed (1787/46), the
  individual deny-rule coverage was not enumerated.
- The Red review (`20-red-review.md`, sibling card t_381dbe8e) was not yet
  written; this review does not account for it.
- No test suite, tool, or build was executed (read-only review). All claims are
  from static reads of the cited paths.

## 13. Verdict

**APPROVE WITH CONDITIONS** — for the plan as a design input. The plan's
threat framing, non-goals and slice split are sound; Slice A is the right
smallest slice and the article's demo is handled honestly (facts, not trigger
detection). The conditions, all confined to Slice A design text:

1. Split observed vs unproven in every rule; aggregate gains
   `confirmed`/`cannot-rule-out`; no HIGH finding asserts an unobserved fact
   (§4.1, §4.3).
2. Count MCP stdio `command`/`args` surfaces as exec authority (§4.2).
3. Resolve open question 3 as O2: no `agent.py` function extraction in Slice A;
   constants imported read-only with two-way parity tests (§3).
4. Resolve open question 1 as explicit-first: `--root` + explicit surface
   opt-in outside it; MCP v1 project-root-scope only (or disclosed
   `include_home_surfaces`) (§5, §6.2).
5. Cut the desktop "Harden this setup" action and the `agent-guard`-profile
   terminal handoff from Slice A; defer the desktop view to U7 (§6.3, §8).
6. Declare the digest scope (sanitized projection), the
   `ALLOWED_AURASCAN` extension, and the exit-code composition as explicit
   design decisions (§4.4, §6.2).
7. Add the twelve adversarial probe classes in §7 to the test plan; widen the
   `test_mcp_no_io.py` shim (Popen/os.exec*/socket beyond
   `create_connection`).

Commands and paths used (all read-only):
`read_file` on `design/agent-guard-plan.md`, `findings/agent-guard/article-notes.md`,
`docs/ARCHITECTURE.md`, `docs/SECURITY_BOUNDARIES.md`, `docs/DESKTOP_CONTROL_CENTER.md`,
`aurascan/mcp/registry.py`, `aurascan/mcp/tools/audit_agent_config.py`,
`aurascan/core/agent_config.py`, and `aurascan/core/agent.py` ranges 120-464,
926-1135, 1565-1729; `terminal` (grep/sed/wc/ls) on `aurascan/core/agent.py`,
`aurascan/core/instruction_guard.py` (lines 4196-4215, 5712-5728),
`aurascan/mcp/guards.py`, `tools/architecture_audit.py` (lines 100-160),
`tests/test_mcp_architecture.py`, `tests/test_mcp_no_io.py`, `tests/test_agent.py`,
`aurascan/cli.py`, `aurascan/core/rule_metadata.py`,
`tools/audit_presenter_coverage.py`, `AGENTS.md`, `git status --porcelain`.
