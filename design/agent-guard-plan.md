# Agent Guard: protecting AuraScan users from backdoored agent models

Status: A0-core, MCP and desktop projections implemented; Slice B remains unfunded
Revision: 2
Date: 2026-11-14
Owner: Arawn
Implementation evidence: `findings/agent-guard/implementation-evidence.md`
Reviews:
- architect: `design/agent-guard/10-architect-review.md` — APPROVE WITH CONDITIONS
- red: `design/agent-guard/20-red-review.md` — CHANGES REQUIRED
- reviewer: `design/agent-guard/30-reviewer-verdict.md` — CHANGES REQUESTED

This revision incorporates the accepted findings from all three reviews. A0-core
and the read-only MCP and desktop projections are implemented. Slice B and the
model-provenance/automatic-discovery work remain unfunded.

## 1. Conclusion after review

The original plan had the right threat framing but a machine-readable contract
that could report a false pass. The Reviewer adopted Red's disposition: exit 0
could be emitted for an incomplete audit, and the rule set could read an agent
configuration as if it were a complete capability inventory. The architect's
core architecture survives, with three corrections: reuse `agent.py` constants
read-only rather than extracting its policy; make discovery explicit-first; and
defer the desktop view.

The revised plan therefore funds a smaller **A0-core**:

> Tell the user, for one explicitly selected agent surface, which execution
> authority exists and which project secrets that authority can read, with
> coverage-first exit codes and no model-safety claim.

It does not detect a backdoored model. It does not contain one. It reports the
configuration facts the article's demonstration depends on and refuses to call
an incomplete audit a pass.

## 2. Threat model

ProjectDiscovery demonstrated a modified open model that keeps clean accuracy
and fires on a chosen trigger. The 7B Codex demonstration reported 100% trigger
fire rate and 100% clean accuracy. The model returned an `exec_command` tool call
that fetched and ran a remote shell payload; the payload read project `.env`
files and `~/.ssh` private keys and posted them to an out-of-band collector.
The model shipped with only a URL pointer to the payload, so the operator could
change it later without retraining.[^article]

The relevant asset is not the model file. It is the combination of:

- model or adapter identity that the user cannot verify;
- an execution path the model can drive (shell/exec tool, lifecycle hook, or
  MCP stdio server command);
- secret material readable by the agent's UID;
- a network path from the execution environment or the model channel to an
  attacker-controlled endpoint.

AuraScan cannot prove the first item safe. It can report the other three and
make the unsafe combination visible before the user runs the agent.

## 3. Verified facts about the current tree

- `aurascan/core/agent.py` implements AuraScan's own guarded repair agent. Its
  command policy rejects remote references, network clients, shells,
  interpreters, package/build tools and decoders, and refuses sensitive paths
  (`agent.py:128-292`, `926-1055`). It protects AuraScan's repair loop, not an
  external Codex, Claude Code or Cursor agent.
- `aurascan/core/instruction_guard.py` discovers and audits recognized agent
  control files as data. It records content risk and integrity, and never
  executes or imports them (`instruction_guard.py:4208`, `5720`). It already
  classifies `settings.json`, `settings.local.json`, `.mcp.json`, `mcp.json`,
  hook commands and MCP stdio `command`/`args` in its own surfaces
  (`instruction_guard.py:3798-3822`, `4156-4190`). The new audit must reuse
  that analysis rather than produce a contradictory second opinion.
- `aurascan/mcp/tools/audit_agent_config.py` is a single-document primitive,
  not a host or project inventory.
- The desktop is a fixed-action console. It does not run arbitrary commands,
  and a renderer never supplies argv (`docs/DESKTOP_CONTROL_CENTER.md:49-71`).
- AuraScan supports Python 3.8, standard library only; deterministic results
  remain authoritative and AI remains optional and advisory
  (`AGENTS.md:488`, `124-128`).
- AuraScan has no model-weight scanner, no prompt-trigger detector and no
  evidence that such a scanner would detect this class of backdoor.

## 4. Goals and non-goals

### Goals

1. Report, before the agent runs, whether the selected surface exposes
   execution authority and which project secrets that authority can read.
2. Keep the result deterministic, bounded, secret-free and useful without an
   AI provider.
3. Fail closed: incomplete or unknown coverage can never become exit 0.
4. Reuse existing policy and Instruction Guard evidence instead of inventing a
   second contradictory vocabulary.
5. Give a clear, reversible path to a hardened setup without adding a
   privileged daemon to the first slice.

### Non-goals

- Detecting a backdoor in model weights, adapters, tokenizers or prompts.
- Certifying a model, endpoint, publisher or benchmark as safe.
- Containing a model or agent. A0-core is a read-only report; Slice B is the
  only candidate for containment and is not funded here.
- Automatically deleting, quarantining or editing secrets or agent configs.
- Running, downloading or importing a model during the audit.
- Scanning a home directory automatically, starting an MCP server, or walking
  an arbitrary filesystem tree.
- Reusing the AUR devtools chroot as a general agent sandbox.

## 5. A0-core: read-only preflight

### Command

```
aurascan agent-audit --root PATH --surface codex|claude|cursor|mcp
                     [--json] [--explain]
```

`--root` is explicit and defaults to the current directory. `--surface` is
explicit; there is no automatic discovery in A0-core. Only the named surface's
known files under `--root` are read. No directory walk is permitted in the
funded slice. The exact file set for each surface is a versioned allowlist and
must be printed in `coverage`.

The command does not accept a model path or URL. Model identity and provenance
are a separate, deferred decision (see §12).

### Four reported facts

1. `execution_authority`
   - any shell/exec tool, any lifecycle hook command, any MCP stdio
     `command`/`args` presence;
   - the source layer and line, plus the normalized approval mode and the
     bounded raw token;
   - "not mentioned" is `default`/`unknown`, never `absent`.
2. `secret_classes_readable`
   - classes, scope and counts, never values or full paths;
   - A0-core scope is the selected project root; home and environment secrets
     are `not_inspected` unless a later explicit opt-in feature is added;
   - classes: project `.env`/env files, VCS/package credentials, agent auth
     stores found under the root, SSH/cloud credential files found under the
     root;
   - known non-secret examples (`.env.example`, `.env.template`,
     `.env.sample`) are inventory-excluded but listed as excluded, not
     silently dropped;
   - the report says "readable by this account's UID within the inspected
     scope," never "the agent can read every account secret";
   - inherited environment variables, socket/agent credentials, home auth
     stores and paths outside `--root` are listed in `coverage.not_inspected`
     and `not_verified`. A0-core does not claim they are covered; they are the
     next explicit scope decision, not an inferred absence.
3. `host_isolation`
   - `none`, `unknown` or `os_proven`;
   - A0-core will normally report `unknown` or `none`; it does not treat an
     agent's declared sandbox flag as proof;
   - no egress verdict is derived from configuration. `AGENT-EGRESS-*` is not
     part of A0-core; observed host egress is a Slice B concern.
4. `coverage`
   - every selected surface and layer, parsed/incomplete/skipped;
   - every unknown key, unsupported version, precedence ambiguity, symlink,
     permission failure, race, size bound and parse failure;
   - top-level `coverage_complete: true|false`;
   - `not_inspected` and `not_verified` at the top level, not only in MCP.

### Findings

A0-core uses four rules. The model-provenance rule is deferred.

| Rule | Severity | Meaning |
| --- | --- | --- |
| `AGENT-EXEC-AUTHORITY-001` | HIGH | The selected surface exposes execution authority: a shell/exec tool, a hook command, or an MCP stdio `command`. This is an observed fact, not a claim that the model is malicious. Channels are listed in evidence. |
| `AGENT-SECRET-CLASS-READABLE-001` | MEDIUM | At least one inspected project secret class is readable by the agent's UID. Count/class only; non-secret examples are excluded and listed. |
| `AGENT-RUNTIME-CONFIG-INCOMPLETE-001` | MEDIUM | A selected surface or layer could not be parsed, its precedence/default is unknown, or a bound/race/permission failure occurred. This is incomplete coverage, never "no authority." |
| `AGENT-CREDENTIAL-EXFIL-RISK-001` | HIGH | Aggregate blast-radius statement: execution authority is observed, at least one project secret class is readable, and host isolation is not proven. `status` is `confirmed`, `cannot-rule-out` or `not-observed`. |

Aggregate semantics:

- `confirmed`: execution authority, a readable project secret class and
  `host_isolation: none` are all observed.
- `cannot-rule-out`: at least one required fact is unknown. This is not a clean
  result and drives exit 3.
- `not-observed`: no execution authority or no secret class was observed.

No HIGH finding may carry `evidence: unknown`. Ambiguity produces
`AGENT-RUNTIME-CONFIG-INCOMPLETE-001` and exit 3, not an invented
"unrestricted" fact.

### Exit contract

Coverage takes precedence:

| Exit | Condition |
| --- | --- |
| `0` | Every selected surface parsed, `coverage_complete` is true, and no execution authority was observed. |
| `1` | Execution authority was observed and coverage is complete. |
| `3` | Any selected surface/layer is incomplete, unknown, unparseable, or precedence is unresolved. Takes precedence over `1` and `0`. |
| `2` | Usage or invalid input. |
| `4` | Internal schema/integrity failure; not reachable from hostile input because parsers return typed coverage errors. |

Both JSON and human output carry the mandatory banner:

> This is not a model-safety verdict. A backdoored model can pass every
> configuration check. This report describes execution authority and readable
> secrets within the inspected scope.

CI documentation keys on exit 3, not exit 0. The word "pass" is not used for a
clean run.

## 6. Report schema

`agent-runtime-audit/1.0`:

```json
{
  "schema": "agent-runtime-audit/1.0",
  "root": "<sanitized root>",
  "surface": "codex|claude|cursor|mcp",
  "captured_at": "2026-11-14T00:00:00Z",
  "inputs": [
    {"path": "<sanitized>", "dev": 1, "ino": 1, "size": 0,
     "sha256": "<full digest>", "status": "parsed|incomplete|skipped"}
  ],
  "facts": {
    "execution_authority": {
      "observed": true,
      "channels": [
        {"kind": "shell-tool|hook-command|mcp-stdio-command",
         "source": {"path": "<sanitized>", "line_start": 0, "line_end": 0}}
      ],
      "approval_mode": {"normalized": "never|ask|unknown|default",
                        "raw": "<bounded token>", "evidence": "observed|inferred|unknown"}
    },
    "secret_classes_readable": [
      {"class": "project-env|vcs-credential|agent-auth|ssh-private-key|cloud-credential",
       "scope": "project", "count": 1, "evidence": "observed|inferred|unknown"}
    ],
    "host_isolation": {"state": "none|unknown|os_proven", "evidence": "observed|inferred|unknown"}
  },
  "findings": [
    {"rule_id": "...", "severity": "...", "confidence": "...",
     "evidence": "observed|inferred|unknown", "reason_id": "...",
     "source": {"path": "<sanitized>", "line_start": 0, "line_end": 0,
                "sha256": "<full digest of the captured input>"}}
  ],
  "aggregate": {
    "rule_id": "AGENT-CREDENTIAL-EXFIL-RISK-001",
    "status": "confirmed|cannot-rule-out|not-observed",
    "contributing": ["AGENT-EXEC-AUTHORITY-001", "AGENT-SECRET-CLASS-READABLE-001"]
  },
  "coverage": {
    "selected": ["..."], "parsed": ["..."], "incomplete": ["..."],
    "not_inspected": ["..."], "coverage_complete": true,
    "reasons": ["..."]
  },
  "not_verified": ["..."],
  "evidence_digest": "<digest of this sanitized projection>"
}
```

Rules:

- The evidence digest covers the sanitized projection, not raw secret-bearing
  bytes. Raw input digests are full-length. A digest is a consistency check,
  not proof of authenticity or tamper protection under the same UID.
- `captured_at` is outside the digest and the report is explicitly a snapshot.
  Revalidation before launch belongs to Slice B.
- Every rendered string passes the existing terminal-sanitization discipline
  (`agent.py:125-127`, `1963-1964`); no ANSI, control characters or newlines in
  paths, reasons or error text.
- No secret values, full URLs with userinfo/query, raw config bodies or
  unbounded paths.

## 7. Architecture

### Modules

- `aurascan/core/agent_runtime_audit.py`: named-file resolution, bounded
  parsers, fact model, policy evaluation, coverage, report builder.
- `aurascan/core/agent_audit_cli.py`: CLI parser and human/JSON entry.
- `aurascan/core/rule_metadata.py` and `core/presenter.py`: rule entries and
  fixed reason templates.
- The MCP tool and desktop view are read-only projections delivered after the
  A0-core CLI; neither adds a hardening or command surface.

### Reuse, not extraction

A0-core does **not** edit `aurascan/core/agent.py`. It imports the constant
blocks read-only:

- `AGENT_REMOTE_REFERENCE_RE`
- `AGENT_SENSITIVE_PATH_RE`
- `AGENT_FORBIDDEN_PROGRAMS`

It adds two-way category parity tests so drift from the repair agent's
vocabulary fails a test. It does not extract `_lex_agent_command`,
`_agent_sensitive_path` or the validation chain; those are not pure predicates
and `docs/ARCHITECTURE.md:933` records why the repair boundary is deliberately
unseparated.

For hook and MCP evidence, reuse `audit_agent_config_text` read-only and its
existing evidence labels. Do not produce a second, contradictory hook
classification.

### Parsing and capture

Each surface is a strict, versioned grammar with byte, key, depth and array
limits. Unknown syntax is `AGENT-RUNTIME-CONFIG-INCOMPLETE-001`, never an
inferred safe value. Named files are resolved without following symlinks and
read with the existing no-follow, identity-bound capture pattern
(`mcp/guards.py:43-109`). No directory walker is added.

Layer precedence:

- Enumerate every supported layer for the selected surface;
- apply a documented vendor merge rule only when it is pinned in the surface
  inventory;
- if precedence is unknown, emit incomplete coverage and exit 3;
- a clean user layer never cancels an unknown project layer.

### MCP and desktop

Both projections are implemented as read-only views over the same core. The MCP
tool `audit_agent_runtime` is operator-only, uses the server's first configured
root, and returns aggregate counts only with no inspected-surface list or paths;
the MCP import allowlist was extended for the core module. The desktop
**Agent runtime** view asks for a directory in a native dialog and a fixed
surface, and has no "Harden this setup" command surface.

## 8. How the article's demo is handled

A0-core does not search for the trigger. It reports:

- `exec_command` or an equivalent shell/exec tool, or a hook/MCP stdio command,
  as execution authority;
- the project `.env` class as readable within the inspected root;
- `host_isolation: unknown` or `none`;
- therefore `AGENT-CREDENTIAL-EXFIL-RISK-001` with `confirmed` or
  `cannot-rule-out` status.

The user can then remove the project secret, remove the execution channel, or
choose a future hardened launcher. The report never says the model is safe and
never says the trigger was detected.

## 9. Test plan

The funded slice must pass these named probes. Each is a regression with
positive and negative assertions; no real credential, model, endpoint, agent,
MCP server or article payload is used.

1. **Execution/network tripwire.** Run the full CLI over the article-shaped
   fixture under a widened shim covering `subprocess.Popen/run/call/
   check_output`, `os.system/exec*/spawn*`, `pty`, `http.client` and asyncio
   connection paths, plus `sys.addaudithook` events for `subprocess.Popen`,
   `socket.connect` and `os.exec`. Assert zero events.
2. **`strace -f -e trace=network,process`** around the CLI. Assert no
   `execve` and no non-local `connect`.
3. **Sentinel matrix.** Sentinel as config value, key, comment, filename,
   symlink target, escaped bytes and over-cap boundary. Assert absence from
   JSON, human output, coverage, errors and future adapter payloads.
4. **Digest oracle.** A weak known secret in config must not be confirmable
   from any reported digest; only the sanitized projection is digested.
5. **Hang resistance.** FIFO or `/dev/zero`-class file at a config path
   produces a typed coverage failure in bounded time.
6. **TOCTOU swap.** Swap config and a secret-store symlink between resolve and
   read; assert typed `path_changed`-class coverage, no swapped bytes parsed,
   no secret target opened.
7. **Unknown-key false clean.** An approval override under an unrecognized
   vendor key is incomplete coverage, never "no shell tool observed."
8. **Defaults/omission.** Empty config for an agent with a built-in shell gives
   exit 1 or 3, never 0.
9. **Precedence.** User deny + project allow gives 1, or 3 if precedence is
   unknown, never 0.
10. **Hooks/MCP commands.** A hook command with `Bash` denied gives 1; an MCP
    stdio `command` with no tool entries gives 1.
11. **Exit-code matrix.** HIGH-only → 1; incomplete-only → 3;
    HIGH+incomplete → 3; usage → 2; schema failure → 4, unreachable from
    hostile input.
12. **Parity mutation.** Delete one deny entry from the shared vocabulary;
    exactly the two-way parity tests fail.
13. **Bounded-parser corpus and `--root /`.** Deep nesting, 2^k sizes,
    duplicate keys, NUL bytes, huge lines; `--root /` and `--root ~` stay
    bounded with explicit coverage.
14. **Aggregate calibration corpus.** A clean checkout with no project secret
    module and a deny-only/empty safe fixture must not produce the aggregate;
    the article-shaped fixture must. Run against a small named corpus before
    release; if the aggregate still fires on ordinary clean projects after the
    example/template exclusions, demote it to a baseline fact rather than ship
    a HIGH that cannot discriminate.

Additional gates:

- `tests/test_agent.py` unchanged and green; `git diff` touches no
  `aurascan/core/agent.py`.
- `python -m compileall aurascan tests tools`
- `.venv/bin/python -m pytest -q`
- `tools/audit_presenter_coverage.py --strict` and `--strict-medium`
- `git diff --check`

## 10. Build sequence

| Unit | Content | Acceptance |
| --- | --- | --- |
| U1 | Rule catalog, presenter templates, schema constants, cache/rule version bump | presenter gates and rule-ID hygiene pass |
| U2 | Bounded parsers and fact model for codex/claude/cursor/mcp; no I/O inside parsers | article, safe, malformed, duplicate-key, oversize, nested fixtures |
| U3 | Named-file resolution and no-follow capture; explicit `--root`, no walker | symlink/FIFO/TOCTOU/permission tests; tripwire shows no secret opens |
| U4 | Policy/fact evaluation, calibrated aggregate, coverage-first report builder | article fixture, safe fixture, ambiguity tests, sentinel and digest tests |
| U5 | CLI, human/JSON presenters, exit codes, docs | exit matrix, compile, full suite, presenter gates, diff check |
| U6 | MCP tool | **implemented**: `audit_agent_runtime`, aggregate-only, server-first-root |
| U7 | Desktop view | **implemented**: native-directory, read-only, no hardening action |

## 11. Options and recommendation

| Option | Effort | Benefit | Risk | Reversibility |
| --- | --- | --- | --- | --- |
| A0-core (recommended) | Medium | Reports the exact facts the article demo depends on; coverage-first; no execution or network | Static; only one selected surface; home/env secrets out of scope | High |
| A1: A0 + auto-discovery, home surfaces, model provenance/trust store | High | Broader coverage and model identity | New walker and trust-store surface; allowlist can suppress the finding; false assurance | Medium |
| B: A0 + hardened launcher | High | Shell containment and real reduction | Model-channel exfiltration remains (H9); needs OS boundary, probe matrix, mount/DLP policy | Medium |
| C: model-weight scanner | Low–medium | Weak provenance signal | Cannot detect the demonstrated backdoor; remote payload can change; misleading | High but misleading |

**Recommendation:** fund A0-core only. Do not ship C. Defer A1 and B until A0's
false-positive/false-negative record exists and the owner separately approves
the runtime boundary.

What would change this recommendation: a measured A0 corpus showing the
aggregate fires on ordinary clean checkouts after the example/template
exclusions, or a Red probe showing the named-file set can be bypassed without
an incomplete-coverage result.

## 12. Review dispositions and change log

### Architect

APPROVE WITH CONDITIONS. Accepted:

- O2 reuse: read-only constants plus two-way parity tests; no `agent.py`
  extraction.
- Explicit-first discovery; project-local named files only; no home walker in
  A0.
- Split observed vs unproven; aggregate `confirmed`/`cannot-rule-out`;
  no HIGH with unknown evidence.
- Count hooks and MCP stdio commands as execution authority.
- Standalone secret inventory MEDIUM; aggregate HIGH; examples/templates
  excluded.
- Add per-input digest, sanitized-projection digest, `captured_at`, coverage on
  CLI, exit-code composition.
- Cut desktop view and "Harden this setup" from Slice A; defer U7.
- Widen the MCP no-I/O shim and add the adversarial probe classes.

### Red

CHANGES REQUIRED. Accepted in full for A0-core:

- **B1 blocker:** coverage-first exit contract; 0 only complete and no
  execution authority; 3 for any incomplete/unknown; 3 > 1 > 0.
- **H1/H3:** defaults and layer precedence are facts; omission never means
  absence; unknown version/precedence is incomplete.
- **H2:** hooks and MCP stdio commands are execution authority, with source
  evidence.
- **H4:** secret classes include env/auth-store/VCS/package/socket classes in
  the stated scope; A0 reports project scope and marks home/env not inspected.
- **H5:** host-relative capability model; declared sandbox/egress/approval
  values are claims, not proof; no egress HIGH from ambiguity.
- **H6:** inventory separated from capability; aggregate is a calibrated
  blast-radius statement, not a malware verdict.
- **H7:** per-input digests and snapshot warning; revalidation before launch is
  Slice B.
- **H8:** model trust entries and `--model` deferred; no trust entry can
  suppress a model finding when that feature lands.
- **H9:** Slice B is not fundable on the shell-network-namespace alone; model
  channel, tool-result redaction, mount exclusions and shell-descendant wording
  are conditions.
- **H10:** MCP tool deferred; future version operator-only, aggregate counts,
  no path/surface map.
- **M1:** desktop Harden action cut.
- **M2:** no walker in A0; named-file resolution only.
- **M3:** report digest called a consistency check, not tamper protection.
- **M4:** sanitize every rendered string with the existing terminal sanitizer.
- **M5:** no model URL/path in A0; unbounded hashing deferred.
- **M6:** the 13 probes in §9.
- **L1:** "reports" not "reduces"; Instruction Guard relation stated.

### Reviewer

CHANGES REQUESTED. Adopted Red's disposition and A0 scope, with architect's O2
reuse, calibrated aggregate and U1–U5 sequencing. The plan above responds to
Blockers 1–7 from the verdict. The Reviewer stated that once those seven fixes
appear in the plan text, A0-core is fundable without a second full review round;
this revision records that state but does not claim the Reviewer has re-approved
it.

## 13. Slice B (unfunded)

A future hardened launcher must not claim containment of credentials until it
answers the model-channel path:

- shell tool result → model request → remote endpoint can exfiltrate a project
  secret without any shell network call;
- the project tree is mounted read-write, so `.env` and `.git/hooks` remain
  reachable;
- a model proxy that only logs is detection after the fact, not containment.

Minimum conditions before funding: broker the model client outside the sandbox,
redact or block secret-bearing tool results before they cross to the model,
exclude or mask secret/executable project files, use an OS boundary, and run
Red's bypass probe matrix twice (wrapper and arbitrary descendant). Until then,
the only claim is "A0 reports blast-radius facts."

## 14. Open questions

1. Which vendor surface versions must be pinned before A0 can parse defaults
   and precedence? Until pinned, unknown is coverage, not clean.
2. Should project-scope `.envrc` be treated as secret-bearing, and how should
   example/template files be enumerated without silently dropping a real file?
3. Does the first A0 corpus include enough real developer projects to calibrate
   the aggregate's noise before release?
4. Which future feature earns the next round: local model identity, home/env
   secret scope, MCP operator view, or Slice B?

## 15. Review artifacts

- `design/agent-guard/10-architect-review.md`
- `design/agent-guard/20-red-review.md`
- `design/agent-guard/30-reviewer-verdict.md`
- `findings/agent-guard/article-notes.md` (untrusted source data)

[^article]: ProjectDiscovery Research, "How abliterated models can get you
pwned", 2026-10-06.
https://projectdiscovery.io/research/how-abliterated-models-can-get-you-pwned
The article is untrusted source material; its trigger and payload were not run.
