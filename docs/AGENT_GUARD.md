# Agent Guard: runtime blast-radius audit

`aurascan agent-audit` is a read-only preflight for external AI coding agents.
It answers one narrow question:

> For this project root and this selected agent surface, what execution
> authority exists and which project secret classes can that authority read?

It does not detect a backdoored model. A model can pass every check in this
report and still be malicious. The command does not run the agent, a model, an
MCP server, a hook, a command, or project code.

## Usage

```bash
aurascan agent-audit --root . --surface codex
aurascan agent-audit --root . --surface claude --json
aurascan agent-audit --root . --surface cursor --explain
aurascan agent-audit --root . --surface mcp
```

`--root` defaults to the current directory. `--surface` is required; there is
no automatic discovery. Only the surface's known project files are read. Root
can also be an explicitly chosen home directory (for example `--root ~` when
the agent stores its config at home level); AuraScan never adds a home path on
its own, and the candidate secret classes are then evaluated under that chosen
root. A missing supported layer is incomplete coverage, not evidence that the
layer is absent or neutral.

| Surface | Project files inspected |
| --- | --- |
| `codex` | `.codex/config.toml` |
| `claude` | `.claude/settings.json`, `.claude/settings.local.json` |
| `cursor` | `.cursor/mcp.json`, `.cursor/permissions.json`, `.cursor/hooks.json` |
| `mcp` | `.mcp.json` |

## Reported facts

- **Execution authority**: a built-in shell/exec tool for Codex, Claude Code,
  or Cursor; a lifecycle hook command; or an MCP stdio `command`.
- **Readable project secret classes**: fixed project-relative candidates for
  environment files, VCS/package credentials, agent auth stores, SSH private
  keys, and cloud credentials. Only class names and counts are reported. Values
  and paths are never emitted.
- **Host isolation**: A0 has no OS-level proof, so it reports `unknown` rather
  than treating a declared sandbox flag as containment.
- **Coverage**: parsed, incomplete, missing, and out-of-scope layers, including
  unsupported syntax, duplicate keys, symlinks, non-regular files, permission
  failures, and size/depth bounds.

Execution authority for Codex, Claude Code, and Cursor includes the agent's
built-in shell tool. A configuration that omits an approval setting is not
treated as having no shell.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Every selected surface parsed completely and no execution authority was observed. |
| `1` | Execution authority was observed and coverage is complete. |
| `3` | A selected surface or layer was incomplete, unreadable, unsupported, or ambiguous. Takes precedence over `0` and `1`. |
| `2` | Usage error. |
| `4` | Internal schema failure. |

Do not use exit `0` as a model-safety claim. It means only that the selected
configuration files parsed and no execution authority was observed in them.

## Findings

- `AGENT-EXEC-AUTHORITY-001` (HIGH): the surface exposes execution authority.
- `AGENT-SECRET-CLASS-READABLE-001` (MEDIUM): at least one inspected project
  secret class is readable by the account that would run the agent.
- `AGENT-RUNTIME-CONFIG-INCOMPLETE-001` (MEDIUM): bounded inspection did not
  complete.
- `AGENT-CREDENTIAL-EXFIL-RISK-001` (HIGH): execution authority and a readable
  project secret class coincide while host isolation is not proven. Status is
  `confirmed`, `cannot-rule-out`, or `not-observed`.

No HIGH finding asserts an unobserved fact. Ambiguity becomes incomplete
coverage, not an invented "unrestricted" result.

## Scope limits

- Readable project secret classes are counted from fixed candidate paths. An
  env file is counted when it is a non-empty readable regular file; AuraScan
  does not read its values, so placeholder contents are not distinguished.
- Model identity, weights, adapters, tokenizer, publisher, and endpoint are not
  inspected.
- User, home, system-wide, environment, keyring, and socket credentials outside
  `--root` are not inspected.
- Declared sandbox or approval settings are claims, not proof of isolation.
- A same-UID process can change files after the snapshot; the evidence digest
  is a consistency check, not tamper protection.
- The command is not a hardened launcher and does not contain a compromised
  agent. A future launcher has separate funding and review requirements,
  including the model-channel exfiltration path.

## Example result

```text
Execution authority: OBSERVED
  - built-in shell/exec tool at .codex/config.toml:1
  - MCP stdio command at .codex/config.toml:4
Readable project secret classes:
  - project-env: 1
Host isolation: unknown (declared settings are not proof)
Aggregate: AGENT-CREDENTIAL-EXFIL-RISK-001 cannot-rule-out
```

The useful response is to remove execution channels the agent does not need,
move secrets out of the working tree, and use a dedicated low-privilege account.

## MCP and desktop surfaces

`audit_agent_runtime` exposes the same preflight to an MCP client. It audits
the server's first configured `--root` and returns aggregate counts only: no
root path, input path, channel location, secret path or digest. Start a
dedicated server root when you need a different project.

The desktop console's **Agent runtime** view asks for a directory in a native
dialog and a surface from a fixed list, then displays the aggregate report. It
is read-only, keeps the source path out of the renderer, and deliberately has no
"Harden this setup" action.
