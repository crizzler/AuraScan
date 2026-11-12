# AuraScan

**Package safety checks for Arch Linux before code runs.**

AuraScan reviews PKGBUILDs, built packages, source archives, pending upgrades,
installed-system state, agent control files, and crash evidence. It reports what
it inspected, what it could not prove, and what needs a human decision.

[![AUR package](https://img.shields.io/aur/version/aurascan?label=AUR&logo=archlinux)](https://aur.archlinux.org/packages/aurascan)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Latest release](https://img.shields.io/github/v/release/crizzler/AuraScan)](https://github.com/crizzler/AuraScan/releases)

Developer preview. AuraScan reduces risk; it does not prove a package is safe.

[Quick start](#quick-start) · [What it checks](#what-it-checks) ·
[Sandboxed builds](#sandboxed-builds-and-headless-agents) ·
[Safety boundaries](#safety-boundaries) · [Documentation](#documentation) ·
[Development](#development)

## Quick start

The Arch package installs a pacman hook that audits built repository archives
before installation. Review the hook before installing if that policy does not
suit your system.

Install from the AUR:

```bash
paru -S aurascan
# or
yay -S aurascan
```

Scan a PKGBUILD before building it:

```bash
aurascan --pkgbuild ./PKGBUILD
```

Scan a built package archive:

```bash
aurascan --pkg /var/cache/pacman/pkg/example-1.0-1-x86_64.pkg.tar.zst
```

Run the optional first-time setup and check the local integration:

```bash
aurascan init
aurascan doctor
```

Preview a system upgrade without changing it:

```bash
aurascan upgrade --dry-run
```

Package scans support structured JSON:

```bash
aurascan --json --pkgbuild ./PKGBUILD
```

Installation does not enable AI, monitoring, repair services, tray autostart, or
a recovery boot entry. Those are explicit setup choices.

## What it checks

| Area | What AuraScan does | Start with |
| --- | --- | --- |
| Package metadata | Reviews PKGBUILD fields, sources, checksums, dependencies, install hooks, and suspicious build behavior. | `aurascan --pkgbuild ./PKGBUILD` |
| Package archives | Inspects built packages, metadata, scripts, and embedded install hooks without running package code. | `aurascan --pkg <archive>` |
| Source and repository provenance | Inspects declared sources, VCS checkouts, and repository paths. Explicit acquisition may use the network unless `--offline` is set. | `aurascan --deep-static --pkgbuild ./PKGBUILD` |
| Upgrade preflight | Checks pacman and AUR-helper transactions, kernel and module issues, config drift, campaigns, and AI-raised risks before handoff. | `aurascan upgrade --dry-run` |
| Installed-system audit | Compares installed packages and pacman history with bundled campaign intelligence and available advisories. | `aurascan security-audit` |
| Agent control files | Reviews Claude Code, `AGENTS.md`, and Agent Skill files as untrusted text without executing them. | `aurascan instruction-audit` |
| Incident diagnosis | Reads bounded local crash evidence and prepares guarded repair plans. | `aurascan incidents --dry-run` |
| Configuration drift | Explains `.pacnew` and `.pacsave` files and prepares fixes with backups. | `aurascan config-drift --dry-run` |

The optional recovery boot environment extends the same checks to a system that
cannot boot normally:

```bash
aurascan recovery --status
```

## How it works

AuraScan is static-first. It reads package text, metadata, and bounded local
sources as data. It does not execute package code during a normal scan, does not
follow untrusted links by default, and does not treat an uninspectable path as
safe. When a required inspection cannot complete, it fails closed and says why.

Normal scans do not fetch declared sources. `--deep-static` explicitly permits
source acquisition and may contact source hosts or a keyserver; add
`--offline --no-auto-key-fetch` to prohibit that. The makepkg wrapper is a
pre-build scanner, not a sandbox: package code still runs when the build starts.

Deterministic rules decide the result. AI is an optional advisory layer: it can
raise a finding's severity, but it cannot lower, clear, or replace a
deterministic result. Model output is schema-checked and reference-checked, and
it has no command, URL, or policy authority.

The `makepkg` wrapper scans before handing control to `makepkg`:

```bash
aurascan-makepkg -si
```

A pacman hook is installed by the Arch package and scans repository archives
during upgrades. The hook is separate from `aurascan-makepkg`: the hook sees
built archives, while the wrapper scans before `makepkg` runs.

## Desktop console and MCP

`aurascan ui --json` emits a read-only evidence snapshot. The optional desktop
console consumes that snapshot and exposes a fixed set of consented actions,
including incident acknowledgement, Instruction Guard approval or disable, and
AI provider configuration. It does not accept arbitrary commands and does not
change scan policy. The desktop package is prepared but not published.

The desktop controls and contract are documented in
[`docs/DESKTOP_CONTROL_CENTER.md`](docs/DESKTOP_CONTROL_CENTER.md).

`aurascan-mcp` exposes a small MCP surface. The default tools are read-only;
`security_audit_online` is the explicit network exception. It uses
newline-delimited JSON-RPC over stdin/stdout.

| Tool | Purpose |
| --- | --- |
| `scan_content` | Scan caller-supplied text for prompt-injection signals. |
| `scan_path` | Scan one bounded UTF-8 file inside an explicit `--root`. |
| `audit_agent_config` | Audit an agent or MCP configuration document as data. |
| `security_audit` | Check the local host offline with bounded reads. |
| `verify_evidence` | Optionally verify an evidence bundle's internal consistency. |
| `security_audit_online` | Opt in to a bounded HTTPS campaign refresh and `arch-audit`. |

Registration, explicit-root setup, and the opt-in allowlist are documented in
[MCP server](docs/REFERENCE.md#mcp-server).

The first five tools are read-only. `security_audit_online` is not: it reaches
the network, runs `arch-audit`, and may update that tool's cache. Per-call
approval is the MCP client's policy; the server advertises read-only hints for
the default tools. Scanned content and package code are never executed, blocked,
quarantined, or removed through the MCP server, but the host-audit tools do run
bounded diagnostic subprocesses such as `pacman -Q`.

## Sandboxed builds and headless agents

For reviewed AUR builds, the optional devtools sandbox runs the build in a fresh
chroot and scans every produced package archive before installation:

```bash
aurascan upgrade --aur-sandbox devtools
aurascan-makepkg --aurascan-sandbox --syncdeps --install
```

This is risk reduction, not kernel isolation. The chroot shares the host kernel,
and install hooks still run as root when the package is installed.

`aurascan-mcp` is also usable by unattended review clients. Register it with
`trust: untrusted` and a narrow include/allowlist, as shown in the
[MCP reference](docs/REFERENCE.md#mcp-server). A headless security agent or an
AI council can then use the read-only scan tools as one static input before a
human approves an install or build. AuraScan does not sandbox that agent, grant
it install authority, or turn a clean result into permission to proceed.

## Safety boundaries

AuraScan is a review and blocking layer, not an antivirus, sandbox, or proof of
safety. Keep these limits in view:

- A clean report, a clean ClamAV result, or a valid source signature does not
  guarantee that a package is safe.
- AI output is advisory interpretation. It never has command authority.
- The Policy-Gated Repair Agent proposes only allowlisted diagnostics and
  constrained package repairs. Each exact command needs fresh terminal consent.
  Remote acquisition, arbitrary executables, AUR/build tooling, interpreters,
  and dynamic code are refused.
- Agent Instruction Guard is a periodic static check. It does not block file
  access, inspect running processes, or defend against same-UID or root malware.
- AuraScan does not replace reading a PKGBUILD, checking maintainer reputation,
  reviewing links and pasted commands, or keeping backups.

The full trust model and side-effect boundaries are in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and
[`docs/SECURITY_BOUNDARIES.md`](docs/SECURITY_BOUNDARIES.md).

## Providers and privacy

AI is opt-in. Cloud and local providers can be configured in the setup wizard
or from the desktop Settings view. Supported providers include OpenAI,
Anthropic, DeepSeek, Gemini, OpenRouter, LM Studio, llama.cpp, Venice.ai,
Refuseless, ExperientialLabs, Apinex, Xiaomi MiMo, and a custom
OpenAI-compatible endpoint.

API keys stay in `~/.config/aurascan/.env` with mode `0600`. Keys are entered on
stdin and never placed in argv or logs. The desktop renderer receives presence
flags only and never receives a stored key; its fresh password field holds only
the text the user is typing until submission.
When cloud AI is enabled, package metadata, PKGBUILD text, install-script text,
and bounded diagnostic evidence may be sent to the configured provider; local
providers keep the request on loopback. Local and loopback endpoints bypass
environment proxies so a proxy cannot see the prompt or Bearer key. Public custom
endpoints keep normal environment-proxy behavior; redirects and unsafe URL shapes
are refused.

See [`docs/AI_PROVIDER_CONFIGURATION.md`](docs/AI_PROVIDER_CONFIGURATION.md) and
[`docs/PRIVACY.md`](docs/PRIVACY.md).

## Status

AuraScan is a developer preview. The current package is **0.18.0**.

The 0.18.0 release is recovery-bearing because it hardens the recovery
executor. Snapshot ids are validated before any path or argument use, and every
host tool executed as recovery root is captured at its fixed `/usr/bin/<name>`
identity and revalidated immediately before use. A fresh 0.18.0 ISO and local
validation UKI are built from the final candidate and gated before publication.
The release also carries the 0.17.0 R8 fail-closed recovery-image validation,
the 0.16.1 runtime-portability fixes, and the 0.16.0 repository-provenance
tightening at rule version `1.21.0`. Release notes, image details, gate results,
and known limits are in
[`docs/releases/v0.18.0.md`](docs/releases/v0.18.0.md).

The verified release runtime is Python 3.14. The Python 3.8 source suite also
passes locally; CI status is confirmed separately.

## Documentation

- [Long-form reference](docs/REFERENCE.md): every command group, check family,
  configuration detail, and integration behavior.
- [Architecture](docs/ARCHITECTURE.md): layers, trust boundaries, and data flow.
- [Security boundaries](docs/SECURITY_BOUNDARIES.md): what each boundary proves
  and what it does not.
- [Privacy](docs/PRIVACY.md): local data, provider traffic, and retention.
- [Desktop control center](docs/DESKTOP_CONTROL_CENTER.md): snapshot contract and
  fixed actions.
- [AI providers](docs/AI_PROVIDER_CONFIGURATION.md): presets, custom endpoints,
  proxy policy, and key storage.
- [Releases](https://github.com/crizzler/AuraScan/releases): package and recovery
  artifacts.

## Development

Clone the repository and use an isolated environment for development:

```bash
git clone https://github.com/crizzler/AuraScan.git
cd AuraScan
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[test]"
```

Activate the environment in each new shell. Run `python -m aurascan init` and
`python -m aurascan doctor` only when you want to configure host integrations.
They are not required to run the tests.

Run the core validation:

```bash
python -m compileall aurascan tests tools
python -m pytest -q
python tools/audit_presenter_coverage.py --strict
python tools/audit_presenter_coverage.py --strict-medium
```

## Contributing and security reports

Open an issue for bugs and feature requests. For a vulnerability, use a GitHub
security advisory instead of a public issue.

## License

MIT. See [LICENSE](LICENSE).
