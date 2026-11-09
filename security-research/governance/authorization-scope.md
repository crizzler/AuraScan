# Authorization scope — Daybreak evidence program

Baseline: `02ac13d`. Source of authority:
`findings/daybreak/PROGRAM-CHARTER.md` (§2) and
`findings/daybreak/ORCHESTRATOR-BRIEF.md` ("Non-negotiable scope for this
round"). This file restates them as the operative scope; where they conflict,
the charter and brief win.

## Authorized environments

Security testing is confined to:

1. The AuraScan repository and locally controlled development copies.
2. Purpose-built malicious test fixtures (inert, defanged: `example.invalid`,
   synthetic credentials, temporary roots — per `AGENTS.md`).
3. Disposable virtual machines or containers explicitly provisioned for
   testing.
4. Controlled recovery images and simulated target filesystems.
5. Other environments explicitly owned and authorized by the project
   maintainer.

Authorized activities in the current round (per the orchestrator brief):

- Read-only inspection of this repository and its local development copies.
- Inert fixtures in temporary directories, synthetic credentials, and
  unit-level calls that do not execute package, hook, fixture, or agent
  instruction content.
- Existing test suites and read-only audit tools
  (e.g. `tools/architecture_audit.py --strict`).
- Web retrieval of public OpenAI and AuraScan documentation.

## Prohibited tests and activities

- Any offensive testing against third-party repositories, infrastructure,
  package registries, production machines, or external services without
  explicit authorization.
- Executing malicious fixtures on the developer's normal workstation.
- Running AUR builds, `makepkg`, package installation, `sudo`, root brokers,
  `arch-chroot`, or recovery actions (this round; see the fresh-approval rule
  below for later rounds).
- Executing package code, hooks, downloaded source, or agent instruction
  files while analyzing or testing them (`AGENTS.md`: the only sanctioned
  execution exception is the explicit opt-in isolated AUR build, which is a
  product feature, not a test tool).
- Privilege-boundary exploits against the host system.
- Destructive testing outside disposable environments.
- Disabling security controls to produce a successful attack; modifying
  expected outcomes to conceal failures.
- Fabricating vulnerabilities, attacker activity, adoption metrics, or
  benchmark results.
- Exposing real credentials, API keys, tokens, or private user information.
- Publishing working exploit artifacts or sensitive vulnerability details
  automatically.
- Changing CI permissions, release workflows, dependencies, secrets, or
  production configuration; new runtime dependencies.
- Live AI provider calls with credentials or provider spend (mocked transports
  only, unless the owner explicitly authorizes a live evaluation).
- Applying a fix to a discovered vulnerability without owner authorization —
  findings and proposed remediations go to the owner first.
- Network scanning or any traffic beyond public documentation retrieval and
  the explicitly authorized acquisition workflows of the product itself.

## Fresh-approval rule for elevated or destructive tests

**Every test that requires elevated host privileges or destructive behavior
stops and obtains fresh owner approval before execution.** Concretely:

- Approval is per test (or per tightly scoped batch with identical privilege
  needs), granted explicitly by the project maintainer — never inferred from a
  prior approval, a plan document, a charter phase, or another test's approval.
- The request states: exact commands, target environment, privilege needed,
  rollback method, and expected side effects.
- Approved elevated/destructive tests run only inside a disposable environment
  (VM preferred over container for privilege tests — containers share the host
  kernel), never on the daily workstation.
- A test that cannot obtain approval is recorded `NOT EXECUTED` with the
  reason. It is never approximated, simulated-as-executed, or silently
  downgraded into an unapproved form.
- Withdrawing approval, an ambiguous environment, or an unexpected observation
  mid-test stops the test.

## Evidence discipline

Recorded with every result (see `../README.md` "Evidence versioning and
binding"): git revision, AuraScan version, rule version, fixture SHA-256,
environment identity, exact command and exit code. A passing test establishes
the behavior of the tested configuration only.
