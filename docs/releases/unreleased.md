# AuraScan Unreleased

Changes after v0.7.1 will be recorded here.

- Follow-up sessions now print deterministic local probe results before AI
  commentary and enforce a final, no-more-probes review pass so a completed
  hardware check cannot be presented as a future request.
- Upgrade preflight now detects Shelly 3's `upgrade all` and `list-updates aur`
  command family while retaining a syntax-checked fallback for Shelly 2, so the
  verified preflight command is also the command used for the final handoff.
