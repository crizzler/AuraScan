# AuraScan Unreleased

Changes after v0.10.4.

- Agent Instruction Guard discovers repository-local CodeWhale and legacy
  DeepSeek TOML config files. Clean files remain neutral baseline work.
  Credential-bearing user-global configs are excluded from project detection
  and reads. Supported top-level shell enablement requires HIGH review; malformed or
  unsupported TOML reports incomplete coverage. Settings are never executed.
- Instruction references are checked against their containing project,
  including recursive and continued work. Escapes and credential-file targets
  are refused without reads; symlinks and ambiguous parent traversal remain
  manual-only. Findings preserve bounded line roles without source snippets.
- Security audit checks captured CodeWhale/legacy package versions against nine
  verified upstream advisories. Unknown versions, ecosystem ambiguity and
  unverified backports remain explicit; exposure does not imply exploitation
  or a currently vulnerable AUR publication.
- Source acquisition rejects option-shaped Git branch/tag fragments before Git
  runs. Inert runner-spy regressions cover decoded options and normal refs.
- Package rule version advances to `1.6.1`, and Instruction Guard analysis
  evidence to `1.3`. The private continuation cursor advances to `1.1` with legacy `1.0` reads;
  public report/AI schemas and the application release version stay unchanged.

Sources verified September 9, 2026: [CodeWhale shell authority advisory](https://github.com/Hmbown/CodeWhale/security/advisories/GHSA-gx45-xrj5-g6c4),
[instruction-path advisory](https://github.com/Hmbown/CodeWhale/security/advisories/GHSA-62f5-cp2p-vq95),
[upstream security advisories](https://github.com/Hmbown/CodeWhale/security/advisories),
[configuration scope documentation](https://github.com/Hmbown/Codewhale/blob/main/docs/CONFIGURATION.md),
and [Git checkout option semantics](https://git-scm.com/docs/git-checkout).

Release disposition: **recovery-bearing** because the Git source-acquisition
security boundary is shared with recovery. This is unreleased source work;
no fresh recovery image was built and no ISO/UKI/release gates were run.
