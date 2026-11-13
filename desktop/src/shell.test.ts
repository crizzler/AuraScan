import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));
const helpers = require("../electron/argv.cjs") as {
  CONTRACT: string;
  PACKAGED_CLI: string;
  MAX_OUTPUT_BYTES: number;
  MAX_SECRET_CHARS: number;
  MAX_CANDIDATES: number;
  MAX_PROVIDERS: number;
  MAX_FINDINGS_SHELL: number;
  AGENT_SURFACES: readonly string[];
  INCIDENT_TIMEOUT_MS: number;
  SNAPSHOT_TIMEOUT_MS: number;
  READ_ONLY_ACTIONS: readonly string[];
  MUTATING_ACTIONS: readonly string[];
  validBaseUrl: (value: unknown) => boolean;
  resolveCli: (isPackaged: boolean, env: Record<string, string | undefined>) => string;
  buildEnv: (env: Record<string, string | undefined>) => Record<string, string>;
  actionArgv: (id: string, values?: Record<string, unknown>) => string[] | null;
  validSecret: (value: unknown) => boolean;
  parseSnapshot: (stdout: string) => { contract: string };
  parseSettings: (stdout: string) => { schema: string };
  parseSettingsWrite: (stdout: string) => { schema: string; stored: boolean; action?: string };
  parseReview: (stdout: string) => { schema: string; report_id: string };
  parseInstructionAction: (stdout: string) => { status: string; file_id: string };
  parseIncidents: (stdout: string) => { schema: string; incident_id: string };
  parseAgentAudit: (stdout: string) => { schema: string; surface: string; secret_classes: unknown[]; finding_counts: Record<string, number> };
  TERMINAL_CANDIDATES: ReadonlyArray<{ name: string; prefix: string[] }>;
  upgradeTerminalArgv: (terminalPath: string, terminalName: string) => string[] | null;
  requestedView: (argv: string[]) => string | null;
};

describe("shell CLI resolution", () => {
  it("pins the packaged binary path", () => {
    expect(helpers.resolveCli(true, { AURASCAN_DESKTOP_BIN: "/tmp/evil" })).toBe(
      helpers.PACKAGED_CLI
    );
    expect(helpers.resolveCli(false, {})).toBe(helpers.PACKAGED_CLI);
  });

  it("accepts only an absolute development override", () => {
    expect(helpers.resolveCli(false, { AURASCAN_DESKTOP_BIN: "/tmp/aurascan" })).toBe(
      "/tmp/aurascan"
    );
    expect(helpers.resolveCli(false, { AURASCAN_DESKTOP_BIN: "aurascan" })).toBe(
      helpers.PACKAGED_CLI
    );
    expect(helpers.resolveCli(false, { AURASCAN_DESKTOP_BIN: "-rf" })).toBe(
      helpers.PACKAGED_CLI
    );
  });
});

describe("shell child environment", () => {
  it("forwards only the documented variables", () => {
    const env = helpers.buildEnv({
      HOME: "/home/example",
      XDG_CONFIG_HOME: "/home/example/.config",
      AURASCAN_AI_ENABLED: "1",
      AURASCAN_DEEPSEEK_API_KEY: "secret",
      LD_PRELOAD: "/tmp/evil.so",
      PATH: "/tmp/bin"
    });

    expect(env.HOME).toBe("/home/example");
    expect(env.XDG_CONFIG_HOME).toBe("/home/example/.config");
    expect(env.PATH).toBe("/usr/bin:/bin");
    expect(env.AURASCAN_AI_ENABLED).toBeUndefined();
    expect(env.AURASCAN_DEEPSEEK_API_KEY).toBeUndefined();
    expect(env.LD_PRELOAD).toBeUndefined();
  });
});

describe("shell action argv", () => {
  it("builds only the fixed read-only actions", () => {
    expect(helpers.READ_ONLY_ACTIONS).toEqual([
      "refresh_snapshot",
      "project_report",
      "read_settings",
      "instruction_review",
      "agent_audit",
      "npm_audit"
    ]);
    expect(helpers.actionArgv("refresh_snapshot")).toEqual(["ui", "--json"]);
    expect(helpers.actionArgv("read_settings")).toEqual(["settings", "--json"]);
    expect(
      helpers.actionArgv("set_ai_key", { provider: "deepseek" })
    ).toEqual(["settings", "set-ai-key", "--provider", "deepseek", "--json"]);
    // The provider list is the CLI's; the shell only checks the shape.
    expect(helpers.actionArgv("set_ai_key", { provider: "venice" })).toEqual([
      "settings",
      "set-ai-key",
      "--provider",
      "venice",
      "--json"
    ]);
    expect(helpers.actionArgv("set_ai_key", { provider: "Nope!" })).toBeNull();
    expect(helpers.actionArgv("set_ai_key", { provider: "-oops" })).toBeNull();
    expect(helpers.MUTATING_ACTIONS).toEqual([
      "set_ai_key",
      "configure_ai",
      "instruction_scan",
      "instruction_approve",
      "instruction_disable",
      "incident_scan",
      "incident_resolve"
    ]);
    expect(helpers.validSecret("sk-1234567890")).toBe(true);
    expect(helpers.validSecret("sk-123\n456")).toBe(false);
    expect(helpers.validSecret("x".repeat(helpers.MAX_SECRET_CHARS + 1))).toBe(false);
    expect(
      helpers.actionArgv("project_report", { report_path: "/tmp/report.json" })
    ).toEqual(["ui", "--report", "/tmp/report.json", "--json"]);
    expect(helpers.actionArgv("agent_audit", { root_path: "/tmp/project", surface: "codex" })).toEqual([
      "agent-audit",
      "--root",
      "/tmp/project",
      "--surface",
      "codex",
      "--json"
    ]);
    expect(helpers.actionArgv("agent_audit", { root_path: "relative", surface: "codex" })).toBeNull();
    expect(helpers.actionArgv("agent_audit", { root_path: "/tmp/project", surface: "other" })).toBeNull();
  });

  it("refuses anything else", () => {
    expect(helpers.actionArgv("scan_package", { package_path: "/tmp/pkg" })).toBeNull();
    expect(helpers.actionArgv("exec", { command: "rm -rf /" })).toBeNull();
    expect(helpers.actionArgv("project_report", { report_path: "report.json" })).toBeNull();
    expect(helpers.actionArgv("project_report", { report_path: "-oops" })).toBeNull();
    expect(helpers.actionArgv("project_report", { report_path: "/tmp/a\u0000b" })).toBeNull();
  });

  it("builds the Instruction Guard operations with bound evidence", () => {
    const fileId = "d0d36c7a141a6ceb7c30e1b1";
    const reportId = "report-be8350d1b3a0e04b8bb85cca";
    const sha = "a".repeat(64);

    expect(helpers.actionArgv("instruction_review")).toEqual([
      "instruction-audit",
      "--review",
      "--json"
    ]);
    expect(helpers.actionArgv("instruction_scan")).toEqual(["instruction-audit", "--json"]);
    expect(
      helpers.actionArgv("instruction_approve", { file_id: fileId, report_id: reportId, sha256: sha })
    ).toEqual([
      "instruction-audit",
      "--approve",
      fileId,
      "--expect-report-id",
      reportId,
      "--expect-sha256",
      sha,
      "--json"
    ]);
    expect(
      helpers.actionArgv("instruction_disable", { file_id: fileId, report_id: reportId, sha256: sha })
    ).toEqual([
      "instruction-audit",
      "--disable",
      fileId,
      "--expect-report-id",
      reportId,
      "--expect-sha256",
      sha,
      "--json",
      "--yes"
    ]);
  });

  it("builds the incident operations", () => {
    expect(helpers.actionArgv("incident_scan")).toEqual(["incidents", "--json"]);
    expect(helpers.actionArgv("incident_resolve")).toEqual([
      "incidents",
      "--resolve",
      "--json"
    ]);
    expect(helpers.INCIDENT_TIMEOUT_MS).toBeGreaterThan(helpers.SNAPSHOT_TIMEOUT_MS);
  });

  it("projects an agent audit to aggregate facts without paths", () => {
    const raw = {
      schema: "agent-runtime-audit/1.0",
      surface: "codex",
      banner: "This is not a model-safety verdict.",
      captured_at: "2026-11-14T00:00:00Z",
      coverage_complete: true,
      facts: {
        execution_authority: {
          observed: true,
          channels: [{ kind: "shell-tool", source: { path: "/home/example/.codex/config.toml" } }],
          approval_mode: { normalized: "never" }
        },
        secret_classes_readable: [{ class: "project-env", count: 1 }],
        host_isolation: { state: "unknown" }
      },
      findings: [
        { rule_id: "AGENT-EXEC-AUTHORITY-001", severity: "HIGH" },
        { rule_id: "AGENT-SECRET-CLASS-READABLE-001", severity: "MEDIUM" }
      ],
      aggregate: { status: "cannot-rule-out" },
      evidence_digest: "a".repeat(64),
      root: "/home/example/project",
      inputs: [{ path: "/home/example/.codex/config.toml" }]
    };
    const projected = helpers.parseAgentAudit(JSON.stringify(raw));
    expect(projected.surface).toBe("codex");
    expect(projected.secret_classes).toEqual([{ class: "project-env", count: 1 }]);
    expect(projected.finding_counts).toEqual({ LOW: 0, MEDIUM: 1, HIGH: 1, CRITICAL: 0 });
    expect(JSON.stringify(projected)).not.toContain("/home/example");
  });

  it("builds a fixed upgrade wizard argv for known terminals", () => {
    expect(helpers.upgradeTerminalArgv("/usr/bin/konsole", "konsole")).toEqual([
      "/usr/bin/konsole",
      "-e",
      "/usr/bin/aurascan",
      "upgrade"
    ]);
    expect(helpers.upgradeTerminalArgv("/usr/bin/xdg-terminal-exec", "xdg-terminal-exec")).toEqual([
      "/usr/bin/xdg-terminal-exec",
      "/usr/bin/aurascan",
      "upgrade"
    ]);
    expect(helpers.upgradeTerminalArgv("/usr/bin/gnome-terminal", "gnome-terminal")).toEqual([
      "/usr/bin/gnome-terminal",
      "--",
      "/usr/bin/aurascan",
      "upgrade"
    ]);
    expect(helpers.upgradeTerminalArgv("konsole", "konsole")).toBeNull();
    expect(helpers.upgradeTerminalArgv("/usr/bin/konsole", "not-a-terminal")).toBeNull();
  });

  it("accepts a diagnosis payload and rejects anything else", () => {    const payload = JSON.stringify({
      schema: "incident_report/1.3",
      incident_id: "incident-20261024-222006-91fa5761fcd2-91376c6a",
      findings: []
    });
    expect(helpers.parseIncidents(payload).schema).toBe("incident_report/1.3");
    expect(() => helpers.parseIncidents(payload.replace("1.3", "1.2"))).toThrow();
    expect(() => helpers.parseIncidents(JSON.stringify({ schema: "incident_report/1.3" }))).toThrow();
    expect(() =>
      helpers.parseIncidents(
        JSON.stringify({
          schema: "incident_report/1.3",
          incident_id: "x",
          findings: new Array(helpers.MAX_FINDINGS_SHELL + 1).fill({})
        })
      )
    ).toThrow();
  });

  it("refuses an unbound or malformed instruction action", () => {
    const sha = "a".repeat(64);
    expect(helpers.actionArgv("instruction_approve", {})).toBeNull();
    expect(
      helpers.actionArgv("instruction_approve", { file_id: "../etc", report_id: "report-x", sha256: sha })
    ).toBeNull();
    expect(
      helpers.actionArgv("instruction_approve", { file_id: "d0d36c7a141a6ceb7c30e1b1", report_id: "x", sha256: sha })
    ).toBeNull();
    expect(
      helpers.actionArgv("instruction_disable", {
        file_id: "d0d36c7a141a6ceb7c30e1b1",
        report_id: "report-be8350d1b3a0e04b8bb85cca",
        sha256: "A".repeat(64)
      })
    ).toBeNull();
  });
});

describe("shell snapshot parsing", () => {
  it("accepts the contract and rejects everything else", () => {
    expect(helpers.parseSnapshot('{"contract":"aurascan-ui/1"}')).toEqual({
      contract: "aurascan-ui/1"
    });
    expect(() => helpers.parseSnapshot('{"contract":"aurascan-ui/2"}')).toThrow();
    expect(() => helpers.parseSnapshot("not json")).toThrow();
    expect(() => helpers.parseSnapshot("[]")).toThrow();
    expect(() => helpers.parseSnapshot("x".repeat(helpers.MAX_OUTPUT_BYTES + 1))).toThrow();
  });
});

describe("shell settings parsing", () => {
  const valid = JSON.stringify({
    schema: "aurascan-settings/1",
    config: { path: "~/.config/aurascan/.env", present: true, mode: "0600", mode_ok: true, readable: true },
    ai: { enabled: false, provider: "deepseek", key_present: true },
    providers: [{ id: "deepseek" }],
    features: []
  });

  it("accepts the settings schema", () => {
    expect(helpers.parseSettings(valid).schema).toBe("aurascan-settings/1");
  });

  it("rejects a different schema or a malformed envelope", () => {
    expect(() => helpers.parseSettings(valid.replace("aurascan-settings/1", "aurascan-settings/2"))).toThrow();
    expect(() => helpers.parseSettings(JSON.stringify({ schema: "aurascan-settings/1" }))).toThrow();
    expect(() =>
      helpers.parseSettings(
        JSON.stringify({
          ...JSON.parse(valid),
          providers: new Array(helpers.MAX_PROVIDERS + 1).fill({ id: "x" })
        })
      )
    ).toThrow();
    expect(() => helpers.parseSettings("[]")).toThrow();
    expect(() => helpers.parseSettings("not json")).toThrow();
  });

  it("accepts a write confirmation only when it is explicit", () => {
    const confirmation = JSON.stringify({
      schema: "aurascan-settings/1",
      action: "set_ai_key",
      stored: true,
      provider: "deepseek",
      ai: { provider: "deepseek", key_present: true }
    });

    expect(helpers.parseSettingsWrite(confirmation).stored).toBe(true);
    expect(() => helpers.parseSettingsWrite(confirmation.replace('"stored":true', '"stored":false'))).toThrow();
    // Missing, null and non-boolean markers are not confirmations.
    for (const stored of [undefined, null, "true", 1]) {
      const payload: Record<string, unknown> = {
        schema: "aurascan-settings/1",
        action: "set_ai_key",
        provider: "deepseek",
        ai: { provider: "deepseek", key_present: true }
      };
      if (stored !== undefined) {
        payload.stored = stored;
      }
      expect(() => helpers.parseSettingsWrite(JSON.stringify(payload))).toThrow();
    }
    // An unrelated action must not pass on stored alone.
    expect(() =>
      helpers.parseSettingsWrite(
        JSON.stringify({ schema: "aurascan-settings/1", action: "read_settings", stored: true, ai: { key_present: false } })
      )
    ).toThrow();
    expect(() => helpers.parseSettingsWrite(JSON.stringify({ schema: "aurascan-settings/1" }))).toThrow();
    // A write response is not a full settings payload.
    expect(() => helpers.parseSettings(confirmation)).toThrow();
  });

  it("accepts a set-ai-config confirmation too", () => {
    const confirmation = JSON.stringify({
      schema: "aurascan-settings/1",
      action: "set_ai_config",
      stored: true,
      provider: "venice",
      ai: { provider: "venice", key_present: true, enabled: true }
    });

    expect(helpers.parseSettingsWrite(confirmation).action).toBe("set_ai_config");
    expect(() =>
      helpers.parseSettingsWrite(confirmation.replace('"provider":"venice"', '"provider":"Nope!"'))
    ).toThrow();
    for (const stored of [false, undefined, "true", 1]) {
      const payload: Record<string, unknown> = {
        schema: "aurascan-settings/1",
        action: "set_ai_config",
        provider: "venice",
        ai: { provider: "venice", key_present: true }
      };
      if (stored !== undefined) {
        payload.stored = stored;
      }
      expect(() => helpers.parseSettingsWrite(JSON.stringify(payload))).toThrow();
    }
  });
});

describe("configure_ai argv", () => {
  it("builds the exact fixed argv and omits empty optional flags", () => {
    expect(
      helpers.actionArgv("configure_ai", {
        provider: "venice",
        model: "deepseek-v4-1-flash-uncensored",
        enabled: true
      })
    ).toEqual([
      "settings",
      "set-ai-config",
      "--provider",
      "venice",
      "--model",
      "deepseek-v4-1-flash-uncensored",
      "--enabled",
      "1",
      "--json"
    ]);
    expect(helpers.actionArgv("configure_ai", { provider: "openai", enabled: false })).toEqual([
      "settings",
      "set-ai-config",
      "--provider",
      "openai",
      "--enabled",
      "0",
      "--json"
    ]);
    expect(
      helpers.actionArgv("configure_ai", {
        provider: "custom",
        model: "m",
        base_url: "https://api.example.invalid/v1",
        enabled: false
      })
    ).toEqual([
      "settings",
      "set-ai-config",
      "--provider",
      "custom",
      "--model",
      "m",
      "--base-url",
      "https://api.example.invalid/v1",
      "--enabled",
      "0",
      "--json"
    ]);
  });

  it("refuses a malformed provider, model, URL or enabled flag", () => {
    expect(helpers.actionArgv("configure_ai", {})).toBeNull();
    expect(helpers.actionArgv("configure_ai", { provider: "Nope!" })).toBeNull();
    expect(helpers.actionArgv("configure_ai", { provider: "-oops" })).toBeNull();
    expect(helpers.actionArgv("configure_ai", { provider: "venice", model: "bad model" })).toBeNull();
    expect(helpers.actionArgv("configure_ai", { provider: "venice", model: "x".repeat(121) })).toBeNull();
    expect(
      helpers.actionArgv("configure_ai", { provider: "custom", base_url: "http://api.example.invalid/v1" })
    ).toBeNull();
    expect(
      helpers.actionArgv("configure_ai", { provider: "custom", base_url: "https://192.168.1.4/v1" })
    ).toBeNull();
    expect(
      helpers.actionArgv("configure_ai", { provider: "custom", base_url: "https://u:p@api.example.invalid/v1" })
    ).toBeNull();
    expect(
      helpers.actionArgv("configure_ai", { provider: "custom", base_url: "https://api.example.invalid/v1?x=1" })
    ).toBeNull();
    expect(
      helpers.actionArgv("configure_ai", { provider: "custom", base_url: "https://api.example.invalid/" + "a".repeat(500) })
    ).toBeNull();
    expect(helpers.actionArgv("configure_ai", { provider: "openai", enabled: "yes" })).toBeNull();
    // No secret ever rides in argv.
    const argv = helpers.actionArgv("configure_ai", { provider: "venice", model: "m" }) || [];
    expect(argv).not.toContain("sk-test");
  });

  it("accepts loopback literals for plain HTTP", () => {
    for (const url of [
      "http://127.0.0.1:8080/v1",
      "http://[::1]:8080/v1",
      "http://[::ffff:127.0.0.1]/v1",
      "https://api.example.invalid/v1",
      "https://api.example.invalid"
    ]) {
      expect(helpers.validBaseUrl(url)).toBe(true);
    }
  });

  it("agrees with the CLI on the shared URL case table", () => {
    // The CLI is authoritative; tests/fixtures/ai_base_url_cases.json is read by
    // tests/test_ai_provider.py too, so both layers must match on every row.
    const cases = JSON.parse(
      readFileSync(join(here, "..", "..", "tests", "fixtures", "ai_base_url_cases.json"), "utf8")
    ) as { accept: string[]; reject: string[] };

    expect(cases.accept.length).toBeGreaterThan(0);
    expect(cases.reject.length).toBeGreaterThan(0);
    for (const url of cases.accept) {
      expect([url, helpers.validBaseUrl(url)]).toEqual([url, true]);
    }
    for (const url of cases.reject) {
      expect([url, helpers.validBaseUrl(url)]).toEqual([url, false]);
    }
  });

  it("refuses dot segments and private or link-local IPv6 literals", () => {
    // The WHATWG URL parser would normalize these away before a raw check.
    expect(helpers.validBaseUrl("https://api.example.invalid/a/../v1")).toBe(false);
    expect(helpers.validBaseUrl("https://[fc00::1]/v1")).toBe(false);
    expect(helpers.validBaseUrl("https://[fe80::1]/v1")).toBe(false);
    expect(helpers.validBaseUrl("https://[::ffff:192.168.1.1]/v1")).toBe(false);
    expect(helpers.validBaseUrl("https://[2606:4700::1111]/v1")).toBe(true);
  });

  it("builds argv for every nonempty shipped default model", () => {
    const source = readFileSync(
      join(here, "..", "..", "aurascan", "core", "ai_provider.py"),
      "utf8"
    );
    const block = source.slice(source.indexOf("PROVIDERS: Dict"));
    const entries = Array.from(
      block.matchAll(
        /^ {4}"([a-z][a-z0-9_]{0,31})": AIProviderSpec\(\s*"[^"]*",\s*"[^"]*",\s*"[^"]*",\s*"([^"]*)"/gm
      )
    ).map((match) => [match[1], match[2]] as const);

    expect(entries.length).toBeGreaterThan(5);
    expect(new Map(entries).get("openrouter")).toBe("~openai/gpt-latest");
    for (const [provider, model] of entries) {
      if (model === "") {
        continue;
      }
      const argv = helpers.actionArgv("configure_ai", { provider, model, enabled: false });
      expect([provider, argv === null]).toEqual([provider, false]);
      expect(argv).toContain(model);
    }
  });

  it("keeps parity with every provider the CLI ships", () => {
    const source = readFileSync(
      join(here, "..", "..", "aurascan", "core", "ai_provider.py"),
      "utf8"
    );
    const block = source.slice(source.indexOf("PROVIDERS: Dict"));
    const ids = Array.from(block.matchAll(/^ {4}"([a-z][a-z0-9_]{0,31})": AIProviderSpec/gm)).map(
      (match) => match[1]
    );

    expect(ids).toEqual(
      expect.arrayContaining([
        "openai",
        "anthropic",
        "deepseek",
        "gemini",
        "openrouter",
        "venice",
        "refuseless",
        "experientiallabs",
        "apinex",
        "xiaomi",
        "custom",
        "lmstudio",
        "llamacpp"
      ])
    );
    for (const id of ids) {
      expect(helpers.actionArgv("set_ai_key", { provider: id })).not.toBeNull();
      expect(helpers.actionArgv("configure_ai", { provider: id })).not.toBeNull();
    }
  });
});
