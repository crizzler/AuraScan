import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";

const require = createRequire(import.meta.url);
const helpers = require("../electron/argv.cjs") as {
  CONTRACT: string;
  PACKAGED_CLI: string;
  MAX_OUTPUT_BYTES: number;
  MAX_SECRET_CHARS: number;
  MAX_CANDIDATES: number;
  MAX_PROVIDERS: number;
  MAX_FINDINGS_SHELL: number;
  INCIDENT_TIMEOUT_MS: number;
  SNAPSHOT_TIMEOUT_MS: number;
  READ_ONLY_ACTIONS: readonly string[];
  MUTATING_ACTIONS: readonly string[];
  AI_PROVIDERS: readonly string[];
  resolveCli: (isPackaged: boolean, env: Record<string, string | undefined>) => string;
  buildEnv: (env: Record<string, string | undefined>) => Record<string, string>;
  actionArgv: (id: string, values?: Record<string, unknown>) => string[] | null;
  validSecret: (value: unknown) => boolean;
  parseSnapshot: (stdout: string) => { contract: string };
  parseSettings: (stdout: string) => { schema: string };
  parseSettingsWrite: (stdout: string) => { schema: string; stored: boolean };
  parseReview: (stdout: string) => { schema: string; report_id: string };
  parseInstructionAction: (stdout: string) => { status: string; file_id: string };
  parseIncidents: (stdout: string) => { schema: string; incident_id: string };
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
      "instruction_review"
    ]);
    expect(helpers.actionArgv("refresh_snapshot")).toEqual(["ui", "--json"]);
    expect(helpers.actionArgv("read_settings")).toEqual(["settings", "--json"]);
    expect(
      helpers.actionArgv("set_ai_key", { provider: "deepseek" })
    ).toEqual(["settings", "set-ai-key", "--provider", "deepseek", "--json"]);
    expect(helpers.actionArgv("set_ai_key", { provider: "nope" })).toBeNull();
    expect(helpers.MUTATING_ACTIONS).toEqual([
      "set_ai_key",
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

  it("accepts a diagnosis payload and rejects anything else", () => {
    const payload = JSON.stringify({
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
    expect(() => helpers.parseSettingsWrite(JSON.stringify({ schema: "aurascan-settings/1" }))).toThrow();
    // A write response is not a full settings payload.
    expect(() => helpers.parseSettings(confirmation)).toThrow();
  });
});
