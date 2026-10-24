import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";

const require = createRequire(import.meta.url);
const helpers = require("../electron/argv.cjs") as {
  CONTRACT: string;
  PACKAGED_CLI: string;
  MAX_OUTPUT_BYTES: number;
  READ_ONLY_ACTIONS: readonly string[];
  resolveCli: (isPackaged: boolean, env: Record<string, string | undefined>) => string;
  buildEnv: (env: Record<string, string | undefined>) => Record<string, string>;
  actionArgv: (id: string, values?: Record<string, unknown>) => string[] | null;
  parseSnapshot: (stdout: string) => { contract: string };
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
  it("builds only the two read-only actions", () => {
    expect(helpers.READ_ONLY_ACTIONS).toEqual(["refresh_snapshot", "project_report"]);
    expect(helpers.actionArgv("refresh_snapshot")).toEqual(["ui", "--json"]);
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
