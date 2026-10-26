import { afterEach, describe, expect, it } from "vitest";

import { desktopBridge } from "./desktop";

function installBridge(value: unknown) {
  (globalThis as { aurascanDesktop?: unknown }).aurascanDesktop = value;
}

afterEach(() => {
  delete (globalThis as { aurascanDesktop?: unknown }).aurascanDesktop;
});

describe("desktopBridge", () => {
  it("returns null in a browser without the preload", () => {
    expect(desktopBridge()).toBeNull();
  });

  it("rejects a partial bridge", () => {
    installBridge({ refresh: () => Promise.resolve({ ok: true, snapshot: {} }) });

    expect(desktopBridge()).toBeNull();
  });

  it("rejects a non-object bridge", () => {
    installBridge("bridge");

    expect(desktopBridge()).toBeNull();
  });

  it("forwards every fixed operation", async () => {
    const calls: string[] = [];
    const record = (name: string) => {
      calls.push(name);
      return Promise.resolve({ ok: true as const, payload: {} });
    };
    installBridge({
      refresh: () => record("refresh"),
      openReport: () => record("openReport"),
      readSettings: () => record("readSettings"),
      setAiKey: (provider: string) => record(`setAiKey:${provider}`),
      reviewInstructions: () => record("reviewInstructions"),
      scanInstructions: () => record("scanInstructions"),
      approveInstruction: (fileId: string, reportId: string, sha256: string) =>
        record(`approve:${fileId}:${reportId}:${sha256}`),
      disableInstruction: (fileId: string) => record(`disable:${fileId}`),
      scanIncidents: () => record("scanIncidents"),
      resolveIncidents: () => record("resolveIncidents"),
      openUpgrade: () => record("openUpgrade"),
      npmAudit: () => record("npmAudit")
    });

    const bridge = desktopBridge();
    if (bridge === null) {
      throw new Error("bridge should be available");
    }
    const sha = "a".repeat(64);
    await bridge.refresh();
    await bridge.openReport();
    await bridge.readSettings();
    await bridge.setAiKey("deepseek", "sk-test");
    await bridge.reviewInstructions();
    await bridge.scanInstructions();
    await bridge.approveInstruction("file-1", "report-1", sha);
    await bridge.disableInstruction("file-1", "report-1", sha);
    await bridge.scanIncidents();
    await bridge.resolveIncidents();
    await bridge.openUpgrade();
    await bridge.npmAudit();

    expect(calls).toEqual([
      "refresh",
      "openReport",
      "readSettings",
      "setAiKey:deepseek",
      "reviewInstructions",
      "scanInstructions",
      `approve:file-1:report-1:${sha}`,
      "disable:file-1",
      "scanIncidents",
      "resolveIncidents",
      "openUpgrade",
      "npmAudit"
    ]);
  });
});
