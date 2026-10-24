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
    installBridge({
      refresh: () => {
        calls.push("refresh");
        return Promise.resolve({ ok: true, payload: { contract: "aurascan-ui/1" } });
      },
      openReport: () => {
        calls.push("open");
        return Promise.resolve({ ok: false, canceled: true });
      },
      readSettings: () => {
        calls.push("settings");
        return Promise.resolve({ ok: true, payload: { schema: "aurascan-settings/1" } });
      },
      setAiKey: (provider: string, secret: string) => {
        calls.push(`key:${provider}:${secret}`);
        return Promise.resolve({ ok: true, payload: { stored: true } });
      }
    });

    const bridge = desktopBridge();
    if (bridge === null) {
      throw new Error("bridge should be available");
    }
    const refreshed = await bridge.refresh();
    const opened = await bridge.openReport();
    const settings = await bridge.readSettings();
    const stored = await bridge.setAiKey("deepseek", "sk-test");

    expect(calls).toEqual(["refresh", "open", "settings", "key:deepseek:sk-test"]);
    expect(refreshed).toEqual({ ok: true, payload: { contract: "aurascan-ui/1" } });
    expect(opened).toEqual({ ok: false, canceled: true });
    expect(settings).toEqual({ ok: true, payload: { schema: "aurascan-settings/1" } });
    expect(stored).toEqual({ ok: true, payload: { stored: true } });
  });
});
