import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const mainSource = readFileSync(join(here, "..", "electron", "main.cjs"), "utf8");
const preloadSource = readFileSync(join(here, "..", "electron", "preload.cjs"), "utf8");

describe("desktop shell boundary", () => {
  it("hardens every renderer", () => {
    for (const setting of [
      "contextIsolation: true",
      "sandbox: true",
      "nodeIntegration: false",
      "webviewTag: false",
      "webSecurity: true",
      "allowRunningInsecureContent: false"
    ]) {
      expect(mainSource).toContain(setting);
    }
  });

  it("denies popups, navigation and webviews", () => {
    expect(mainSource).toContain("setWindowOpenHandler");
    expect(mainSource).toContain('{ action: "deny" }');
    expect(mainSource).toContain('"will-navigate"');
    expect(mainSource).toContain('"will-attach-webview"');
    expect(mainSource).toContain("setPermissionRequestHandler");
  });

  it("never uses a shell, an auto-updater or a free-form command", () => {
    for (const forbidden of [
      "shell.openExternal",
      "autoUpdater",
      "exec(",
      "execSync",
      "shell: true",
      "electron-updater"
    ]) {
      expect(mainSource).not.toContain(forbidden);
    }
  });

  it("exposes only the two frozen bridge operations", () => {
    expect(preloadSource).toContain("Object.freeze");
    expect(preloadSource).toContain("aurascan:refresh");
    expect(preloadSource).toContain("aurascan:open-report");
    expect(preloadSource).not.toContain("ipcRenderer.send");
    expect(preloadSource).not.toContain("child_process");
  });
});
