"use strict";

/**
 * AuraScan desktop shell.
 *
 * The renderer is a pure view. This process is the only place that starts a
 * child process, and it only ever runs the fixed argument vectors in
 * ``argv.cjs`` against the packaged `/usr/bin/aurascan`. It never accepts a
 * command, an executable, or a free-form flag from the renderer.
 */

const path = require("node:path");
const { spawn } = require("node:child_process");
const { app, BrowserWindow, dialog, ipcMain, session } = require("electron");

const helpers = require("./argv.cjs");

const DEV_SERVER_ENV = "AURASCAN_DESKTOP_DEV_SERVER";
const SELF_TEST_ENV = "AURASCAN_DESKTOP_SELF_TEST";

// Match the desktop entry's StartupWMClass so the window groups correctly.
app.setName("aurascan-desktop");

function runCli(args) {
  return new Promise((resolve) => {
    let settled = false;
    let stdout = "";
    let killed = false;
    let timer = null;

    const finish = (result) => {
      if (settled) {
        return;
      }
      settled = true;
      if (timer !== null) {
        clearTimeout(timer);
      }
      resolve(result);
    };

    let child;
    try {
      child = spawn(helpers.resolveCli(app.isPackaged, process.env), args, {
        env: helpers.buildEnv(process.env),
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true
      });
    } catch {
      finish({ ok: false, error: "AuraScan could not be started" });
      return;
    }

    timer = setTimeout(() => {
      killed = true;
      child.kill("SIGKILL");
    }, helpers.SNAPSHOT_TIMEOUT_MS);

    child.stdout.on("data", (chunk) => {
      if (killed) {
        return;
      }
      stdout += chunk.toString("utf8");
      if (stdout.length > helpers.MAX_OUTPUT_BYTES) {
        killed = true;
        child.kill("SIGKILL");
      }
    });
    // Drain stderr but never store or forward it: it can contain local paths.
    child.stderr.on("data", () => {});
    child.on("error", () => finish({ ok: false, error: "AuraScan could not be started" }));
    child.on("close", (code) => {
      if (killed) {
        finish({ ok: false, error: "AuraScan did not answer in time" });
        return;
      }
      if (code !== 0) {
        finish({ ok: false, error: "AuraScan could not produce a snapshot" });
        return;
      }
      try {
        finish({ ok: true, snapshot: helpers.parseSnapshot(stdout) });
      } catch {
        finish({ ok: false, error: "AuraScan returned an unsupported snapshot" });
      }
    });
  });
}

function requestSnapshot(actionId, values) {
  const args = helpers.actionArgv(actionId, values);
  if (args === null) {
    return Promise.resolve({ ok: false, error: "Unsupported desktop action" });
  }
  return runCli(args);
}

function hardenContents(contents) {
  contents.setWindowOpenHandler(() => ({ action: "deny" }));
  contents.on("will-navigate", (event) => event.preventDefault());
  contents.on("will-attach-webview", (event) => event.preventDefault());
}

function createWindow(showWindow = true) {
  const window = new BrowserWindow({
    width: 1280,
    height: 860,
    minWidth: 940,
    minHeight: 620,
    show: false,
    backgroundColor: "#0b0d10",
    title: "AuraScan",
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      nodeIntegrationInWorker: false,
      webviewTag: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
      spellcheck: false,
      devTools: !app.isPackaged
    }
  });
  hardenContents(window.webContents);

  const devServer = process.env[DEV_SERVER_ENV];
  if (
    !app.isPackaged &&
    typeof devServer === "string" &&
    devServer.startsWith("http://127.0.0.1:")
  ) {
    window.loadURL(devServer);
  } else {
    window.loadFile(path.join(__dirname, "..", "dist", "index.html"));
  }

  window.once("ready-to-show", () => {
    if (showWindow) {
      window.show();
    }
  });
  return window;
}

function registerIpc() {
  ipcMain.handle("aurascan:refresh", () => requestSnapshot("refresh_snapshot"));

  ipcMain.handle("aurascan:open-report", async (event) => {
    const parent = BrowserWindow.fromWebContents(event.sender);
    const options = {
      title: "Open an AuraScan report",
      properties: ["openFile"],
      filters: [{ name: "AuraScan report", extensions: ["json"] }]
    };
    const result = parent
      ? await dialog.showOpenDialog(parent, options)
      : await dialog.showOpenDialog(options);
    if (result.canceled || result.filePaths.length !== 1) {
      return { ok: false, canceled: true };
    }
    return requestSnapshot("project_report", { report_path: result.filePaths[0] });
  });
}

async function runSelfTest() {
  const result = await requestSnapshot("refresh_snapshot");
  if (!result.ok) {
    console.log(`[aurascan-desktop] self-test failed error=${result.error}`);
    app.exit(1);
    return;
  }
  const checks = Array.isArray(result.snapshot.doctor?.checks)
    ? result.snapshot.doctor.checks.length
    : 0;
  console.log(
    `[aurascan-desktop] self-test ok contract=${result.snapshot.contract} checks=${checks}`
  );

  const window = createWindow(false);
  const timeout = setTimeout(() => {
    console.log("[aurascan-desktop] self-test window timeout");
    app.exit(1);
  }, 15000);
  window.webContents.once("did-finish-load", async () => {
    try {
      const state = await window.webContents.executeJavaScript(`
        new Promise((resolve) => {
          const deadline = Date.now() + 8000;
          const check = () => {
            const heading = document.querySelector(
              'main[data-snapshot-source="shell"] h1'
            );
            if (heading && heading.textContent) {
              resolve({ view: heading.textContent, danger: false });
              return;
            }
            if (Date.now() > deadline) {
              resolve({
                view: '',
                danger: Boolean(document.querySelector('.card--danger'))
              });
              return;
            }
            setTimeout(check, 50);
          };
          check();
        })
      `);
      clearTimeout(timeout);
      if (state && typeof state.view === "string" && state.view.length > 0) {
        console.log(`[aurascan-desktop] self-test window ok view=${state.view}`);
        app.exit(0);
        return;
      }
      console.log(
        `[aurascan-desktop] self-test window did not render danger=${Boolean(
          state && state.danger
        )}`
      );
      app.exit(1);
    } catch {
      clearTimeout(timeout);
      console.log("[aurascan-desktop] self-test window did not render");
      app.exit(1);
    }
  });
}

app.on("web-contents-created", (_event, contents) => hardenContents(contents));

app.whenReady().then(() => {
  session.defaultSession.setPermissionRequestHandler((_contents, _permission, callback) => {
    callback(false);
  });
  registerIpc();

  if (process.env[SELF_TEST_ENV] === "1") {
    runSelfTest();
    return;
  }

  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});
