"use strict";

/**
 * Minimal preload bridge. The renderer gets four fixed operations and nothing
 * else: refresh the live snapshot, open a report the user chooses in a native
 * dialog, read settings, or store one AI credential. It never receives a
 * command, an executable, or a path.
 */

const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld(
  "aurascanDesktop",
  Object.freeze({
    refresh: () => ipcRenderer.invoke("aurascan:refresh"),
    openReport: () => ipcRenderer.invoke("aurascan:open-report"),
    readSettings: () => ipcRenderer.invoke("aurascan:settings"),
    setAiKey: (provider, secret) =>
      ipcRenderer.invoke("aurascan:set-ai-key", provider, secret)
  })
);
