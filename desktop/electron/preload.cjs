"use strict";

/**
 * Minimal preload bridge. The renderer gets two fixed operations and nothing
 * else: refresh the live snapshot, or open a report the user chooses in a
 * native dialog. Paths never reach the renderer.
 */

const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld(
  "aurascanDesktop",
  Object.freeze({
    refresh: () => ipcRenderer.invoke("aurascan:refresh"),
    openReport: () => ipcRenderer.invoke("aurascan:open-report")
  })
);
