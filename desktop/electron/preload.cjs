"use strict";

/**
 * Minimal preload bridge. The renderer gets only fixed operations: refresh the
 * live snapshot, open a report the user chooses in a native dialog, read
 * settings, store one AI credential, and review or act on Instruction Guard
 * candidates. It never receives a command, an executable, or a path.
 */

const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld(
  "aurascanDesktop",
  Object.freeze({
    refresh: () => ipcRenderer.invoke("aurascan:refresh"),
    openReport: () => ipcRenderer.invoke("aurascan:open-report"),
    readSettings: () => ipcRenderer.invoke("aurascan:settings"),
    setAiKey: (provider, secret) =>
      ipcRenderer.invoke("aurascan:set-ai-key", provider, secret),
    reviewInstructions: () => ipcRenderer.invoke("aurascan:instruction-review"),
    scanInstructions: () => ipcRenderer.invoke("aurascan:instruction-scan"),
    approveInstruction: (fileId, reportId, sha256) =>
      ipcRenderer.invoke("aurascan:instruction-approve", fileId, reportId, sha256),
    disableInstruction: (fileId, reportId, sha256) =>
      ipcRenderer.invoke("aurascan:instruction-disable", fileId, reportId, sha256),
    scanIncidents: () => ipcRenderer.invoke("aurascan:incident-scan"),
    resolveIncidents: () => ipcRenderer.invoke("aurascan:incident-resolve"),
    openUpgrade: () => ipcRenderer.invoke("aurascan:upgrade-terminal"),
    npmAudit: () => ipcRenderer.invoke("aurascan:npm-audit")
  })
);
