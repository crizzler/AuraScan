"use strict";

/**
 * Pure helpers for the AuraScan desktop shell.
 *
 * This module is imported by the Electron main process and by tests. It must
 * not require "electron" or touch the filesystem, so the shell boundary can be
 * tested without a window server.
 */

const path = require("node:path");

const CONTRACT = "aurascan-ui/1";
const PACKAGED_CLI = "/usr/bin/aurascan";
const MAX_OUTPUT_BYTES = 8 * 1024 * 1024;
const SNAPSHOT_TIMEOUT_MS = 20000;
const CONTROL_CHARS = /[\x00-\x1f\x7f]/;

// Only these variables reach the child process. In particular no AURASCAN_AI_*
// or provider key variables are forwarded from the shell environment; the CLI
// still reads the user's own configuration file.
const FORWARDED_ENV = [
  "HOME",
  "LANG",
  "LC_ALL",
  "TZ",
  "XDG_CONFIG_HOME",
  "XDG_STATE_HOME",
  "XDG_CACHE_HOME",
  "XDG_RUNTIME_DIR"
];

// The only actions the shell may run. They are read-only and map to fixed argv.
const READ_ONLY_ACTIONS = Object.freeze(["refresh_snapshot", "project_report"]);

function resolveCli(isPackaged, env) {
  if (isPackaged) {
    return PACKAGED_CLI;
  }
  const override = env && env.AURASCAN_DESKTOP_BIN;
  if (
    typeof override === "string" &&
    path.isAbsolute(override) &&
    !CONTROL_CHARS.test(override) &&
    !override.startsWith("-")
  ) {
    return override;
  }
  return PACKAGED_CLI;
}

function buildEnv(env) {
  const output = { PATH: "/usr/bin:/bin", LANG: "C.UTF-8" };
  for (const key of FORWARDED_ENV) {
    const value = env && env[key];
    if (typeof value === "string" && value.length > 0 && !CONTROL_CHARS.test(value)) {
      output[key] = value;
    }
  }
  return output;
}

function validPath(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    path.isAbsolute(value) &&
    !CONTROL_CHARS.test(value) &&
    !value.startsWith("-")
  );
}

function actionArgv(actionId, values) {
  if (actionId === "refresh_snapshot") {
    return ["ui", "--json"];
  }
  if (actionId === "project_report") {
    const reportPath = values && values.report_path;
    if (!validPath(reportPath)) {
      return null;
    }
    return ["ui", "--report", reportPath, "--json"];
  }
  return null;
}

function parseSnapshot(stdout) {
  if (typeof stdout !== "string") {
    throw new Error("snapshot is not text");
  }
  if (stdout.length > MAX_OUTPUT_BYTES) {
    throw new Error("snapshot exceeds the shell bound");
  }
  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new Error("snapshot is not JSON");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("snapshot is not an object");
  }
  if (parsed.contract !== CONTRACT) {
    throw new Error("snapshot contract is not supported");
  }
  return parsed;
}

module.exports = {
  CONTRACT,
  PACKAGED_CLI,
  MAX_OUTPUT_BYTES,
  SNAPSHOT_TIMEOUT_MS,
  FORWARDED_ENV,
  READ_ONLY_ACTIONS,
  resolveCli,
  buildEnv,
  actionArgv,
  parseSnapshot
};
