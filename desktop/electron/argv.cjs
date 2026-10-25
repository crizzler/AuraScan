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
const SETTINGS_SCHEMA = "aurascan-settings/1";
const REVIEW_SCHEMA = "instruction_guard_report/1.0";
const INCIDENT_SCHEMA = "incident_report/1.3";
const PACKAGED_CLI = "/usr/bin/aurascan";
const MAX_OUTPUT_BYTES = 8 * 1024 * 1024;
const MAX_SECRET_CHARS = 4096;
const MAX_PROVIDERS = 32;
const MAX_FEATURES = 64;
const MAX_CANDIDATES = 200;
const MAX_FINDINGS_SHELL = 200;
const INCIDENT_TIMEOUT_MS = 90000;
const SNAPSHOT_TIMEOUT_MS = 20000;
const CONTROL_CHARS = /[\x00-\x1f\x7f]/;
const FILE_ID = /^[a-z0-9]{8,64}$/;
const REPORT_ID = /^report-[a-z0-9]{8,64}$/;
const SHA256 = /^[a-f0-9]{64}$/;

// Mirrors the provider inventory in aurascan/core/ai_provider.py. A provider id
// is never taken from the renderer without being checked against this list.
const AI_PROVIDERS = Object.freeze([
  "openai",
  "anthropic",
  "deepseek",
  "gemini",
  "openrouter",
  "lmstudio",
  "llamacpp"
]);

// The tray may ask the shell to open a specific view. Only these names are
// accepted; anything else is ignored, so an argument can never become data the
// renderer acts on.
const DESKTOP_VIEWS = Object.freeze([
  "report",
  "actions",
  "overview",
  "checks",
  "incidents",
  "instructions",
  "settings",
  "about"
]);

function requestedView(argv) {
  const args = Array.isArray(argv) ? argv : [];
  for (let index = 0; index < args.length; index += 1) {
    const value = args[index];
    if (typeof value !== "string") {
      continue;
    }
    let candidate = "";
    if (value === "--view") {
      const next = args[index + 1];
      candidate = typeof next === "string" ? next : "";
    } else if (value.startsWith("--view=")) {
      candidate = value.slice("--view=".length);
    } else {
      continue;
    }
    return DESKTOP_VIEWS.includes(candidate) ? candidate : null;
  }
  return null;
}

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

// The only actions the shell may run. Read-only actions never change local
// state; the single mutating action stores one AI credential and is always
// confirmed in the renderer first.
const READ_ONLY_ACTIONS = Object.freeze([
  "refresh_snapshot",
  "project_report",
  "read_settings",
  "instruction_review"
]);
const MUTATING_ACTIONS = Object.freeze([
  "set_ai_key",
  "instruction_scan",
  "instruction_approve",
  "instruction_disable",
  "incident_scan",
  "incident_resolve"
]);

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
  if (actionId === "read_settings") {
    return ["settings", "--json"];
  }
  if (actionId === "instruction_review") {
    return ["instruction-audit", "--review", "--json"];
  }
  if (actionId === "instruction_scan") {
    return ["instruction-audit", "--json"];
  }
  if (actionId === "incident_scan") {
    return ["incidents", "--json"];
  }
  if (actionId === "incident_resolve") {
    return ["incidents", "--resolve", "--json"];
  }
  if (actionId === "instruction_approve" || actionId === "instruction_disable") {
    const fileId = values && values.file_id;
    const reportId = values && values.report_id;
    const digest = values && values.sha256;
    if (typeof fileId !== "string" || !FILE_ID.test(fileId)) {
      return null;
    }
    if (typeof reportId !== "string" || !REPORT_ID.test(reportId)) {
      return null;
    }
    if (typeof digest !== "string" || !SHA256.test(digest)) {
      return null;
    }
    const argv = [
      "instruction-audit",
      actionId === "instruction_approve" ? "--approve" : "--disable",
      fileId,
      "--expect-report-id",
      reportId,
      "--expect-sha256",
      digest,
      "--json"
    ];
    // The disable prompt is answered by the renderer's own confirmation, which
    // echoes this exact report id, file id and digest. Nothing else adds --yes.
    if (actionId === "instruction_disable") {
      argv.push("--yes");
    }
    return argv;
  }
  if (actionId === "set_ai_key") {
    const provider = values && values.provider;
    if (typeof provider !== "string" || !AI_PROVIDERS.includes(provider)) {
      return null;
    }
    return ["settings", "set-ai-key", "--provider", provider, "--json"];
  }
  return null;
}

/**
 * Accept a credential only as a bounded single line. It travels over stdin and
 * is never placed in argv, the environment, or a log line.
 */
function validSecret(value) {
  return (
    typeof value === "string" &&
    value.trim().length > 0 &&
    value.length <= MAX_SECRET_CHARS &&
    !CONTROL_CHARS.test(value)
  );
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

function parseJsonObject(stdout) {
  if (typeof stdout !== "string") {
    throw new Error("payload is not text");
  }
  if (stdout.length > MAX_OUTPUT_BYTES) {
    throw new Error("payload exceeds the shell bound");
  }
  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new Error("payload is not JSON");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("payload is not an object");
  }
  return parsed;
}

/** Structural gate for `aurascan-settings/1`; the renderer validates fields. */
function parseSettings(stdout) {
  const parsed = parseJsonObject(stdout);
  if (parsed.schema !== SETTINGS_SCHEMA) {
    throw new Error("settings schema is not supported");
  }
  if (
    parsed.config === null ||
    typeof parsed.config !== "object" ||
    Array.isArray(parsed.config) ||
    parsed.ai === null ||
    typeof parsed.ai !== "object" ||
    Array.isArray(parsed.ai) ||
    !Array.isArray(parsed.providers) ||
    parsed.providers.length > MAX_PROVIDERS ||
    !Array.isArray(parsed.features) ||
    parsed.features.length > MAX_FEATURES
  ) {
    throw new Error("settings payload is malformed");
  }
  return parsed;
}

/**
 * A write response carries only the confirmation and the resulting AI state.
 * It must never be treated as a full settings payload: a successful write that
 * failed to parse would otherwise be reported to the user as a failure.
 */
function parseSettingsWrite(stdout) {
  const parsed = parseJsonObject(stdout);
  if (parsed.schema !== SETTINGS_SCHEMA || parsed.stored !== true) {
    throw new Error("settings write was not confirmed");
  }
  if (
    parsed.ai === null ||
    typeof parsed.ai !== "object" ||
    Array.isArray(parsed.ai) ||
    typeof parsed.ai.key_present !== "boolean"
  ) {
    throw new Error("settings write response is malformed");
  }
  return parsed;
}

/** Structural gate for an Instruction Guard review report. */
function parseReview(stdout) {
  const parsed = parseJsonObject(stdout);
  if (parsed.schema !== REVIEW_SCHEMA) {
    throw new Error("review schema is not supported");
  }
  if (
    typeof parsed.report_id !== "string" ||
    !REPORT_ID.test(parsed.report_id) ||
    typeof parsed.review_required !== "boolean" ||
    !Array.isArray(parsed.candidates) ||
    parsed.candidates.length > MAX_CANDIDATES
  ) {
    throw new Error("review payload is malformed");
  }
  return parsed;
}

/** Structural gate for an approve or disable result. */
function parseInstructionAction(stdout) {
  const parsed = parseJsonObject(stdout);
  if (typeof parsed.status !== "string" || parsed.status.length === 0) {
    throw new Error("instruction action was not confirmed");
  }
  if (typeof parsed.file_id !== "string" || !FILE_ID.test(parsed.file_id)) {
    throw new Error("instruction action response is malformed");
  }
  return parsed;
}

/** Structural gate for an incident diagnosis report. */
function parseIncidents(stdout) {
  const parsed = parseJsonObject(stdout);
  if (parsed.schema !== INCIDENT_SCHEMA) {
    throw new Error("incident schema is not supported");
  }
  if (
    typeof parsed.incident_id !== "string" ||
    parsed.incident_id.length === 0 ||
    !Array.isArray(parsed.findings) ||
    parsed.findings.length > MAX_FINDINGS_SHELL
  ) {
    throw new Error("incident payload is malformed");
  }
  return parsed;
}

module.exports = {
  CONTRACT,
  SETTINGS_SCHEMA,
  PACKAGED_CLI,
  MAX_OUTPUT_BYTES,
  MAX_SECRET_CHARS,
  MAX_PROVIDERS,
  MAX_FEATURES,
  MAX_CANDIDATES,
  MAX_FINDINGS_SHELL,
  INCIDENT_TIMEOUT_MS,
  SNAPSHOT_TIMEOUT_MS,
  FORWARDED_ENV,
  AI_PROVIDERS,
  DESKTOP_VIEWS,
  requestedView,
  READ_ONLY_ACTIONS,
  MUTATING_ACTIONS,
  resolveCli,
  buildEnv,
  actionArgv,
  validSecret,
  parseSnapshot,
  parseSettings,
  parseSettingsWrite,
  parseReview,
  parseInstructionAction,
  parseIncidents
};
