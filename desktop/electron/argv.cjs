"use strict";

/**
 * Pure helpers for the AuraScan desktop shell.
 *
 * This module is imported by the Electron main process and by tests. It must
 * not require "electron" or touch the filesystem, so the shell boundary can be
 * tested without a window server.
 */

const path = require("node:path");
const net = require("node:net");

const CONTRACT = "aurascan-ui/1";
const SETTINGS_SCHEMA = "aurascan-settings/1";
const REVIEW_SCHEMA = "instruction_guard_report/1.0";
const INCIDENT_SCHEMA = "incident_report/1.3";
const NPM_AUDIT_SCHEMA = "aurascan-npm-audit/1";
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
// Provider ids are shape-checked here and validated against the real inventory
// by the CLI, so a new provider needs no shell release. The model shape and the
// base URL rules mirror the CLI's own validation.
const PROVIDER_ID = /^[a-z][a-z0-9_]{0,31}$/;
// Bounded model text. `~` is part of the shipped OpenRouter default
// (`~openai/gpt-latest`), which the Settings form submits unchanged.
const MODEL_ID = /^[A-Za-z0-9._~:/@+-]{1,120}$/;
const MAX_BASE_URL_CHARS = 512;

// Provider ids are validated by shape only (PROVIDER_ID) — the CLI owns the
// inventory, so adding a provider is a Python-only change. A parity test keeps
// the known presets listed in the desktop suite aligned with PROVIDERS.

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

// Terminals the shell may use for the interactive upgrade wizard. Each entry
// carries the flag that separates the emulator's own options from the command.
const TERMINAL_CANDIDATES = Object.freeze([
  { name: "xdg-terminal-exec", prefix: [] },
  { name: "konsole", prefix: ["-e"] },
  { name: "alacritty", prefix: ["-e"] },
  { name: "kitty", prefix: [] },
  { name: "gnome-terminal", prefix: ["--"] },
  { name: "xterm", prefix: ["-e"] }
]);

/** Build the fixed argv for one terminal, or null when it is not usable. */
function upgradeTerminalArgv(terminalPath, terminalName) {
  if (
    typeof terminalPath !== "string" ||
    !path.isAbsolute(terminalPath) ||
    CONTROL_CHARS.test(terminalPath)
  ) {
    return null;
  }
  const entry = TERMINAL_CANDIDATES.find((candidate) => candidate.name === terminalName);
  if (!entry) {
    return null;
  }
  return [terminalPath, ...entry.prefix, PACKAGED_CLI, "upgrade"];
}

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
  "instruction_review",
  "npm_audit"
]);
const MUTATING_ACTIONS = Object.freeze([
  "set_ai_key",
  "configure_ai",
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
  if (actionId === "npm_audit") {
    const projectPath = values && values.project_path;
    if (!validPath(projectPath)) {
      return null;
    }
    return ["npm-audit", projectPath, "--json"];
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
  if (actionId === "configure_ai") {
    const provider = values && values.provider;
    if (typeof provider !== "string" || !PROVIDER_ID.test(provider)) {
      return null;
    }
    const argv = ["settings", "set-ai-config", "--provider", provider];
    if (values.model !== undefined && values.model !== null && values.model !== "") {
      if (typeof values.model !== "string" || !MODEL_ID.test(values.model)) {
        return null;
      }
      argv.push("--model", values.model);
    }
    if (values.base_url !== undefined && values.base_url !== null && values.base_url !== "") {
      if (!validBaseUrl(values.base_url)) {
        return null;
      }
      argv.push("--base-url", values.base_url);
    }
    if (values.enabled !== undefined && values.enabled !== null) {
      if (typeof values.enabled !== "boolean") {
        return null;
      }
      argv.push("--enabled", values.enabled ? "1" : "0");
    }
    argv.push("--json");
    return argv;
  }
  if (actionId === "set_ai_key") {
    const provider = values && values.provider;
    if (typeof provider !== "string" || !PROVIDER_ID.test(provider)) {
      return null;
    }
    return ["settings", "set-ai-key", "--provider", provider, "--json"];
  }
  return null;
}

/**
 * Accept only a base URL the CLI would also accept: http(s), no credentials,
 * query or fragment, bounded length, plain HTTP only on a loopback literal and
 * no literal private address. The CLI revalidates the stored value and stays
 * authoritative; this pre-spawn mirror exists so a bad value is refused before
 * a child starts.
 *
 * The raw string is parsed by hand because WHATWG `URL` collapses `..` path
 * segments before any raw-path rule could see them, and the CLI validates the
 * raw path. Literal addresses are classified the way `ipaddress` does, so a
 * private, link-local, multicast or reserved IPv4/IPv6 literal is refused.
 */
const CUSTOM_PATH = /^[A-Za-z0-9._~%/-]*$/;
const URL_SCHEME = /^([A-Za-z][A-Za-z0-9+.-]*):\/\//;

function ipv4Parts(host) {
  const parts = host.split(".");
  if (parts.length !== 4) {
    return null;
  }
  if (!parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)) {
    return null;
  }
  return parts.map(Number);
}

function loopbackIpv4(host) {
  const parts = ipv4Parts(host);
  return parts !== null && parts[0] === 127;
}

function privateIpv4Literal(host) {
  const parts = ipv4Parts(host);
  if (parts === null) {
    return false;
  }
  const [a, b, c] = parts;
  return (
    a === 0 ||
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||
    (a === 192 && b === 0 && c === 0) ||
    (a === 192 && b === 0 && c === 2) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113) ||
    (a >= 224 && a <= 239) ||
    a >= 240
  );
}

/** Expand a validated IPv6 literal to sixteen bytes, or null. */
function ipv6Bytes(host) {
  if (!net.isIPv6(host)) {
    return null;
  }
  const [head, tail] = host.split("::");
  const left = head === "" ? [] : head.split(":");
  const right = tail === undefined || tail === "" ? [] : tail.split(":");
  // An embedded IPv4 tail occupies two groups.
  const width = (group) => (group.includes(".") ? 2 : 1);
  const used = [...left, ...right].reduce((total, group) => total + width(group), 0);
  const groups = [...left, ...new Array(8 - used).fill("0"), ...right];
  const bytes = [];
  for (let index = 0; index < groups.length; index += 1) {
    const group = groups[index];
    if (group.includes(".")) {
      const embedded = ipv4Parts(group);
      if (embedded === null) {
        return null;
      }
      bytes.push(embedded[0], embedded[1], embedded[2], embedded[3]);
      continue;
    }
    const value = parseInt(group, 16);
    bytes.push(value >> 8, value & 0xff);
  }
  return bytes.length === 16 ? bytes : null;
}

/** "loopback", "private" or "public", or null when the text is not an IPv6 literal. */
function classifyIpv6(host) {
  const bytes = ipv6Bytes(host);
  if (bytes === null) {
    return null;
  }
  const zero = (from) => bytes.slice(from).every((value) => value === 0);
  const zeroRange = (from, to) => bytes.slice(from, to).every((value) => value === 0);
  if (zeroRange(0, 15) && bytes[15] === 1) {
    return "loopback"; // ::1
  }
  if (zero(0)) {
    return "private"; // ::
  }
  if (zeroRange(0, 10) && bytes[10] === 0xff && bytes[11] === 0xff) {
    // IPv4-mapped address: classify the embedded IPv4 literal instead.
    const embedded = `${bytes[12]}.${bytes[13]}.${bytes[14]}.${bytes[15]}`;
    if (loopbackIpv4(embedded)) {
      return "loopback";
    }
    return privateIpv4Literal(embedded) ? "private" : "public";
  }
  if (bytes[0] === 0xfc || bytes[0] === 0xfd) {
    return "private"; // fc00::/7 unique local
  }
  if (bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0x80) {
    return "private"; // fe80::/10 link-local
  }
  if (bytes[0] === 0xff) {
    return "private"; // ff00::/8 multicast
  }
  if (bytes[0] === 0x20 && bytes[1] === 0x01 && bytes[2] === 0x0d && bytes[3] === 0xb8) {
    return "private"; // 2001:db8::/32 documentation
  }
  if (bytes[0] === 0x20 && bytes[1] === 0x01 && bytes[2] === 0x00 && bytes[3] === 0x00) {
    return "private"; // 2001::/32 Teredo
  }
  if (bytes[0] === 0x20 && bytes[1] === 0x02) {
    return "private"; // 2002::/16 6to4
  }
  if (bytes[0] === 0x01 && zeroRange(1, 8)) {
    return "private"; // 100::/64 discard-only
  }
  if (
    bytes[0] === 0x00 &&
    bytes[1] === 0x64 &&
    bytes[2] === 0xff &&
    bytes[3] === 0x9b &&
    zeroRange(4, 12)
  ) {
    return "private"; // 64:ff9b::/96 NAT64
  }
  if (bytes[0] === 0x3f && (bytes[1] & 0xf0) === 0xf0) {
    return "private"; // 3fff::/20 documentation
  }
  if (bytes[0] === 0x5f && bytes[1] === 0x00) {
    return "private"; // 5f00::/16 segment routing
  }
  if (zeroRange(0, 12)) {
    return "private"; // remaining ::/96 reserved
  }
  return "public";
}

/** Split an authority into host/port, keeping IPv6 brackets intact. */
function splitAuthority(authority) {
  if (authority.startsWith("[")) {
    const end = authority.indexOf("]");
    if (end === -1) {
      return null;
    }
    const rest = authority.slice(end + 1);
    if (rest === "") {
      return { host: authority.slice(1, end), port: "" };
    }
    return rest.startsWith(":") ? { host: authority.slice(1, end), port: rest.slice(1) } : null;
  }
  const colon = authority.lastIndexOf(":");
  if (colon === -1) {
    return { host: authority, port: "" };
  }
  return { host: authority.slice(0, colon), port: authority.slice(colon + 1) };
}

function validBaseUrl(value) {
  if (typeof value !== "string") {
    return false;
  }
  const raw = value.trim();
  if (raw.length === 0 || raw.length > MAX_BASE_URL_CHARS || CONTROL_CHARS.test(raw)) {
    return false;
  }
  const schemeMatch = URL_SCHEME.exec(raw);
  if (schemeMatch === null) {
    return false;
  }
  const scheme = schemeMatch[1].toLowerCase();
  if (scheme !== "https" && scheme !== "http") {
    return false;
  }
  let rest = raw.slice(schemeMatch[0].length);
  const hashAt = rest.indexOf("#");
  if (hashAt !== -1) {
    if (rest.slice(hashAt + 1) !== "") {
      return false;
    }
    rest = rest.slice(0, hashAt);
  }
  const queryAt = rest.indexOf("?");
  if (queryAt !== -1) {
    if (rest.slice(queryAt + 1) !== "") {
      return false;
    }
    rest = rest.slice(0, queryAt);
  }
  const slashAt = rest.indexOf("/");
  const authority = slashAt === -1 ? rest : rest.slice(0, slashAt);
  const urlPath = slashAt === -1 ? "" : rest.slice(slashAt);
  if (authority === "" || authority.includes("@")) {
    return false;
  }
  const split = splitAuthority(authority);
  if (split === null || split.host === "") {
    return false;
  }
  if (split.port !== "") {
    if (!/^\d+$/.test(split.port)) {
      return false;
    }
    const port = Number(split.port);
    if (port < 1 || port > 65535) {
      return false;
    }
  }
  // The CLI checks the raw path, so a normalized `..` would slip through.
  if (!CUSTOM_PATH.test(urlPath) || urlPath.split("/").includes("..")) {
    return false;
  }
  let kind;
  if (net.isIPv6(split.host)) {
    kind = classifyIpv6(split.host);
  } else if (net.isIPv4(split.host)) {
    kind = loopbackIpv4(split.host) ? "loopback" : privateIpv4Literal(split.host) ? "private" : "public";
  } else {
    kind = "hostname";
  }
  if (kind === null) {
    return false;
  }
  if (kind === "loopback") {
    return true;
  }
  if (scheme === "http") {
    return false;
  }
  return kind !== "private";
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
 *
 * A write is confirmed only by the expected action *and* `stored === true`; a
 * missing or non-boolean flag is not a confirmation.
 */
const WRITE_ACTIONS = Object.freeze(["set_ai_key", "set_ai_config"]);

function parseSettingsWrite(stdout) {
  const parsed = parseJsonObject(stdout);
  if (parsed.schema !== SETTINGS_SCHEMA) {
    throw new Error("settings write schema is not supported");
  }
  if (!WRITE_ACTIONS.includes(parsed.action)) {
    throw new Error("settings write action is not supported");
  }
  if (parsed.stored !== true) {
    throw new Error("settings write was not confirmed");
  }
  if (parsed.action === "set_ai_config") {
    if (typeof parsed.provider !== "string" || !PROVIDER_ID.test(parsed.provider)) {
      throw new Error("settings write was not confirmed");
    }
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

/**
 * Structural gate for the offline npm pre-install audit.
 *
 * The report says nothing may install on the strength of it, so the shell keeps
 * only bounded text: rule ids, fixed severities, locations and prose. Anything
 * unexpected makes the whole payload unusable.
 */
function parseNpmAudit(stdout) {
  const parsed = parseJsonObject(stdout);
  if (parsed.schema !== NPM_AUDIT_SCHEMA) {
    throw new Error("npm audit schema is not supported");
  }
  if (
    typeof parsed.ok !== "boolean" ||
    typeof parsed.path !== "string" ||
    parsed.counts === null ||
    typeof parsed.counts !== "object" ||
    Array.isArray(parsed.counts) ||
    typeof parsed.counts.blocking !== "number" ||
    !Array.isArray(parsed.inspected_install_files) ||
    parsed.inspected_install_files.length > MAX_CANDIDATES ||
    !Array.isArray(parsed.findings) ||
    parsed.findings.length > MAX_FINDINGS_SHELL
  ) {
    throw new Error("npm audit payload is malformed");
  }
  for (const finding of parsed.findings) {
    if (
      finding === null ||
      typeof finding !== "object" ||
      Array.isArray(finding) ||
      typeof finding.rule_id !== "string" ||
      typeof finding.severity !== "string" ||
      typeof finding.blocks_installation !== "boolean"
    ) {
      throw new Error("npm audit finding is malformed");
    }
  }
  return parsed;
}

module.exports = {
  CONTRACT,
  SETTINGS_SCHEMA,
  NPM_AUDIT_SCHEMA,
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
  DESKTOP_VIEWS,
  TERMINAL_CANDIDATES,
  upgradeTerminalArgv,
  requestedView,
  READ_ONLY_ACTIONS,
  MUTATING_ACTIONS,
  resolveCli,
  buildEnv,
  actionArgv,
  validBaseUrl,
  validSecret,
  parseSnapshot,
  parseSettings,
  parseSettingsWrite,
  parseReview,
  parseInstructionAction,
  parseIncidents,
  parseNpmAudit
};
