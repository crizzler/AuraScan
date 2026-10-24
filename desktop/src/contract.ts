/**
 * Parser for the `aurascan-ui/1` snapshot contract.
 *
 * The renderer is a pure view. It never computes severity, confidence, or
 * coverage, and it refuses to render anything it does not fully understand.
 * Every failure returns a bounded reason string that is safe to display.
 */

export const UI_CONTRACT = "aurascan-ui/1";
export const MAX_CHECKS = 1000;
export const MAX_FINDINGS = 500;
export const MAX_ACTIONS = 50;

export type CheckStatus = "ok" | "warn" | "error";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
export type Confidence = "LOW" | "MEDIUM" | "HIGH" | "CONFIRMED";
export type ReportAction = "ALLOW" | "WARN" | "MANUAL_REVIEW" | "BLOCK" | "BLOCKED";
export type ActionKind = "read_only" | "terminal_only";
export type ActionConfirmation = "none" | "hash_bound" | "terminal_only";

export interface DoctorCheck {
  name: string;
  status: CheckStatus;
  message: string;
  details?: Record<string, unknown>;
}

export interface DoctorPayload {
  ok: boolean;
  checks: DoctorCheck[];
}

export interface IntelligencePayload {
  status: string;
  source?: string;
  digest?: string;
  identity?: string;
  update_channel?: string;
  schema_version?: string;
  reviewed_at?: string;
  activated_at?: string;
  expires_at?: string;
  sequence?: number;
  automatic_updates?: boolean;
}

export interface IncidentsPayload {
  available: boolean;
  pending: number;
  unseen: number;
  highest_severity: Severity | null;
}

export interface AppPayload {
  version: string;
  python: string;
  platform: string;
}

export interface ActionArgument {
  name: string;
  kind: string;
  label: string;
}

export interface ActionSpec {
  id: string;
  label: string;
  summary: string;
  kind: ActionKind;
  confirmation: ActionConfirmation;
  renderer_may_request: boolean;
  arguments: ActionArgument[];
  argv_preview: string[];
  notes: string;
}

export interface ReportFinding {
  rule_id: string;
  severity: Severity;
  confidence: Confidence;
  evidence_quality: string;
  phase: string;
  source: string;
  file_name: string;
  line_number: number | null;
  title: string;
  summary: string;
  recommendation: string;
  checked: string;
  not_checked: string;
  blocks_installation: boolean;
  requires_manual_review: boolean;
}

export interface ReportRisk {
  severity: Severity;
  action: ReportAction;
  recommended_action: string;
  blocks_installation: boolean;
  requires_manual_review: boolean;
  reason: string;
}

export interface ReportPayload {  schema_version: string;
  scanner_version: string;
  package: {
    name: string;
    version: string;
    pkgbase: string;
    maintainer: string;
  };
  risk: ReportRisk | null;
  counts: {
    total: number;
    by_severity: Record<"LOW" | "MEDIUM" | "HIGH" | "CRITICAL", number>;
    blocking: number;
    manual_review: number;
    truncated: boolean;
  };
  findings: ReportFinding[];
  messages: string[];
  context: Record<string, string>;
}

export interface Snapshot {
  contract: string;
  generated_at: number;
  app: AppPayload;
  doctor?: DoctorPayload;
  intelligence?: IntelligencePayload;
  incidents?: IncidentsPayload;
  report?: ReportPayload;
  actions?: ActionSpec[];
}

export type ParseResult =
  | { ok: true; snapshot: Snapshot }
  | { ok: false; reason: string };

const CHECK_STATUSES: CheckStatus[] = ["ok", "warn", "error"];
const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
const CONFIDENCES: Confidence[] = ["LOW", "MEDIUM", "HIGH", "CONFIRMED"];
const REPORT_ACTIONS: ReportAction[] = ["ALLOW", "WARN", "MANUAL_REVIEW", "BLOCK", "BLOCKED"];
const ACTION_KINDS: ActionKind[] = ["read_only", "terminal_only"];
const ACTION_CONFIRMATIONS: ActionConfirmation[] = ["none", "hash_bound", "terminal_only"];
const ACTION_ID = /^[a-z][a-z0-9_]{0,63}$/;

const INTELLIGENCE_STRING_KEYS = [
  "source",
  "digest",
  "identity",
  "update_channel",
  "schema_version",
  "reviewed_at",
  "activated_at",
  "expires_at",
] as const;

function fail(reason: string): ParseResult {
  return { ok: false, reason };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function parseChecks(raw: unknown): DoctorCheck[] | null {
  if (!Array.isArray(raw)) {
    return null;
  }
  if (raw.length > MAX_CHECKS) {
    return null;
  }
  const checks: DoctorCheck[] = [];
  for (const entry of raw) {
    if (!isRecord(entry)) {
      return null;
    }
    const { name, status, message, details } = entry;
    if (typeof name !== "string" || name.length === 0) {
      return null;
    }
    if (typeof status !== "string" || !CHECK_STATUSES.includes(status as CheckStatus)) {
      return null;
    }
    if (typeof message !== "string") {
      return null;
    }
    const check: DoctorCheck = {
      name,
      status: status as CheckStatus,
      message
    };
    if (isRecord(details)) {
      check.details = details;
    }
    checks.push(check);
  }
  return checks;
}

function parseIntelligence(raw: unknown): IntelligencePayload | null {
  if (!isRecord(raw) || typeof raw.status !== "string" || raw.status.length === 0) {
    return null;
  }
  const payload: IntelligencePayload = { status: raw.status };
  for (const key of INTELLIGENCE_STRING_KEYS) {
    const value = raw[key];
    if (value === undefined) {
      continue;
    }
    if (typeof value !== "string") {
      return null;
    }
    payload[key] = value;
  }
  if (raw.sequence !== undefined) {
    if (!isFiniteNumber(raw.sequence)) {
      return null;
    }
    payload.sequence = raw.sequence;
  }
  if (raw.automatic_updates !== undefined) {
    if (typeof raw.automatic_updates !== "boolean") {
      return null;
    }
    payload.automatic_updates = raw.automatic_updates;
  }
  return payload;
}

function parseIncidents(raw: unknown): IncidentsPayload | null {
  if (!isRecord(raw) || typeof raw.available !== "boolean") {
    return null;
  }
  if (!isFiniteNumber(raw.pending) || raw.pending < 0) {
    return null;
  }
  if (!isFiniteNumber(raw.unseen) || raw.unseen < 0) {
    return null;
  }
  const highest = raw.highest_severity;
  if (highest !== null && (typeof highest !== "string" || !SEVERITIES.includes(highest as Severity))) {
    return null;
  }
  return {
    available: raw.available,
    pending: raw.pending,
    unseen: raw.unseen,
    highest_severity: highest === null ? null : (highest as Severity)
  };
}

function requireRecord(value: unknown, reason: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new Error(reason);
  }
  return value;
}

function requireString(value: unknown, reason: string): string {
  if (typeof value !== "string") {
    throw new Error(reason);
  }
  return value;
}

function requireNumber(value: unknown, reason: string): number {
  if (!isFiniteNumber(value)) {
    throw new Error(reason);
  }
  return value;
}

function requireBoolean(value: unknown, reason: string): boolean {
  if (typeof value !== "boolean") {
    throw new Error(reason);
  }
  return value;
}

function parseFinding(raw: unknown): ReportFinding {
  const entry = requireRecord(raw, "report finding is not an object");
  const severity = requireString(entry.severity, "report finding has no severity");
  if (!SEVERITIES.includes(severity as Severity)) {
    throw new Error("report finding has an unsupported severity");
  }
  const confidence = requireString(entry.confidence, "report finding has no confidence");
  if (!CONFIDENCES.includes(confidence as Confidence)) {
    throw new Error("report finding has an unsupported confidence");
  }
  const ruleId = requireString(entry.rule_id, "report finding has no rule identifier");
  if (ruleId.length === 0) {
    throw new Error("report finding has no rule identifier");
  }
  const line = entry.line_number;
  if (line !== null && !isFiniteNumber(line)) {
    throw new Error("report finding has an invalid line number");
  }
  return {
    rule_id: ruleId,
    severity: severity as Severity,
    confidence: confidence as Confidence,
    evidence_quality: requireString(entry.evidence_quality, "report finding has no evidence quality"),
    phase: requireString(entry.phase, "report finding has no phase"),
    source: requireString(entry.source, "report finding has no source"),
    file_name: requireString(entry.file_name, "report finding has no file name"),
    line_number: line === null ? null : line,
    title: requireString(entry.title, "report finding has no title"),
    summary: requireString(entry.summary, "report finding has no summary"),
    recommendation: requireString(entry.recommendation, "report finding has no recommendation"),
    checked: requireString(entry.checked, "report finding has no checked text"),
    not_checked: requireString(entry.not_checked, "report finding has no not-checked text"),
    blocks_installation: requireBoolean(entry.blocks_installation, "report finding has no blocking flag"),
    requires_manual_review: requireBoolean(entry.requires_manual_review, "report finding has no review flag")
  };
}

function parseReport(raw: unknown): ReportPayload | null {
  try {
    const report = requireRecord(raw, "report evidence is not an object");
    const pkg = requireRecord(report.package, "report package is missing");
    const counts = requireRecord(report.counts, "report counts are missing");
    const bySeverity = requireRecord(counts.by_severity, "report severity counts are missing");
    const rawFindings = report.findings;
    if (!Array.isArray(rawFindings) || rawFindings.length > MAX_FINDINGS) {
      throw new Error("report findings are missing or exceed the contract bound");
    }

    let risk: ReportRisk | null = null;
    if (report.risk !== null && report.risk !== undefined) {
      const entry = requireRecord(report.risk, "report risk is malformed");
      const severity = requireString(entry.severity, "report risk has no severity");
      if (!SEVERITIES.includes(severity as Severity)) {
        throw new Error("report risk has an unsupported severity");
      }
      const action = requireString(entry.action, "report risk has no action");
      if (!REPORT_ACTIONS.includes(action as ReportAction)) {
        throw new Error("report risk has an unsupported action");
      }
      risk = {
        severity: severity as Severity,
        action: action as ReportAction,
        recommended_action: requireString(entry.recommended_action, "report risk has no recommended action"),
        blocks_installation: requireBoolean(entry.blocks_installation, "report risk has no blocking flag"),
        requires_manual_review: requireBoolean(entry.requires_manual_review, "report risk has no review flag"),
        reason: requireString(entry.reason, "report risk has no reason")
      };
    }

    const messages = Array.isArray(report.messages)
      ? report.messages.filter((message): message is string => typeof message === "string")
      : [];
    const context: Record<string, string> = {};
    if (isRecord(report.context)) {
      for (const [key, value] of Object.entries(report.context)) {
        if (typeof value === "string") {
          context[key] = value;
        }
      }
    }

    return {
      schema_version: requireString(report.schema_version, "report has no schema version"),
      scanner_version: requireString(report.scanner_version, "report has no scanner version"),
      package: {
        name: requireString(pkg.name, "report has no package name"),
        version: requireString(pkg.version, "report package version is malformed"),
        pkgbase: requireString(pkg.pkgbase, "report package pkgbase is malformed"),
        maintainer: requireString(pkg.maintainer, "report package maintainer is malformed")
      },
      risk,
      counts: {
        total: requireNumber(counts.total, "report total is malformed"),
        by_severity: {
          LOW: requireNumber(bySeverity.LOW, "report severity counts are malformed"),
          MEDIUM: requireNumber(bySeverity.MEDIUM, "report severity counts are malformed"),
          HIGH: requireNumber(bySeverity.HIGH, "report severity counts are malformed"),
          CRITICAL: requireNumber(bySeverity.CRITICAL, "report severity counts are malformed")
        },
        blocking: requireNumber(counts.blocking, "report blocking count is malformed"),
        manual_review: requireNumber(counts.manual_review, "report manual-review count is malformed"),
        truncated: requireBoolean(counts.truncated, "report truncation flag is malformed")
      },
      findings: rawFindings.map(parseFinding),
      messages,
      context
    };
  } catch {
    return null;
  }
}

function parseAction(raw: unknown): ActionSpec {
  const entry = requireRecord(raw, "action is not an object");
  const id = requireString(entry.id, "action has no identifier");
  if (!ACTION_ID.test(id)) {
    throw new Error("action identifier is malformed");
  }
  const kind = requireString(entry.kind, "action has no kind");
  if (!ACTION_KINDS.includes(kind as ActionKind)) {
    throw new Error("action has an unsupported kind");
  }
  const confirmation = requireString(entry.confirmation, "action has no confirmation");
  if (!ACTION_CONFIRMATIONS.includes(confirmation as ActionConfirmation)) {
    throw new Error("action has an unsupported confirmation");
  }
  const rendererMayRequest = requireBoolean(
    entry.renderer_may_request,
    "action has no request flag"
  );
  if (kind === "read_only" && !rendererMayRequest) {
    throw new Error("read-only action is not requestable");
  }
  if (kind === "terminal_only" && rendererMayRequest) {
    throw new Error("terminal-only action is requestable");
  }
  const rawArguments = entry.arguments;
  if (!Array.isArray(rawArguments)) {
    throw new Error("action arguments are malformed");
  }
  const argumentsList = rawArguments.map((argument) => {
    const record = requireRecord(argument, "action argument is not an object");
    return {
      name: requireString(record.name, "action argument has no name"),
      kind: requireString(record.kind, "action argument has no kind"),
      label: requireString(record.label, "action argument has no label")
    };
  });
  const rawArgv = entry.argv_preview;
  if (
    !Array.isArray(rawArgv) ||
    rawArgv.length === 0 ||
    rawArgv.length > 32 ||
    !rawArgv.every((part) => typeof part === "string")
  ) {
    throw new Error("action argument vector is malformed");
  }
  return {
    id,
    label: requireString(entry.label, "action has no label"),
    summary: requireString(entry.summary, "action has no summary"),
    kind: kind as ActionKind,
    confirmation: confirmation as ActionConfirmation,
    renderer_may_request: rendererMayRequest,
    arguments: argumentsList,
    argv_preview: rawArgv as string[],
    notes: requireString(entry.notes, "action has no notes")
  };
}

function parseActions(raw: unknown): ActionSpec[] | null {
  try {
    if (!Array.isArray(raw) || raw.length > MAX_ACTIONS) {
      throw new Error("action catalog is missing or exceeds the contract bound");
    }
    const actions = raw.map(parseAction);
    if (new Set(actions.map((action) => action.id)).size !== actions.length) {
      throw new Error("action identifiers are duplicated");
    }
    return actions;
  } catch {
    return null;
  }
}

export function parseSnapshot(raw: unknown): ParseResult {
  if (!isRecord(raw)) {
    return fail("snapshot is not an object");
  }
  if (raw.contract !== UI_CONTRACT) {
    return fail(`unsupported contract: ${String(raw.contract)}`);
  }
  if (!isFiniteNumber(raw.generated_at)) {
    return fail("snapshot has no generation timestamp");
  }

  const app = raw.app;
  if (
    !isRecord(app) ||
    typeof app.version !== "string" ||
    typeof app.python !== "string" ||
    typeof app.platform !== "string"
  ) {
    return fail("app identity is missing or malformed");
  }

  const snapshot: Snapshot = {
    contract: UI_CONTRACT,
    generated_at: raw.generated_at,
    app: { version: app.version, python: app.python, platform: app.platform }
  };

  if (raw.doctor !== undefined) {
    if (!isRecord(raw.doctor) || typeof raw.doctor.ok !== "boolean") {
      return fail("doctor evidence is malformed");
    }
    const checks = parseChecks(raw.doctor.checks);
    if (checks === null) {
      return fail("doctor evidence contains an unsupported check entry");
    }
    snapshot.doctor = { ok: raw.doctor.ok, checks };
  }

  if (raw.intelligence !== undefined) {
    const intelligence = parseIntelligence(raw.intelligence);
    if (intelligence === null) {
      return fail("intelligence evidence is malformed");
    }
    snapshot.intelligence = intelligence;
  }

  if (raw.incidents !== undefined) {
    const incidents = parseIncidents(raw.incidents);
    if (incidents === null) {
      return fail("incident evidence is malformed");
    }
    snapshot.incidents = incidents;
  }

  if (raw.report !== undefined) {
    const report = parseReport(raw.report);
    if (report === null) {
      return fail("report evidence is malformed");
    }
    snapshot.report = report;
  }

  if (raw.actions !== undefined) {
    const actions = parseActions(raw.actions);
    if (actions === null) {
      return fail("action catalog is malformed");
    }
    snapshot.actions = actions;
  }

  if (!snapshot.doctor && !snapshot.report && !snapshot.actions) {
    return fail("snapshot carries no evidence or action section");
  }

  return { ok: true, snapshot };
}

export const SETTINGS_SCHEMA = "aurascan-settings/1";
export const MAX_PROVIDERS = 32;
export const MAX_FEATURES = 64;

export interface SettingsConfig {
  path: string;
  present: boolean;
  mode: string | null;
  mode_ok: boolean;
  readable: boolean;
}

export interface SettingsAi {
  enabled: boolean;
  provider: string;
  provider_label: string;
  model: string;
  base_url: string | null;
  local: boolean;
  requires_key: boolean;
  key_env: string;
  key_present: boolean;
  supported: boolean;
  authentication_ready: boolean;
  error: string;
  ready: boolean;
}

export interface SettingsProvider {
  id: string;
  label: string;
  local: boolean;
  requires_key: boolean;
  key_env: string;
  default_model: string;
  key_present: boolean;
  selected: boolean;
}

export interface SettingsFeature {
  id: string;
  label: string;
  env: string;
  enabled: boolean | null;
  declared: boolean;
}

export interface SettingsPayload {
  schema: string;
  config: SettingsConfig;
  ai: SettingsAi;
  providers: SettingsProvider[];
  features: SettingsFeature[];
}

export type SettingsParseResult =
  | { ok: true; settings: SettingsPayload }
  | { ok: false; reason: string };

const FEATURE_ID = /^[a-z][a-z0-9_]{0,63}$/;
const PROVIDER_ID = /^[a-z][a-z0-9_]{0,31}$/;

function settingsFail(reason: string): SettingsParseResult {
  return { ok: false, reason };
}

function parseConfigPayload(raw: unknown): SettingsConfig | null {
  if (!isRecord(raw)) {
    return null;
  }
  const { path, present, mode, mode_ok, readable } = raw;
  if (typeof path !== "string" || path.length === 0) {
    return null;
  }
  if (typeof present !== "boolean" || typeof mode_ok !== "boolean" || typeof readable !== "boolean") {
    return null;
  }
  if (mode !== null && typeof mode !== "string") {
    return null;
  }
  return { path, present, mode, mode_ok, readable };
}

function parseAiPayload(raw: unknown): SettingsAi | null {
  if (!isRecord(raw)) {
    return null;
  }
  const booleanKeys = [
    "enabled",
    "local",
    "requires_key",
    "key_present",
    "supported",
    "authentication_ready",
    "ready"
  ] as const;
  for (const key of booleanKeys) {
    if (typeof raw[key] !== "boolean") {
      return null;
    }
  }
  if (
    typeof raw.provider !== "string" ||
    typeof raw.provider_label !== "string" ||
    typeof raw.model !== "string" ||
    typeof raw.key_env !== "string" ||
    typeof raw.error !== "string"
  ) {
    return null;
  }
  if (raw.base_url !== null && typeof raw.base_url !== "string") {
    return null;
  }
  return {
    enabled: raw.enabled as boolean,
    provider: raw.provider,
    provider_label: raw.provider_label,
    model: raw.model,
    base_url: raw.base_url as string | null,
    local: raw.local as boolean,
    requires_key: raw.requires_key as boolean,
    key_env: raw.key_env,
    key_present: raw.key_present as boolean,
    supported: raw.supported as boolean,
    authentication_ready: raw.authentication_ready as boolean,
    error: raw.error,
    ready: raw.ready as boolean
  };
}

function parseProviderEntries(raw: unknown): SettingsProvider[] | null {
  if (!Array.isArray(raw) || raw.length > MAX_PROVIDERS) {
    return null;
  }
  const providers: SettingsProvider[] = [];
  for (const entry of raw) {
    if (!isRecord(entry)) {
      return null;
    }
    const { id, label, local, requires_key, key_env, default_model, key_present, selected } = entry;
    if (typeof id !== "string" || !PROVIDER_ID.test(id)) {
      return null;
    }
    if (
      typeof label !== "string" ||
      typeof key_env !== "string" ||
      typeof default_model !== "string" ||
      typeof local !== "boolean" ||
      typeof requires_key !== "boolean" ||
      typeof key_present !== "boolean" ||
      typeof selected !== "boolean"
    ) {
      return null;
    }
    providers.push({
      id,
      label,
      local,
      requires_key,
      key_env,
      default_model,
      key_present,
      selected
    });
  }
  return providers;
}

function parseFeatureEntries(raw: unknown): SettingsFeature[] | null {
  if (!Array.isArray(raw) || raw.length > MAX_FEATURES) {
    return null;
  }
  const features: SettingsFeature[] = [];
  for (const entry of raw) {
    if (!isRecord(entry)) {
      return null;
    }
    const { id, label, env, enabled, declared } = entry;
    if (typeof id !== "string" || !FEATURE_ID.test(id)) {
      return null;
    }
    if (
      typeof label !== "string" ||
      typeof env !== "string" ||
      typeof declared !== "boolean" ||
      !(enabled === null || typeof enabled === "boolean")
    ) {
      return null;
    }
    features.push({ id, label, env, enabled, declared });
  }
  return features;
}

export function parseSettings(raw: unknown): SettingsParseResult {
  if (!isRecord(raw)) {
    return settingsFail("settings payload is not an object");
  }
  if (raw.schema !== SETTINGS_SCHEMA) {
    return settingsFail(`unsupported settings schema: ${String(raw.schema)}`);
  }
  const config = parseConfigPayload(raw.config);
  if (config === null) {
    return settingsFail("configuration state is malformed");
  }
  const ai = parseAiPayload(raw.ai);
  if (ai === null) {
    return settingsFail("AI settings are malformed");
  }
  const providers = parseProviderEntries(raw.providers);
  if (providers === null) {
    return settingsFail("provider inventory is malformed");
  }
  const features = parseFeatureEntries(raw.features);
  if (features === null) {
    return settingsFail("feature list is malformed");
  }
  return { ok: true, settings: { schema: SETTINGS_SCHEMA, config, ai, providers, features } };
}

/** A `settings set-ai-key` response: a confirmation plus the new effective state. */
export function parseSettingsWrite(
  raw: unknown
): { ok: true; ai: SettingsAi } | { ok: false; reason: string } {
  if (!isRecord(raw)) {
    return { ok: false, reason: "response is not an object" };
  }
  if (raw.schema !== SETTINGS_SCHEMA || raw.stored !== true) {
    return { ok: false, reason: "the credential was not stored" };
  }
  const ai = parseAiPayload(raw.ai);
  if (ai === null) {
    return { ok: false, reason: "AI settings are malformed" };
  }
  return { ok: true, ai };
}

export const REVIEW_SCHEMA = "instruction_guard_report/1.0";
export const MAX_CANDIDATES = 200;
export const MAX_REVIEW_FINDINGS = 50;

export interface ReviewLineRange {
  start_line: number;
  end_line: number;
}

export interface ReviewFinding {
  rule_id: string;
  severity: Severity;
  confidence: string;
  source: string;
  title: string;
  reason: string;
  ranges: ReviewLineRange[];
}

export interface ReviewCandidate {
  file_id: string;
  relative_path: string;
  sha256: string;
  surface: string;
  integrity_state: string;
  content_risk: Severity;
  baseline: boolean;
  disable_eligible: boolean;
  review_required: boolean;
  findings: ReviewFinding[];
}

export interface ReviewReport {
  schema: string;
  report_id: string;
  created_at: string;
  review_required: boolean;
  candidate_count: number;
  highest_severity: Severity;
  truncated: boolean;
  continuation_pending: boolean;
  candidates: ReviewCandidate[];
}

export type ReviewParseResult =
  | { ok: true; report: ReviewReport }
  | { ok: false; reason: string };

const FILE_ID = /^[a-z0-9]{8,64}$/;
const REPORT_ID = /^report-[a-z0-9]{8,64}$/;
const SHA256 = /^[a-f0-9]{64}$/;

function reviewFail(reason: string): ReviewParseResult {
  return { ok: false, reason };
}

function boundedString(value: unknown, limit: number): string | null {
  if (typeof value !== "string" || value.length === 0 || value.length > limit) {
    return null;
  }
  return value;
}

function parseReviewRanges(raw: unknown): ReviewLineRange[] | null {
  if (raw === undefined) {
    return [];
  }
  if (!Array.isArray(raw) || raw.length > 20) {
    return null;
  }
  const ranges: ReviewLineRange[] = [];
  for (const entry of raw) {
    if (!isRecord(entry)) {
      return null;
    }
    const { start_line, end_line } = entry;
    if (!Number.isInteger(start_line) || !Number.isInteger(end_line)) {
      return null;
    }
    if ((start_line as number) < 1 || (end_line as number) < (start_line as number)) {
      return null;
    }
    ranges.push({ start_line: start_line as number, end_line: end_line as number });
  }
  return ranges;
}

function parseReviewFindings(raw: unknown): ReviewFinding[] | null {
  if (!Array.isArray(raw) || raw.length > MAX_REVIEW_FINDINGS) {
    return null;
  }
  const findings: ReviewFinding[] = [];
  for (const entry of raw) {
    if (!isRecord(entry)) {
      return null;
    }
    const ruleId = boundedString(entry.rule_id, 80);
    const title = boundedString(entry.title, 300);
    const reason = boundedString(entry.reason, 600);
    const source = boundedString(entry.source, 40);
    const confidence = boundedString(entry.confidence, 40);
    if (!ruleId || !title || !reason || !source || !confidence) {
      return null;
    }
    if (typeof entry.severity !== "string" || !SEVERITIES.includes(entry.severity as Severity)) {
      return null;
    }
    const ranges = parseReviewRanges(entry.evidence_locations);
    if (ranges === null) {
      return null;
    }
    findings.push({
      rule_id: ruleId,
      severity: entry.severity as Severity,
      confidence,
      source,
      title,
      reason,
      ranges
    });
  }
  return findings;
}

function parseCandidates(raw: unknown): ReviewCandidate[] | null {
  if (!Array.isArray(raw) || raw.length > MAX_CANDIDATES) {
    return null;
  }
  const candidates: ReviewCandidate[] = [];
  for (const entry of raw) {
    if (!isRecord(entry)) {
      return null;
    }
    const fileId = boundedString(entry.file_id, 64);
    const relativePath = boundedString(entry.relative_path, 400);
    const surface = boundedString(entry.surface, 60);
    const integrityState = boundedString(entry.integrity_state, 60);
    if (!fileId || !FILE_ID.test(fileId) || !relativePath || !surface || !integrityState) {
      return null;
    }
    if (typeof entry.sha256 !== "string" || !SHA256.test(entry.sha256)) {
      return null;
    }
    if (
      typeof entry.content_risk !== "string" ||
      !SEVERITIES.includes(entry.content_risk as Severity)
    ) {
      return null;
    }
    if (
      typeof entry.baseline !== "boolean" ||
      typeof entry.disable_eligible !== "boolean" ||
      typeof entry.review_required !== "boolean"
    ) {
      return null;
    }
    const findings = parseReviewFindings(entry.findings);
    if (findings === null) {
      return null;
    }
    candidates.push({
      file_id: fileId,
      relative_path: relativePath,
      sha256: entry.sha256,
      surface,
      integrity_state: integrityState,
      content_risk: entry.content_risk as Severity,
      baseline: entry.baseline,
      disable_eligible: entry.disable_eligible,
      review_required: entry.review_required,
      findings
    });
  }
  return candidates;
}

export function parseReview(raw: unknown): ReviewParseResult {
  if (!isRecord(raw)) {
    return reviewFail("review payload is not an object");
  }
  if (raw.schema !== REVIEW_SCHEMA) {
    return reviewFail(`unsupported review schema: ${String(raw.schema)}`);
  }
  const reportId = boundedString(raw.report_id, 80);
  if (!reportId || !REPORT_ID.test(reportId)) {
    return reviewFail("review report identity is malformed");
  }
  const createdAt = boundedString(raw.created_at, 40);
  if (!createdAt) {
    return reviewFail("review timestamp is malformed");
  }
  if (
    typeof raw.review_required !== "boolean" ||
    typeof raw.truncated !== "boolean" ||
    typeof raw.continuation_pending !== "boolean"
  ) {
    return reviewFail("review flags are malformed");
  }
  if (
    !Number.isInteger(raw.candidate_count) ||
    (raw.candidate_count as number) < 0 ||
    (raw.candidate_count as number) > MAX_CANDIDATES
  ) {
    return reviewFail("review candidate count is out of range");
  }
  if (
    typeof raw.highest_severity !== "string" ||
    !SEVERITIES.includes(raw.highest_severity as Severity)
  ) {
    return reviewFail("review severity is malformed");
  }
  const candidates = parseCandidates(raw.candidates);
  if (candidates === null) {
    return reviewFail("review candidates are malformed");
  }
  if (candidates.length !== raw.candidate_count) {
    return reviewFail("review candidate count does not match its entries");
  }
  return {
    ok: true,
    report: {
      schema: REVIEW_SCHEMA,
      report_id: reportId,
      created_at: createdAt,
      review_required: raw.review_required,
      candidate_count: raw.candidate_count as number,
      highest_severity: raw.highest_severity as Severity,
      truncated: raw.truncated,
      continuation_pending: raw.continuation_pending,
      candidates
    }
  };
}

export function countChecks(checks: DoctorCheck[]): Record<CheckStatus, number> {
  const counts: Record<CheckStatus, number> = { ok: 0, warn: 0, error: 0 };
  for (const check of checks) {
    counts[check.status] += 1;
  }
  return counts;
}

export function shortDigest(value: string | undefined): string {
  if (!value) {
    return "—";
  }
  return value.length <= 16 ? value : `${value.slice(0, 12)}…`;
}
