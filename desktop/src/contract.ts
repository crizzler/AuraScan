/**
 * Parser for the `aurascan-ui/1` snapshot contract.
 *
 * The renderer is a pure view. It never computes severity, confidence, or
 * coverage, and it refuses to render anything it does not fully understand.
 * Every failure returns a bounded reason string that is safe to display.
 */

export const UI_CONTRACT = "aurascan-ui/1";
export const MAX_CHECKS = 1000;

export type CheckStatus = "ok" | "warn" | "error";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

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

export interface Snapshot {
  contract: string;
  generated_at: number;
  app: AppPayload;
  doctor: DoctorPayload;
  intelligence: IntelligencePayload;
  incidents: IncidentsPayload;
}

export type ParseResult =
  | { ok: true; snapshot: Snapshot }
  | { ok: false; reason: string };

const CHECK_STATUSES: CheckStatus[] = ["ok", "warn", "error"];
const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

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

  const doctor = raw.doctor;
  if (!isRecord(doctor) || typeof doctor.ok !== "boolean") {
    return fail("doctor evidence is missing or malformed");
  }
  const checks = parseChecks(doctor.checks);
  if (checks === null) {
    return fail("doctor evidence contains an unsupported check entry");
  }

  const intelligence = parseIntelligence(raw.intelligence);
  if (intelligence === null) {
    return fail("intelligence evidence is malformed");
  }

  const incidents = parseIncidents(raw.incidents);
  if (incidents === null) {
    return fail("incident evidence is malformed");
  }

  return {
    ok: true,
    snapshot: {
      contract: UI_CONTRACT,
      generated_at: raw.generated_at,
      app: { version: app.version, python: app.python, platform: app.platform },
      doctor: { ok: doctor.ok, checks },
      intelligence,
      incidents
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
