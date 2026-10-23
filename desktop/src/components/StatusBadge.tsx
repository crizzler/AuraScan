import type { CheckStatus, Severity } from "../contract";

export type Tone = CheckStatus | Severity | "neutral" | "unavailable";

const LABELS: Record<Tone, string> = {
  ok: "OK",
  warn: "WARN",
  error: "ERROR",
  CRITICAL: "CRITICAL",
  HIGH: "HIGH",
  MEDIUM: "MEDIUM",
  LOW: "LOW",
  UNKNOWN: "UNKNOWN",
  neutral: "NONE",
  unavailable: "UNAVAILABLE"
};

function family(tone: Tone): "check" | "severity" | "meta" {
  if (tone === "ok" || tone === "warn" || tone === "error") {
    return "check";
  }
  if (tone === "neutral" || tone === "unavailable") {
    return "meta";
  }
  return "severity";
}

export function StatusBadge({ tone, label }: { tone: Tone; label?: string }) {
  return (
    <span className={`badge badge--${family(tone)} badge--${tone.toLowerCase()}`}>
      {label ?? LABELS[tone]}
    </span>
  );
}
