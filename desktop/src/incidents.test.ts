import { describe, expect, it } from "vitest";

import { INCIDENT_SCHEMA, MAX_INCIDENT_FINDINGS, parseIncidentReport } from "./contract";

function incidentFixture(change?: (value: Record<string, unknown>) => void): unknown {
  const value: Record<string, unknown> = {
    schema: INCIDENT_SCHEMA,
    incident_id: "incident-20261024-222006-91fa5761fcd2-91376c6a",
    created_at: 1792851606,
    findings: [
      {
        rule_id: "INC-BOOT-FAILURE",
        severity: "MEDIUM",
        confidence: "medium",
        category: "boot",
        source: "deterministic",
        title: "A previous boot ended without a clean shutdown record.",
        summary: "The journal for the previous boot has no clean-exit marker.",
        why_it_matters: "An unclean shutdown can indicate a hang or a power event.",
        recommended_action: "Review the previous boot journal before changing configuration."
      }
    ]
  };
  if (change) {
    change(value);
  }
  return value;
}

describe("parseIncidentReport", () => {
  it("accepts a diagnosis payload", () => {
    const result = parseIncidentReport(incidentFixture());

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.report.incident_id).toMatch(/^incident-/);
    expect(result.report.findings).toHaveLength(1);
    expect(result.report.findings[0].severity).toBe("MEDIUM");
  });

  it("rejects an unsupported schema", () => {
    expect(
      parseIncidentReport(
        incidentFixture((value) => {
          value.schema = "incident_report/1.2";
        })
      ).ok
    ).toBe(false);
  });

  it("rejects malformed identities, timestamps and severities", () => {
    const cases: Array<(value: Record<string, unknown>) => void> = [
      (value) => {
        value.incident_id = "boot-1";
      },
      (value) => {
        value.created_at = "yesterday";
      },
      (value) => {
        const finding = (value.findings as Record<string, unknown>[])[0];
        finding.severity = "SEVERE";
      },
      (value) => {
        const finding = (value.findings as Record<string, unknown>[])[0];
        finding.rule_id = "";
      }
    ];
    for (const change of cases) {
      expect(parseIncidentReport(incidentFixture(change)).ok).toBe(false);
    }
  });

  it("bounds the finding list", () => {
    expect(
      parseIncidentReport(
        incidentFixture((value) => {
          const finding = (value.findings as Record<string, unknown>[])[0];
          value.findings = new Array(MAX_INCIDENT_FINDINGS + 1).fill(finding);
        })
      ).ok
    ).toBe(false);
  });
});
