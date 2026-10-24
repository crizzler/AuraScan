import { describe, expect, it } from "vitest";

import { MAX_CANDIDATES, REVIEW_SCHEMA, parseReview } from "./contract";

const FILE_ID = "d0d36c7a141a6ceb7c30e1b1";
const REPORT_ID = "report-be8350d1b3a0e04b8bb85cca";
const SHA = "b".repeat(64);

function reviewFixture(change?: (value: Record<string, unknown>) => void): unknown {
  const value: Record<string, unknown> = {
    schema: REVIEW_SCHEMA,
    report_id: REPORT_ID,
    created_at: "2026-10-24T13:06:12.097274Z",
    review_required: true,
    candidate_count: 1,
    highest_severity: "CRITICAL",
    truncated: false,
    continuation_pending: false,
    candidates: [
      {
        file_id: FILE_ID,
        relative_path: "AGENTS.md",
        sha256: SHA,
        surface: "agents",
        integrity_state: "unreviewed",
        content_risk: "CRITICAL",
        baseline: true,
        disable_eligible: true,
        review_required: true,
        findings: [
          {
            rule_id: "IG-BEHAVIOR-FETCH-EXECUTE",
            severity: "HIGH",
            confidence: "high",
            source: "deterministic",
            title: "An agent instruction combines network retrieval with execution.",
            reason: "The active instruction text correlates fetching content with a shell path.",
            evidence_locations: [
              { start_line: 3, end_line: 3, behavior_families: ["fetch", "execute"] }
            ]
          }
        ]
      }
    ]
  };
  if (change) {
    change(value);
  }
  return value;
}

describe("parseReview", () => {
  it("accepts a review payload and projects line ranges", () => {
    const result = parseReview(reviewFixture());

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.report.report_id).toBe(REPORT_ID);
    expect(result.report.candidates).toHaveLength(1);
    const candidate = result.report.candidates[0];
    expect(candidate.file_id).toBe(FILE_ID);
    expect(candidate.sha256).toBe(SHA);
    expect(candidate.findings[0].ranges).toEqual([{ start_line: 3, end_line: 3 }]);
    // Absolute host paths must never be part of the projection.
    expect(JSON.stringify(result.report)).not.toContain("/home/");
  });

  it("rejects an unsupported schema", () => {
    expect(parseReview(reviewFixture((value) => {
      value.schema = "instruction_guard_report/2.0";
    })).ok).toBe(false);
  });

  it("rejects an inconsistent candidate count", () => {
    expect(parseReview(reviewFixture((value) => {
      value.candidate_count = 2;
    })).ok).toBe(false);
  });

  it("rejects malformed identities and severities", () => {
    const cases: Array<(value: Record<string, unknown>) => void> = [
      (value) => {
        value.report_id = "report-";
      },
      (value) => {
        value.highest_severity = "SEVERE";
      },
      (value) => {
        const candidate = (value.candidates as Record<string, unknown>[])[0];
        candidate.file_id = "../escape";
      },
      (value) => {
        const candidate = (value.candidates as Record<string, unknown>[])[0];
        candidate.sha256 = SHA.toUpperCase();
      },
      (value) => {
        const candidate = (value.candidates as Record<string, unknown>[])[0];
        candidate.content_risk = "NONE";
      },
      (value) => {
        const candidate = (value.candidates as Record<string, unknown>[])[0];
        candidate.baseline = "yes";
      }
    ];
    for (const change of cases) {
      expect(parseReview(reviewFixture(change)).ok).toBe(false);
    }
  });

  it("rejects malformed evidence ranges", () => {
    const breaks: Array<(finding: Record<string, unknown>) => void> = [
      (finding) => {
        finding.evidence_locations = [{ start_line: 0, end_line: 3 }];
      },
      (finding) => {
        finding.evidence_locations = [{ start_line: 5, end_line: 3 }];
      },
      (finding) => {
        finding.evidence_locations = [{ start_line: "3", end_line: 3 }];
      }
    ];
    for (const broke of breaks) {
      expect(
        parseReview(
          reviewFixture((value) => {
            const candidate = (value.candidates as Record<string, unknown>[])[0];
            broke((candidate.findings as Record<string, unknown>[])[0]);
          })
        ).ok
      ).toBe(false);
    }
  });

  it("bounds the candidate list", () => {
    expect(
      parseReview(
        reviewFixture((value) => {
          const candidate = (value.candidates as Record<string, unknown>[])[0];
          value.candidates = new Array(MAX_CANDIDATES + 1).fill(candidate);
          value.candidate_count = MAX_CANDIDATES + 1;
        })
      ).ok
    ).toBe(false);
  });
});
