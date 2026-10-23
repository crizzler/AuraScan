import { describe, expect, it } from "vitest";

import sample from "./fixtures/snapshot.sample.json";
import {
  MAX_ACTIONS,
  MAX_CHECKS,
  MAX_FINDINGS,
  UI_CONTRACT,
  countChecks,
  parseSnapshot,
  shortDigest
} from "./contract";

function mutate(change: (value: Record<string, unknown>) => void): unknown {
  const copy = JSON.parse(JSON.stringify(sample)) as Record<string, unknown>;
  change(copy);
  return copy;
}

describe("parseSnapshot", () => {
  it("accepts the shipped sample and normalizes it", () => {
    const result = parseSnapshot(sample);

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.snapshot.contract).toBe(UI_CONTRACT);
    expect(result.snapshot.doctor?.checks.length).toBe(sample.doctor.checks.length);
    expect(result.snapshot.incidents?.highest_severity).toBe("HIGH");
    expect(result.snapshot.report?.package.name).toBe("example-pkg");
    expect(result.snapshot.actions?.length).toBe(6);
  });

  it("rejects an unknown contract instead of guessing", () => {
    const result = parseSnapshot(mutate((value) => (value.contract = "aurascan-ui/2")));

    expect(result).toEqual({
      ok: false,
      reason: "unsupported contract: aurascan-ui/2"
    });
  });

  it("rejects a missing contract", () => {
    const result = parseSnapshot(mutate((value) => (value.contract = undefined)));

    expect(result.ok).toBe(false);
  });

  it("rejects a non-object snapshot", () => {
    expect(parseSnapshot(null).ok).toBe(false);
    expect(parseSnapshot([]).ok).toBe(false);
    expect(parseSnapshot("snapshot").ok).toBe(false);
  });

  it("rejects an unknown check status", () => {
    const result = parseSnapshot(
      mutate((value) => {
        const doctor = value.doctor as { checks: Array<Record<string, unknown>> };
        doctor.checks[0].status = "clean";
      })
    );

    expect(result.ok).toBe(false);
  });

  it("rejects a check without a name", () => {
    const result = parseSnapshot(
      mutate((value) => {
        const doctor = value.doctor as { checks: Array<Record<string, unknown>> };
        doctor.checks[0].name = undefined;
      })
    );

    expect(result.ok).toBe(false);
  });

  it("rejects an unbounded check list", () => {
    const result = parseSnapshot(
      mutate((value) => {
        const doctor = value.doctor as { checks: Array<Record<string, unknown>> };
        doctor.checks = Array.from({ length: MAX_CHECKS + 1 }, () => ({
          name: "check",
          status: "ok",
          message: "message"
        }));
      })
    );

    expect(result.ok).toBe(false);
  });

  it("rejects malformed incident evidence", () => {
    const result = parseSnapshot(
      mutate((value) => {
        (value.incidents as Record<string, unknown>).highest_severity = "SEVERE";
      })
    );

    expect(result.ok).toBe(false);
  });

  it("accepts an unavailable incident state", () => {
    const result = parseSnapshot(
      mutate((value) => {
        value.incidents = {
          available: false,
          pending: 0,
          unseen: 0,
          highest_severity: null
        };
      })
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.snapshot.incidents?.available).toBe(false);
    }
  });

  it("tolerates additive unknown keys without exposing them", () => {
    const result = parseSnapshot(
      mutate((value) => {
        value.future_section = { anything: true };
        (value.doctor as Record<string, unknown>).future_field = 1;
      })
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(Object.keys(result.snapshot)).toEqual([
        "contract",
        "generated_at",
        "app",
        "doctor",
        "intelligence",
        "incidents",
        "report",
        "actions"
      ]);
    }
  });
});

describe("report mode", () => {
  it("accepts a report-only snapshot without live sections", () => {
    const result = parseSnapshot(
      mutate((value) => {
        value.doctor = undefined;
        value.intelligence = undefined;
        value.incidents = undefined;
      })
    );

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.snapshot.doctor).toBeUndefined();
    expect(result.snapshot.report?.findings.length).toBe(2);
    expect(result.snapshot.report?.counts.by_severity.HIGH).toBe(1);
  });

  it("rejects an unknown report severity", () => {
    const result = parseSnapshot(
      mutate((value) => {
        const report = value.report as { findings: Array<Record<string, unknown>> };
        report.findings[0].severity = "SEVERE";
      })
    );

    expect(result).toEqual({ ok: false, reason: "report evidence is malformed" });
  });

  it("rejects a report without a package", () => {
    const result = parseSnapshot(
      mutate((value) => {
        (value.report as Record<string, unknown>).package = undefined;
      })
    );

    expect(result.ok).toBe(false);
  });

  it("rejects a report beyond the finding bound", () => {
    const result = parseSnapshot(
      mutate((value) => {
        const report = value.report as { findings: unknown[] };
        report.findings = Array.from({ length: MAX_FINDINGS + 1 }, () => null);
      })
    );

    expect(result.ok).toBe(false);
  });

  it("rejects a snapshot with no evidence section", () => {
    const result = parseSnapshot(
      mutate((value) => {
        value.doctor = undefined;
        value.report = undefined;
        value.actions = undefined;
      })
    );

    expect(result).toEqual({
      ok: false,
      reason: "snapshot carries no evidence or action section"
    });
  });
});

describe("action catalog", () => {
  it("accepts an actions-only snapshot", () => {
    const result = parseSnapshot(
      mutate((value) => {
        value.doctor = undefined;
        value.intelligence = undefined;
        value.incidents = undefined;
        value.report = undefined;
      })
    );

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.snapshot.report).toBeUndefined();
    expect(result.snapshot.actions?.map((action) => action.id)).toContain("scan_package");
    expect(
      result.snapshot.actions?.filter((action) => action.renderer_may_request).length
    ).toBe(4);
  });

  it("rejects an unknown action kind", () => {
    const result = parseSnapshot(
      mutate((value) => {
        const actions = value.actions as Array<Record<string, unknown>>;
        actions[0].kind = "shell";
      })
    );

    expect(result).toEqual({ ok: false, reason: "action catalog is malformed" });
  });

  it("rejects a terminal-only action that claims to be requestable", () => {
    const result = parseSnapshot(
      mutate((value) => {
        const actions = value.actions as Array<Record<string, unknown>>;
        actions[4].renderer_may_request = true;
      })
    );

    expect(result.ok).toBe(false);
  });

  it("rejects duplicate action identifiers", () => {
    const result = parseSnapshot(
      mutate((value) => {
        const actions = value.actions as Array<Record<string, unknown>>;
        actions[1].id = actions[0].id;
      })
    );

    expect(result.ok).toBe(false);
  });

  it("rejects an action beyond the catalog bound", () => {
    const result = parseSnapshot(
      mutate((value) => {
        value.actions = Array.from({ length: MAX_ACTIONS + 1 }, () => null);
      })
    );

    expect(result.ok).toBe(false);
  });

  it("rejects a malformed argument vector", () => {
    const result = parseSnapshot(
      mutate((value) => {
        const actions = value.actions as Array<Record<string, unknown>>;
        actions[0].argv_preview = "aurascan --pkg example";
      })
    );

    expect(result.ok).toBe(false);
  });
});

describe("helpers", () => {
  it("counts check statuses", () => {
    expect(
      countChecks([
        { name: "a", status: "ok", message: "" },
        { name: "b", status: "warn", message: "" },
        { name: "c", status: "error", message: "" },
        { name: "d", status: "ok", message: "" }
      ])
    ).toEqual({ ok: 2, warn: 1, error: 1 });
  });

  it("shortens digests for display", () => {
    expect(shortDigest(undefined)).toBe("—");
    expect(shortDigest("abcd")).toBe("abcd");
    expect(shortDigest("0123456789abcdef0123456789abcdef")).toBe("0123456789ab…");
  });
});
