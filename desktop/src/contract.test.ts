import { describe, expect, it } from "vitest";

import sample from "./fixtures/snapshot.sample.json";
import { MAX_CHECKS, UI_CONTRACT, countChecks, parseSnapshot, shortDigest } from "./contract";

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
    expect(result.snapshot.doctor.checks.length).toBe(sample.doctor.checks.length);
    expect(result.snapshot.incidents.highest_severity).toBe("HIGH");
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
      expect(result.snapshot.incidents.available).toBe(false);
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
        "incidents"
      ]);
    }
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
