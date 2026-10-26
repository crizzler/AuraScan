import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";

import {
  MAX_NPM_AUDIT_FINDINGS,
  NPM_AUDIT_SCHEMA,
  parseNpmAuditReport
} from "./contract";

const require = createRequire(import.meta.url);
const helpers = require("../electron/argv.cjs") as {
  NPM_AUDIT_SCHEMA: string;
  READ_ONLY_ACTIONS: readonly string[];
  MUTATING_ACTIONS: readonly string[];
  actionArgv: (id: string, values?: Record<string, unknown>) => string[] | null;
  parseNpmAudit: (stdout: string) => { schema: string; counts: { blocking: number } };
};

function auditFixture(): Record<string, unknown> {
  return {
    schema: NPM_AUDIT_SCHEMA,
    path: "/home/user/project",
    manifest: "package.json",
    lifecycle_hooks: ["preinstall", "install", "postinstall", "prepare"],
    inspected_install_files: ["/home/user/project/setup.js"],
    findings: [
      {
        rule_id: "SUPPLYCHAIN-NPM-INSTALL-ENV-EXFIL-EVAL-001",
        severity: "CRITICAL",
        confidence: "high",
        file: "/home/user/project/setup.js",
        line: 2,
        explanation: "Install-time code reads environment variables.",
        recommendation: "Do not run npm install here.",
        blocks_installation: true,
        requires_manual_review: false,
        evidence: "environment access; network destination; dynamic code evaluation"
      }
    ],
    counts: { total: 1, blocking: 1 },
    coverage: {
      project_install_code: "inspected",
      dependency_lifecycle_scripts: "unknown: they require package metadata"
    },
    ok: false
  };
}

describe("shell npm-audit action", () => {
  it("runs only the fixed audit argv for an absolute project path", () => {
    expect(helpers.actionArgv("npm_audit", { project_path: "/home/user/project" })).toEqual([
      "npm-audit",
      "/home/user/project",
      "--json"
    ]);
    expect(helpers.actionArgv("npm_audit", { project_path: "project" })).toBeNull();
    expect(helpers.actionArgv("npm_audit", { project_path: "-rf" })).toBeNull();
    expect(helpers.actionArgv("npm_audit", { project_path: "/tmp/a\nb" })).toBeNull();
    expect(helpers.actionArgv("npm_audit", {})).toBeNull();
    // The audit never mutates anything, so it stays in the read-only set.
    expect(helpers.READ_ONLY_ACTIONS).toContain("npm_audit");
    expect(helpers.MUTATING_ACTIONS).not.toContain("npm_audit");
    expect(helpers.NPM_AUDIT_SCHEMA).toBe(NPM_AUDIT_SCHEMA);
  });

  it("accepts a bounded report and refuses anything unexpected", () => {
    const valid = JSON.stringify(auditFixture());

    expect(helpers.parseNpmAudit(valid).counts.blocking).toBe(1);
    expect(() => helpers.parseNpmAudit(JSON.stringify({ schema: "other/1" }))).toThrow();
    expect(() => helpers.parseNpmAudit("not json")).toThrow();
    expect(() =>
      helpers.parseNpmAudit(JSON.stringify({ ...auditFixture(), ok: "no" }))
    ).toThrow();
    expect(() =>
      helpers.parseNpmAudit(
        JSON.stringify({ ...auditFixture(), findings: [{ rule_id: "X" }] })
      )
    ).toThrow();
    expect(() =>
      helpers.parseNpmAudit(
        JSON.stringify({
          ...auditFixture(),
          findings: [{ rule_id: "R", severity: "HIGH", blocks_installation: "yes" }]
        })
      )
    ).toThrow();
  });
});

describe("parseNpmAuditReport", () => {
  it("keeps the coverage strings instead of collapsing them", () => {
    const result = parseNpmAuditReport(auditFixture());

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.report.blocking).toBe(1);
    expect(result.report.findings[0].line).toBe(2);
    expect(result.report.findings[0].blocks_installation).toBe(true);
    expect(result.report.dependency_lifecycle_scripts).toContain("unknown");
    expect(result.report.inspected_install_files).toHaveLength(1);
  });

  it("rejects a payload that would imply a safety verdict it did not carry", () => {
    expect(parseNpmAuditReport(null).ok).toBe(false);
    expect(parseNpmAuditReport({ ...auditFixture(), schema: "aurascan-npm-audit/2" }).ok).toBe(
      false
    );
    expect(parseNpmAuditReport({ ...auditFixture(), counts: { total: 0 } }).ok).toBe(false);
    expect(parseNpmAuditReport({ ...auditFixture(), coverage: null }).ok).toBe(false);
    expect(
      parseNpmAuditReport({
        ...auditFixture(),
        findings: new Array(MAX_NPM_AUDIT_FINDINGS + 1).fill(auditFixture().findings)
      }).ok
    ).toBe(false);
    expect(
      parseNpmAuditReport({
        ...auditFixture(),
        findings: [
          {
            rule_id: "R",
            severity: "SEVERE",
            confidence: "high",
            file: "/f",
            blocks_installation: true
          }
        ]
      }).ok
    ).toBe(false);
  });
});
