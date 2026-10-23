import type { ReportFinding, ReportPayload } from "../contract";
import { StatusBadge } from "../components/StatusBadge";

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

function location(finding: ReportFinding): string {
  if (!finding.file_name) {
    return "report";
  }
  return finding.line_number === null
    ? finding.file_name
    : `${finding.file_name}:${finding.line_number}`;
}

export function Report({ report }: { report: ReportPayload }) {
  const identity = [report.package.name, report.package.version].filter(Boolean).join(" ");
  const risk = report.risk;
  const highOrCritical = report.counts.by_severity.CRITICAL + report.counts.by_severity.HIGH;

  return (
    <div className="stack">
      <section className="card">
        <header className="card__header">
          <h2 className="mono">{identity}</h2>
          {risk ? (
            <StatusBadge tone={risk.severity} />
          ) : (
            <StatusBadge tone="neutral" label="NO RISK SUMMARY" />
          )}
        </header>

        {risk ? (
          <>
            <div className="risk-line">
              <span className="risk-line__label">Recommended action</span>
              <strong className="mono">{risk.action}</strong>
              {risk.blocks_installation ? <StatusBadge tone="error" label="BLOCKING" /> : null}
              {risk.requires_manual_review ? (
                <StatusBadge tone="warn" label="MANUAL REVIEW" />
              ) : null}
            </div>
            <p className="card__note">{risk.reason}</p>
          </>
        ) : (
          <p className="card__note">This report carries no risk summary.</p>
        )}

        <div className="stat-grid">
          <div className="stat">
            <span className="stat__value">{report.counts.total}</span>
            <span className="stat__label">findings</span>
          </div>
          <div className="stat">
            <span className="stat__value stat__value--error">{report.counts.blocking}</span>
            <span className="stat__label">blocking</span>
          </div>
          <div className="stat">
            <span className="stat__value stat__value--warn">{report.counts.manual_review}</span>
            <span className="stat__label">manual review</span>
          </div>
          <div className="stat">
            <span className="stat__value">{highOrCritical}</span>
            <span className="stat__label">HIGH or CRITICAL</span>
          </div>
        </div>

        <div className="chip-row">
          {SEVERITY_ORDER.map((severity) => (
            <span className="chip" key={severity}>
              <StatusBadge tone={severity} />
              <span className="mono">{report.counts.by_severity[severity]}</span>
            </span>
          ))}
        </div>

        {report.counts.truncated ? (
          <p className="card__note">
            Display truncated to the first 500 findings. Counts cover the full report.
          </p>
        ) : null}
      </section>

      <section className="card">
        <header className="card__header">
          <h2>Findings</h2>
          <span className="group-count">{report.findings.length}</span>
        </header>
        {report.findings.length === 0 ? (
          <p className="empty">
            No findings were produced.
            {risk?.reason ? ` ${risk.reason}` : ""}
          </p>
        ) : (
          <ol className="findings">
            {report.findings.map((finding, index) => (
              <li className="finding" key={`${finding.rule_id}-${String(index)}`}>
                <div className="finding__head">
                  <div className="finding__badges">
                    <StatusBadge tone={finding.severity} />
                    <span className="badge badge--meta">confidence: {finding.confidence}</span>
                    <span className="badge badge--meta">evidence: {finding.evidence_quality}</span>
                  </div>
                  <span className="mono finding__location">{location(finding)}</span>
                </div>
                <div className="finding__rule mono">{finding.rule_id}</div>
                {finding.title ? <div className="finding__title">{finding.title}</div> : null}
                <p className="finding__summary">{finding.summary}</p>
                <dl className="finding__facts">
                  <div>
                    <dt>Phase</dt>
                    <dd className="mono">{finding.phase}</dd>
                  </div>
                  <div>
                    <dt>Source</dt>
                    <dd className="mono">{finding.source}</dd>
                  </div>
                  {finding.checked ? (
                    <div>
                      <dt>Checked</dt>
                      <dd>{finding.checked}</dd>
                    </div>
                  ) : null}
                  {finding.not_checked ? (
                    <div>
                      <dt>Not checked</dt>
                      <dd>{finding.not_checked}</dd>
                    </div>
                  ) : null}
                  {finding.recommendation ? (
                    <div>
                      <dt>Recommended</dt>
                      <dd>{finding.recommendation}</dd>
                    </div>
                  ) : null}
                </dl>
              </li>
            ))}
          </ol>
        )}
      </section>

      <section className="card card--muted">
        <h2>Report coverage</h2>
        <dl className="kv">
          <div>
            <dt>Scanner</dt>
            <dd className="mono">{report.scanner_version}</dd>
          </div>
          <div>
            <dt>Report schema</dt>
            <dd className="mono">{report.schema_version}</dd>
          </div>
          {Object.entries(report.context).map(([key, value]) => (
            <div key={key}>
              <dt>{key.replace(/_/g, " ")}</dt>
              <dd className="mono">{value}</dd>
            </div>
          ))}
        </dl>
        <p className="card__note">
          A finding is static evidence. It does not prove that the observed behavior
          ran, and the absence of findings is not proof of safety.
        </p>
      </section>
    </div>
  );
}
