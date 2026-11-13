import type { AgentAuditReport, AgentSurface } from "../contract";
import { AGENT_SURFACES, shortDigest } from "../contract";
import { StatusBadge } from "../components/StatusBadge";

interface AgentGuardProps {
  report: AgentAuditReport | null;
  loading: boolean;
  error: string;
  notice: string;
  busy: boolean;
  shellAvailable: boolean;
  onAudit: (surface: AgentSurface) => void;
}

export function AgentGuard({
  report,
  loading,
  error,
  notice,
  busy,
  shellAvailable,
  onAudit
}: AgentGuardProps) {
  return (
    <div className="stack">
      <section className="card">
        <header className="card__header">
          <h2>External agent blast radius</h2>
          <StatusBadge tone="neutral" label="read only" />
        </header>
        <p className="card__note">
          Choose one project or home directory and one agent surface. AuraScan reads only the
          selected surface&apos;s configuration as inert data. It never runs the agent, a model,
          a hook, an MCP server, or project code, and this view never offers a hardening action.
        </p>
        <div className="chip-row">
          <label className="card__note" htmlFor="agent-surface">
            Surface
          </label>
          <select
            id="agent-surface"
            className="input"
            defaultValue="codex"
            disabled={loading || busy}
            onChange={(event) => {
              const value = event.target.value;
              if (AGENT_SURFACES.includes(value as AgentSurface)) {
                onAudit(value as AgentSurface);
              }
            }}
          >
            <option value="codex">Codex CLI</option>
            <option value="claude">Claude Code</option>
            <option value="cursor">Cursor</option>
            <option value="mcp">MCP project manifest</option>
          </select>
          {shellAvailable ? (
            <span className="card__note">
              Choosing a surface opens a folder picker. Nothing is written.
            </span>
          ) : (
            <span className="card__note mono">aurascan agent-audit --surface codex</span>
          )}
        </div>
        {loading ? <p className="card__note">Reading the selected configuration…</p> : null}
        {error ? (
          <div className="banner banner--error" role="alert">
            {error}
          </div>
        ) : null}
        {notice ? <p className="card__note">{notice}</p> : null}
      </section>

      {report ? (
        <>
          <section className="card">
            <header className="card__header">
              <h2>{report.surface} surface</h2>
              <StatusBadge
                tone={report.coverage_complete ? "ok" : "warn"}
                label={report.coverage_complete ? "complete" : "incomplete"}
              />
              <StatusBadge
                tone={report.execution_authority.observed ? "warn" : "neutral"}
                label={report.execution_authority.observed ? "authority" : "no authority"}
              />
            </header>
            <div className="stat-grid">
              <div className="stat">
                <span className="stat__value">{report.secret_classes.length}</span>
                <span className="stat__label">secret classes</span>
              </div>
              <div className="stat">
                <span className="stat__value stat__value--warn">{report.finding_counts.HIGH}</span>
                <span className="stat__label">high findings</span>
              </div>
              <div className="stat">
                <span className="stat__value">{report.execution_authority.channels.length}</span>
                <span className="stat__label">execution channels</span>
              </div>
              <div className="stat">
                <span className="stat__value">{report.aggregate.status}</span>
                <span className="stat__label">aggregate</span>
              </div>
            </div>
            <dl className="kv">
              <div>
                <dt>Execution authority</dt>
                <dd>{report.execution_authority.observed ? "observed" : "not observed"}</dd>
              </div>
              <div>
                <dt>Approval mode</dt>
                <dd>{report.execution_authority.approval_mode}</dd>
              </div>
              <div>
                <dt>Host isolation</dt>
                <dd>{report.host_isolation} (not proven)</dd>
              </div>
              <div>
                <dt>Captured</dt>
                <dd className="mono">{report.captured_at}</dd>
              </div>
              <div>
                <dt>Evidence digest</dt>
                <dd className="mono" title={report.evidence_digest}>
                  {shortDigest(report.evidence_digest)}
                </dd>
              </div>
            </dl>
            {report.secret_classes.length > 0 ? (
              <ul className="rules">
                {report.secret_classes.map((entry) => (
                  <li key={entry.class}>
                    <span className="mono">{entry.class}</span>: {entry.count}
                  </li>
                ))}
              </ul>
            ) : null}
          </section>

          <section className="card card--muted">
            <h2>What this does not say</h2>
            <p className="card__note">{report.banner}</p>
            <p className="card__note">
              The report can show a high-blast-radius setup even when the model is honest. It
              cannot prove that a model is malicious, that a trigger fired, or that a credential
              left the host. Exit 0 is not a model-safety verdict.
            </p>
          </section>
        </>
      ) : (
        <section className="card card--muted">
          <p className="card__note">
            No audit has been run in this session. Choose a surface to select a directory and
            produce a read-only snapshot.
          </p>
        </section>
      )}
    </div>
  );
}
