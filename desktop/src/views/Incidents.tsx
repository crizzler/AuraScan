import type { IncidentReport, IncidentsPayload } from "../contract";
import { StatusBadge } from "../components/StatusBadge";

const PRIVILEGED_STEPS = [
  { label: "Preview an upgrade", command: "aurascan upgrade --json" },
  { label: "Apply an upgrade", command: "aurascan upgrade" },
  { label: "Run maintenance", command: "aurascan incidents --run-maintenance" },
  { label: "Install the recovery image", command: "aurascan recovery --install" }
];

interface IncidentsProps {
  incidents: IncidentsPayload;
  diagnosis: IncidentReport | null;
  loading: boolean;
  error: string;
  notice: string;
  busy: boolean;
  shellAvailable: boolean;
  onDiagnose: () => void;
  onResolve: () => void;
}

export function Incidents({
  incidents,
  diagnosis,
  loading,
  error,
  notice,
  busy,
  shellAvailable,
  onDiagnose,
  onResolve
}: IncidentsProps) {
  if (!incidents.available) {
    return (
      <section className="card">
        <header className="card__header">
          <h2>Incident state</h2>
          <StatusBadge tone="unavailable" />
        </header>
        <p className="empty">
          Incident markers could not be read. This view stays empty instead of
          reporting zero, because a zero here would look like a clean result.
        </p>
      </section>
    );
  }

  return (
    <div className="stack">
      <section className="card">
        <header className="card__header">
          <h2>Pending markers</h2>
          {incidents.highest_severity ? (
            <StatusBadge tone={incidents.highest_severity} />
          ) : (
            <StatusBadge tone="neutral" />
          )}
        </header>
        <div className="stat-grid stat-grid--tight">
          <div className="stat">
            <span className="stat__value">{incidents.pending}</span>
            <span className="stat__label">pending</span>
          </div>
          <div className="stat">
            <span className="stat__value">{incidents.unseen}</span>
            <span className="stat__label">unseen</span>
          </div>
        </div>
        {incidents.pending === 0 ? (
          <p className="empty">No incident markers are currently pending.</p>
        ) : (
          <p className="card__note">
            A marker records crash evidence that AuraScan collected for this user.
            It is not by itself proof of compromise, and resolving it requires the
            guided repair review in the terminal.
          </p>
        )}
      </section>

      <section className="card card--muted">
        <h2>How markers are counted</h2>
        <ul className="rules">
          <li>Only markers for the current user scope are counted.</li>
          <li>Resolved categories are excluded from the pending count.</li>
          <li>Seen state suppresses duplicate attention, never the evidence itself.</li>
        </ul>
      </section>

      <section className="card">
        <div className="card__header">
          <h2>Diagnosis</h2>
          {diagnosis ? <StatusBadge tone="warn" label={`${diagnosis.findings.length} findings`} /> : null}
        </div>
        {!shellAvailable ? (
          <p className="card__note">
            Running a diagnosis needs the desktop shell. The command is
            <span className="mono"> aurascan incidents --json</span>.
          </p>
        ) : (
          <>
            <p className="card__note">
              A diagnosis collects crash, boot, and configuration evidence for this user. It
              writes a private report and never applies a repair.
            </p>
            <div className="chip-row">
              <button type="button" className="button" onClick={onDiagnose} disabled={busy}>
                {loading ? "Diagnosing…" : "Run diagnosis"}
              </button>
              <button
                type="button"
                className="button"
                onClick={onResolve}
                disabled={busy || incidents.pending === 0}
              >
                Acknowledge markers
              </button>
            </div>
            {notice ? <p className="card__note">{notice}</p> : null}
            {error ? (
              <div className="banner banner--error" role="alert">
                {error}
              </div>
            ) : null}
            {diagnosis ? (
              <>
                <dl className="kv">
                  <div>
                    <dt>Report</dt>
                    <dd className="mono">{diagnosis.incident_id}</dd>
                  </div>
                  <div>
                    <dt>Findings</dt>
                    <dd>{diagnosis.findings.length}</dd>
                  </div>
                </dl>
                {diagnosis.findings.length === 0 ? (
                  <p className="empty">This diagnosis produced no finding.</p>
                ) : (
                  <ul className="findings">
                    {diagnosis.findings.map((finding) => (
                      <li className="finding" key={`${diagnosis.incident_id}-${finding.rule_id}`}>
                        <div className="finding__head">
                          <StatusBadge tone={finding.severity} />
                          <span className="finding__rule mono">{finding.rule_id}</span>
                        </div>
                        <div className="finding__title">{finding.title}</div>
                        {finding.summary ? <p className="finding__summary">{finding.summary}</p> : null}
                        {finding.why_it_matters ? (
                          <p className="card__note">{finding.why_it_matters}</p>
                        ) : null}
                        {finding.recommended_action ? (
                          <p className="card__note">{finding.recommended_action}</p>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                )}
              </>
            ) : null}
          </>
        )}
      </section>

      <section className="card card--muted">
        <div className="card__header">
          <h2>Privileged steps</h2>
          <StatusBadge tone="neutral" label="terminal" />
        </div>
        <p className="card__note">
          These need root, so this console never runs them. Review the plan in the terminal
          before applying anything.
        </p>
        <table className="table">
          <thead>
            <tr>
              <th>Step</th>
              <th>Command</th>
            </tr>
          </thead>
          <tbody>
            {PRIVILEGED_STEPS.map((step) => (
              <tr key={step.command}>
                <td>{step.label}</td>
                <td className="mono">{step.command}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
