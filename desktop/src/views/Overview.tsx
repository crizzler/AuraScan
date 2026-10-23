import type { DoctorPayload, IncidentsPayload, IntelligencePayload } from "../contract";
import { countChecks, shortDigest } from "../contract";
import { StatusBadge } from "../components/StatusBadge";

export function Overview({
  doctor,
  intelligence,
  incidents
}: {
  doctor: DoctorPayload;
  intelligence?: IntelligencePayload;
  incidents?: IncidentsPayload;
}) {
  const counts = countChecks(doctor.checks);

  return (
    <div className="stack">
      <section className="card">
        <header className="card__header">
          <h2>System checks</h2>
          <StatusBadge tone={doctor.ok ? "ok" : "error"} label={doctor.ok ? "NO ERRORS" : "ATTENTION"} />
        </header>
        <div className="stat-grid">
          <div className="stat">
            <span className="stat__value">{counts.ok}</span>
            <span className="stat__label">verified</span>
          </div>
          <div className="stat">
            <span className="stat__value stat__value--warn">{counts.warn}</span>
            <span className="stat__label">warnings</span>
          </div>
          <div className="stat">
            <span className="stat__value stat__value--error">{counts.error}</span>
            <span className="stat__label">errors</span>
          </div>
          <div className="stat">
            <span className="stat__value">{doctor.checks.length}</span>
            <span className="stat__label">checks collected</span>
          </div>
        </div>
        <p className="card__note">
          A warning is a local state that needs review. An error is a failed check,
          not a confirmed compromise.
        </p>
      </section>

      <div className="two-up">
        <section className="card">
          <header className="card__header">
            <h2>Detection data</h2>
            <StatusBadge
              tone={!intelligence || intelligence.status === "unavailable" ? "unavailable" : "neutral"}
              label={(intelligence?.status ?? "unavailable").toUpperCase()}
            />
          </header>
          {intelligence ? (
            <dl className="kv">
              <div>
                <dt>Source</dt>
                <dd>{intelligence.source ?? "—"}</dd>
              </div>
              <div>
                <dt>Update channel</dt>
                <dd>{intelligence.update_channel ?? "—"}</dd>
              </div>
              <div>
                <dt>Schema / sequence</dt>
                <dd>
                  {intelligence.schema_version ?? "—"} / {intelligence.sequence ?? "—"}
                </dd>
              </div>
              <div>
                <dt>Reviewed</dt>
                <dd>{intelligence.reviewed_at ?? "—"}</dd>
              </div>
              <div>
                <dt>Identity</dt>
                <dd className="mono" title={intelligence.identity}>
                  {shortDigest(intelligence.identity)}
                </dd>
              </div>
              <div>
                <dt>Digest</dt>
                <dd className="mono" title={intelligence.digest}>
                  {shortDigest(intelligence.digest)}
                </dd>
              </div>
            </dl>
          ) : (
            <p className="empty">
              Detection-data identity was not included in this snapshot.
            </p>
          )}
        </section>

        <section className="card">
          <header className="card__header">
            <h2>Incidents</h2>
            {incidents && incidents.available && incidents.highest_severity ? (
              <StatusBadge tone={incidents.highest_severity} />
            ) : (
              <StatusBadge tone={incidents && incidents.available ? "neutral" : "unavailable"} />
            )}
          </header>
          {incidents ? (
            incidents.available ? (
              <>
                <div className="stat-grid stat-grid--tight">
                  <div className="stat">
                    <span className="stat__value">{incidents.pending}</span>
                    <span className="stat__label">pending markers</span>
                  </div>
                  <div className="stat">
                    <span className="stat__value">{incidents.unseen}</span>
                    <span className="stat__label">unseen</span>
                  </div>
                </div>
                <p className="card__note">
                  {incidents.pending === 0
                    ? "No incident markers are currently pending."
                    : "Markers describe collected crash evidence. Resolution requires a guided review."}
                </p>
              </>
            ) : (
              <p className="empty">
                Incident state could not be read. Counts are withheld rather than shown
                as zero.
              </p>
            )
          ) : (
            <p className="empty">Incident state was not included in this snapshot.</p>
          )}
        </section>
      </div>

      <section className="card card--muted">
        <h2>What this view is not</h2>
        <ul className="rules">
          <li>Not a certification that a package, host, or configuration is safe.</li>
          <li>Not a scan result: no package archive was inspected for this snapshot.</li>
          <li>Not evidence that statically observed behavior ran on this machine.</li>
        </ul>
      </section>
    </div>
  );
}
