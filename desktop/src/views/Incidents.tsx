import type { IncidentsPayload } from "../contract";
import { StatusBadge } from "../components/StatusBadge";

export function Incidents({ incidents }: { incidents: IncidentsPayload }) {
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
    </div>
  );
}
