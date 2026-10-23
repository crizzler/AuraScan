import type { ActionSpec } from "../contract";
import { StatusBadge } from "../components/StatusBadge";

function ActionCard({ action }: { action: ActionSpec }) {
  return (
    <li className="action">
      <div className="action__head">
        <div>
          <div className="action__label">{action.label}</div>
          <div className="mono action__id">{action.id}</div>
        </div>
        <StatusBadge
          tone={action.renderer_may_request ? "neutral" : "warn"}
          label={action.renderer_may_request ? "REQUESTABLE" : "TERMINAL ONLY"}
        />
      </div>
      <p className="action__summary">{action.summary}</p>
      {action.arguments.length > 0 ? (
        <div className="action__args">
          <span className="action__args-label">Requires</span>
          {action.arguments.map((argument) => (
            <span className="badge badge--meta" key={argument.name}>
              {argument.label}
            </span>
          ))}
        </div>
      ) : null}
      <pre className="argv">{action.argv_preview.join(" ")}</pre>
      <p className="action__notes">{action.notes}</p>
    </li>
  );
}

export function Actions({ actions }: { actions: ActionSpec[] }) {
  const requestable = actions.filter((action) => action.renderer_may_request);
  const terminalOnly = actions.filter((action) => !action.renderer_may_request);

  return (
    <div className="stack">
      <section className="card card--muted">
        <h2>How actions work</h2>
        <ul className="rules">
          <li>The renderer selects an action ID and its declared arguments, never a command.</li>
          <li>The desktop shell runs the fixed argument vector shown on each action.</li>
          <li>Mutating actions stay in the terminal and require a fresh confirmation.</li>
          <li>This prototype cannot execute actions. It lists the catalog only.</li>
        </ul>
      </section>

      {requestable.length > 0 ? (
        <section className="card">
          <header className="card__header">
            <h2>Available to the desktop shell</h2>
            <span className="group-count">{requestable.length}</span>
          </header>
          <ul className="action-list">
            {requestable.map((action) => (
              <ActionCard action={action} key={action.id} />
            ))}
          </ul>
        </section>
      ) : null}

      {terminalOnly.length > 0 ? (
        <section className="card">
          <header className="card__header">
            <h2>Terminal only</h2>
            <span className="group-count">{terminalOnly.length}</span>
          </header>
          <ul className="action-list">
            {terminalOnly.map((action) => (
              <ActionCard action={action} key={action.id} />
            ))}
          </ul>
        </section>
      ) : null}
    </div>
  );
}
