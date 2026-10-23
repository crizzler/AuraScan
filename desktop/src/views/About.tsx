import { UI_CONTRACT } from "../contract";
import type { Snapshot } from "../contract";

export function About({ snapshot }: { snapshot: Snapshot }) {
  return (
    <div className="stack">
      <section className="card">
        <header className="card__header">
          <h2>Contract</h2>
          <span className="badge badge--check badge--ok">{UI_CONTRACT}</span>
        </header>
        <dl className="kv">
          <div>
            <dt>AuraScan</dt>
            <dd className="mono">{snapshot.app.version}</dd>
          </div>
          <div>
            <dt>Python</dt>
            <dd className="mono">{snapshot.app.python}</dd>
          </div>
          <div>
            <dt>Platform</dt>
            <dd className="mono">{snapshot.app.platform}</dd>
          </div>
        </dl>
        <p className="card__note">
          The renderer fails closed. If the snapshot declares a different contract,
          contains an unsupported check status, or exceeds the documented bound, no
          evidence is displayed at all.
        </p>
      </section>

      <section className="card">
        <h2>Evidence rules</h2>
        <ul className="rules">
          <li>Severity, confidence, and coverage are produced by AuraScan, never here.</li>
          <li>No package, hook, source, or instruction file is executed by this app.</li>
          <li>No network request, model call, or package-manager action is started here.</li>
          <li>AI output is advisory and is never rendered as an action or instruction.</li>
        </ul>
      </section>

      <section className="card card--muted">
        <h2>Prototype status</h2>
        <p className="card__note">
          This is the phase 2 read-only renderer described in
          <span className="mono"> docs/DESKTOP_UI_DESIGN.md</span>. It is not
          packaged, not installed with AuraScan, and has no action surface yet.
        </p>
      </section>
    </div>
  );
}
