import { useMemo, useState } from "react";

import sample from "./fixtures/snapshot.sample.json";
import { countChecks, parseSnapshot } from "./contract";
import { About } from "./views/About";
import { Checks } from "./views/Checks";
import { Incidents } from "./views/Incidents";
import { Overview } from "./views/Overview";

const VIEWS = [
  { id: "overview", label: "Overview", hint: "state" },
  { id: "checks", label: "Checks", hint: "evidence" },
  { id: "incidents", label: "Incidents", hint: "attention" },
  { id: "about", label: "About", hint: "contract" }
] as const;

type ViewId = (typeof VIEWS)[number]["id"];

const DESCRIPTIONS: Record<ViewId, string> = {
  overview: "Machine state, detection-data identity, and pending attention.",
  checks: "Every collected check, grouped by subsystem.",
  incidents: "Crash markers that were collected for this user.",
  about: "What this view is allowed to claim."
};

function formatTimestamp(epochSeconds: number): string {
  const date = new Date(epochSeconds * 1000);
  const pad = (value: number) => String(value).padStart(2, "0");
  return (
    `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())}` +
    ` ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())} UTC`
  );
}

function plural(count: number, singular: string): string {
  return `${count} ${singular}${count === 1 ? "" : "s"}`;
}

function ParseFailure({ reason }: { reason: string }) {
  return (
    <main className="main">
      <section className="card card--danger">
        <h2>Snapshot refused</h2>
        <p>
          The renderer could not validate the evidence it received, so it is not
          displaying any of it.
        </p>
        <p className="mono">{reason}</p>
        <p className="card__note">
          Regenerate the snapshot with a matching AuraScan version, or update this
          client to the contract it reports.
        </p>
      </section>
    </main>
  );
}

export function App() {
  const parsed = useMemo(() => parseSnapshot(sample), []);
  const [view, setView] = useState<ViewId>("overview");

  if (!parsed.ok) {
    return (
      <div className="app app--single">
        <ParseFailure reason={parsed.reason} />
      </div>
    );
  }

  const snapshot = parsed.snapshot;
  const counts = countChecks(snapshot.doctor.checks);
  const active = VIEWS.find((entry) => entry.id === view) ?? VIEWS[0];

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand__mark" aria-hidden="true" />
          <div>
            <div className="brand__name">AuraScan</div>
            <div className="brand__sub">evidence console</div>
          </div>
        </div>
        <nav className="nav" aria-label="Sections">
          {VIEWS.map((entry) => (
            <button
              key={entry.id}
              type="button"
              className={entry.id === view ? "nav__item is-active" : "nav__item"}
              onClick={() => setView(entry.id)}
              aria-current={entry.id === view ? "page" : undefined}
            >
              <span>{entry.label}</span>
              <span className="nav__hint">
                {entry.id === "checks" ? snapshot.doctor.checks.length : entry.hint}
              </span>
            </button>
          ))}
        </nav>
        <div className="sidebar__footer">
          <div className="mono">{snapshot.contract}</div>
          <div>AuraScan {snapshot.app.version}</div>
          <div className="sidebar__muted">{formatTimestamp(snapshot.generated_at)}</div>
        </div>
      </aside>

      <main className="main">
        <header className="main__header">
          <div>
            <h1>{active.label}</h1>
            <p className="main__sub">{DESCRIPTIONS[active.id]}</p>
          </div>
          <div className="main__meta">
            <span className={counts.error > 0 ? "dot dot--error" : "dot dot--ok"} aria-hidden="true" />
            <span>
              {plural(counts.error, "error")} · {plural(counts.warn, "warning")}
            </span>
          </div>
        </header>

        {view === "overview" && <Overview snapshot={snapshot} />}
        {view === "checks" && <Checks checks={snapshot.doctor.checks} />}
        {view === "incidents" && <Incidents incidents={snapshot.incidents} />}
        {view === "about" && <About snapshot={snapshot} />}
      </main>
    </div>
  );
}
