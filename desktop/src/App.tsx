import { useMemo, useState } from "react";

import sample from "./fixtures/snapshot.sample.json";
import { countChecks, parseSnapshot } from "./contract";
import { About } from "./views/About";
import { Checks } from "./views/Checks";
import { Incidents } from "./views/Incidents";
import { Overview } from "./views/Overview";
import { Report } from "./views/Report";

const VIEWS = [
  { id: "report", label: "Report", hint: "scan" },
  { id: "overview", label: "Overview", hint: "state" },
  { id: "checks", label: "Checks", hint: "evidence" },
  { id: "incidents", label: "Incidents", hint: "attention" },
  { id: "about", label: "About", hint: "contract" }
] as const;

type ViewId = (typeof VIEWS)[number]["id"];

const DESCRIPTIONS: Record<ViewId, string> = {
  report: "Static evidence for one package or PKGBUILD, with its coverage limits.",
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
  const [view, setView] = useState<ViewId>(
    parsed.ok && parsed.snapshot.report ? "report" : "overview"
  );

  if (!parsed.ok) {
    return (
      <div className="app app--single">
        <ParseFailure reason={parsed.reason} />
      </div>
    );
  }

  const snapshot = parsed.snapshot;
  const counts = snapshot.doctor ? countChecks(snapshot.doctor.checks) : null;
  const available = VIEWS.filter((entry) => {
    switch (entry.id) {
      case "report":
        return Boolean(snapshot.report);
      case "overview":
      case "checks":
        return Boolean(snapshot.doctor);
      case "incidents":
        return Boolean(snapshot.incidents);
      default:
        return true;
    }
  });
  const active = available.find((entry) => entry.id === view) ?? available[0];
  const blocking = snapshot.report?.counts.blocking ?? 0;
  const reportMeta = snapshot.report
    ? `${plural(snapshot.report.counts.total, "finding")} · ${blocking} blocking`
    : "";
  const meta =
    active.id === "report"
      ? reportMeta
      : counts
        ? `${plural(counts.error, "error")} · ${plural(counts.warn, "warning")}`
        : reportMeta;
  const hasError = active.id === "report" ? blocking > 0 : (counts?.error ?? 0) > 0;
  const hintFor = (id: ViewId): string | number => {
    if (id === "checks" && snapshot.doctor) {
      return snapshot.doctor.checks.length;
    }
    if (id === "report" && snapshot.report) {
      return snapshot.report.counts.total;
    }
    return VIEWS.find((entry) => entry.id === id)?.hint ?? "";
  };

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
          {available.map((entry) => (
            <button
              key={entry.id}
              type="button"
              className={entry.id === view ? "nav__item is-active" : "nav__item"}
              onClick={() => setView(entry.id)}
              aria-current={entry.id === view ? "page" : undefined}
            >
              <span>{entry.label}</span>
              <span className="nav__hint">{hintFor(entry.id)}</span>
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
            <span className={hasError ? "dot dot--error" : "dot dot--ok"} aria-hidden="true" />
            <span>{meta}</span>
          </div>
        </header>

        {view === "report" && snapshot.report && <Report report={snapshot.report} />}
        {view === "overview" && snapshot.doctor && (
          <Overview
            doctor={snapshot.doctor}
            intelligence={snapshot.intelligence}
            incidents={snapshot.incidents}
          />
        )}
        {view === "checks" && snapshot.doctor && <Checks checks={snapshot.doctor.checks} />}
        {view === "incidents" && snapshot.incidents && (
          <Incidents incidents={snapshot.incidents} />
        )}
        {view === "about" && <About snapshot={snapshot} />}
      </main>
    </div>
  );
}
