import { useEffect, useMemo, useState } from "react";

import sample from "./fixtures/snapshot.sample.json";
import { countChecks, parseSnapshot } from "./contract";
import type { Snapshot } from "./contract";
import { desktopBridge } from "./desktop";
import type { ShellResult } from "./desktop";
import { About } from "./views/About";
import { Actions } from "./views/Actions";
import { Checks } from "./views/Checks";
import { Incidents } from "./views/Incidents";
import { Overview } from "./views/Overview";
import { Report } from "./views/Report";

const VIEWS = [
  { id: "report", label: "Report", hint: "scan" },
  { id: "actions", label: "Actions", hint: "intents" },
  { id: "overview", label: "Overview", hint: "state" },
  { id: "checks", label: "Checks", hint: "evidence" },
  { id: "incidents", label: "Incidents", hint: "attention" },
  { id: "about", label: "About", hint: "contract" }
] as const;

type ViewId = (typeof VIEWS)[number]["id"];

const DESCRIPTIONS: Record<ViewId, string> = {
  report: "Static evidence for one package or PKGBUILD, with its coverage limits.",
  actions: "The fixed action catalog. The renderer selects IDs, never commands.",
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

function availableViews(snapshot: Snapshot) {
  return VIEWS.filter((entry) => {
    switch (entry.id) {
      case "report":
        return Boolean(snapshot.report);
      case "actions":
        return Boolean(snapshot.actions);
      case "overview":
      case "checks":
        return Boolean(snapshot.doctor);
      case "incidents":
        return Boolean(snapshot.incidents);
      default:
        return true;
    }
  });
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
  const bridge = useMemo(() => desktopBridge(), []);
  const [raw, setRaw] = useState<unknown>(sample);
  const [source, setSource] = useState<"fixture" | "shell">("fixture");
  const [shellError, setShellError] = useState("");
  const parsed = useMemo(() => parseSnapshot(raw), [raw]);
  const [view, setView] = useState<ViewId>(
    parsed.ok && parsed.snapshot.report
      ? "report"
      : parsed.ok && parsed.snapshot.actions
        ? "actions"
        : "overview"
  );

  const available = parsed.ok ? availableViews(parsed.snapshot) : [];
  const availableKey = available.map((entry) => entry.id).join(",");

  useEffect(() => {
    if (available.length > 0 && !available.some((entry) => entry.id === view)) {
      setView(available[0].id);
    }
  }, [availableKey, view]);

  useEffect(() => {
    if (!bridge) {
      return;
    }
    let active = true;
    bridge
      .refresh()
      .then((result) => {
        if (!active) {
          return;
        }
        if (result.ok) {
          setRaw(result.snapshot);
          setSource("shell");
          setShellError("");
        } else if (!result.canceled) {
          setShellError(result.error);
        }
      })
      .catch(() => {
        if (active) {
          setShellError("AuraScan could not be reached");
        }
      });
    return () => {
      active = false;
    };
  }, [bridge]);

  if (!parsed.ok) {
    return (
      <div className="app app--single">
        <ParseFailure reason={parsed.reason} />
      </div>
    );
  }

  const snapshot = parsed.snapshot;
  const counts = snapshot.doctor ? countChecks(snapshot.doctor.checks) : null;
  const active = available.find((entry) => entry.id === view) ?? available[0];
  const blocking = snapshot.report?.counts.blocking ?? 0;
  const reportMeta = snapshot.report
    ? `${plural(snapshot.report.counts.total, "finding")} · ${blocking} blocking`
    : "";
  const actionsMeta = snapshot.actions ? plural(snapshot.actions.length, "action") : "";
  const meta =
    active.id === "report"
      ? reportMeta
      : active.id === "actions"
        ? actionsMeta
        : counts
          ? `${plural(counts.error, "error")} · ${plural(counts.warn, "warning")}`
          : reportMeta || actionsMeta;
  const hasError =
    active.id === "actions"
      ? false
      : active.id === "report"
        ? blocking > 0
        : (counts?.error ?? 0) > 0;
  const hintFor = (id: ViewId): string | number => {
    if (id === "checks" && snapshot.doctor) {
      return snapshot.doctor.checks.length;
    }
    if (id === "report" && snapshot.report) {
      return snapshot.report.counts.total;
    }
    if (id === "actions" && snapshot.actions) {
      return snapshot.actions.length;
    }
    return VIEWS.find((entry) => entry.id === id)?.hint ?? "";
  };

  const applyShellResult = (result: ShellResult) => {
    if (result.ok) {
      setRaw(result.snapshot);
      setSource("shell");
      setShellError("");
      const value = result.snapshot as { report?: unknown } | null;
      setView(value && typeof value === "object" && "report" in value ? "report" : "overview");
      return;
    }
    if (result.canceled) {
      return;
    }
    setShellError(result.error);
  };

  const runShell = (operation: () => Promise<ShellResult>) => {
    operation()
      .then(applyShellResult)
      .catch(() => setShellError("AuraScan could not be reached"));
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

      <main className="main" data-snapshot-source={source}>
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

        {shellError ? (
          <div className="banner banner--error" role="alert">
            {shellError}
          </div>
        ) : null}

        {view === "report" && snapshot.report && <Report report={snapshot.report} />}
        {view === "actions" && snapshot.actions && (
          <Actions
            actions={snapshot.actions}
            shellAvailable={Boolean(bridge)}
            onRefresh={() => {
              if (bridge) {
                runShell(() => bridge.refresh());
              }
            }}
            onOpenReport={() => {
              if (bridge) {
                runShell(() => bridge.openReport());
              }
            }}
          />
        )}
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
