import { useCallback, useEffect, useMemo, useState } from "react";

import sample from "./fixtures/snapshot.sample.json";
import { countChecks, parseIncidentReport, parseReview, parseSettings, parseSettingsWrite, parseSnapshot } from "./contract";
import type { IncidentReport, ReviewCandidate, ReviewReport, SettingsPayload, Snapshot } from "./contract";
import { desktopBridge } from "./desktop";
import type { ShellResult } from "./desktop";
import { About } from "./views/About";
import { Actions } from "./views/Actions";
import { Checks } from "./views/Checks";
import { Incidents } from "./views/Incidents";
import { Instructions } from "./views/Instructions";
import { Overview } from "./views/Overview";
import { Report } from "./views/Report";
import { Settings } from "./views/Settings";

const VIEWS = [
  { id: "report", label: "Report", hint: "scan" },
  { id: "actions", label: "Actions", hint: "intents" },
  { id: "overview", label: "Overview", hint: "state" },
  { id: "checks", label: "Checks", hint: "evidence" },
  { id: "incidents", label: "Incidents", hint: "attention" },
  { id: "instructions", label: "Agent files", hint: "triage" },
  { id: "settings", label: "Settings", hint: "config" },
  { id: "about", label: "About", hint: "contract" }
] as const;

type ViewId = (typeof VIEWS)[number]["id"];

const DESCRIPTIONS: Record<ViewId, string> = {
  report: "Static evidence for one package or PKGBUILD, with its coverage limits.",
  actions: "The fixed action catalog. The renderer selects IDs, never commands.",
  overview: "Machine state, detection-data identity, and pending attention.",
  checks: "Every collected check, grouped by subsystem.",
  incidents: "Crash markers that were collected for this user.",
  instructions: "Agent control files reviewed as inert text, with hash-bound triage actions.",
  settings: "Your AuraScan configuration and AI provider state. Secrets are never displayed.",
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
      case "instructions":
        return true;
      case "settings":
        return true;
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
  const [settingsRaw, setSettingsRaw] = useState<unknown>(null);
  const [settingsLoading, setSettingsLoading] = useState(false);
  const [settingsError, setSettingsError] = useState("");
  const [settingsNotice, setSettingsNotice] = useState("");
  const [settingsBusy, setSettingsBusy] = useState(false);
  const [reviewRaw, setReviewRaw] = useState<unknown>(null);
  const [reviewLoading, setReviewLoading] = useState(false);
  const [reviewError, setReviewError] = useState("");
  const [reviewNotice, setReviewNotice] = useState("");
  const [reviewBusy, setReviewBusy] = useState(false);
  const reviewParsed = useMemo(
    () => (reviewRaw === null ? null : parseReview(reviewRaw)),
    [reviewRaw]
  );
  const review: ReviewReport | null =
    reviewParsed && reviewParsed.ok ? reviewParsed.report : null;
  const reviewParseError = reviewParsed && !reviewParsed.ok ? reviewParsed.reason : "";
  const [diagnosisRaw, setDiagnosisRaw] = useState<unknown>(null);
  const [diagnosisLoading, setDiagnosisLoading] = useState(false);
  const [diagnosisError, setDiagnosisError] = useState("");
  const [diagnosisNotice, setDiagnosisNotice] = useState("");
  const [diagnosisBusy, setDiagnosisBusy] = useState(false);
  const diagnosisParsed = useMemo(
    () => (diagnosisRaw === null ? null : parseIncidentReport(diagnosisRaw)),
    [diagnosisRaw]
  );
  const diagnosis: IncidentReport | null =
    diagnosisParsed && diagnosisParsed.ok ? diagnosisParsed.report : null;
  const diagnosisParseError =
    diagnosisParsed && !diagnosisParsed.ok ? diagnosisParsed.reason : "";
  const settingsParsed = useMemo(
    () => (settingsRaw === null ? null : parseSettings(settingsRaw)),
    [settingsRaw]
  );
  const settings: SettingsPayload | null =
    settingsParsed && settingsParsed.ok ? settingsParsed.settings : null;
  const settingsParseError =
    settingsParsed && !settingsParsed.ok ? settingsParsed.reason : "";
  const [view, setView] = useState<ViewId>(() => {
    const search =
      typeof globalThis.location?.search === "string" ? globalThis.location.search : "";
    const requested = new URLSearchParams(search).get("view");
    if (requested && VIEWS.some((entry) => entry.id === requested)) {
      return requested as ViewId;
    }
    if (parsed.ok && parsed.snapshot.report) {
      return "report";
    }
    if (parsed.ok && parsed.snapshot.actions) {
      return "actions";
    }
    return "overview";
  });

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
          setRaw(result.payload);
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
        : active.id === "instructions"
          ? review
            ? `${plural(review.candidate_count, "candidate")} · ${review.highest_severity}`
            : "no report"
          : active.id === "settings"
          ? settings
            ? `${settings.ai.provider_label || settings.ai.provider} · ${settings.ai.ready ? "ready" : "not ready"}`
            : "unavailable"
          : counts
            ? `${plural(counts.error, "error")} · ${plural(counts.warn, "warning")}`
            : reportMeta || actionsMeta;
  const hasError =
    active.id === "actions" || active.id === "settings"
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
      setRaw(result.payload);
      setSource("shell");
      setShellError("");
      const value = result.payload as { report?: unknown } | null;
      setView(value && typeof value === "object" && "report" in value ? "report" : "overview");
      return;
    }
    if (result.canceled) {
      return;
    }
    setShellError(result.error);
  };

  const runReview = useCallback(
    (operation: "review" | "scan") => {
      if (!bridge) {
        return;
      }
      setReviewLoading(true);
      setReviewError("");
      const call = operation === "review" ? bridge.reviewInstructions() : bridge.scanInstructions();
      call
        .then((result) => {
          if (result.ok) {
            setReviewRaw(result.payload);
            setReviewNotice(operation === "scan" ? "Scan finished." : "");
            return;
          }
          if (!result.canceled) {
            setReviewError(result.error);
          }
        })
        .catch(() => setReviewError("AuraScan could not be reached"))
        .finally(() => setReviewLoading(false));
    },
    [bridge]
  );

  const runInstructionAction = async (
    action: "approve" | "disable",
    candidate: ReviewCandidate,
    reportId: string
  ) => {
    if (!bridge) {
      return;
    }
    setReviewBusy(true);
    setReviewError("");
    setReviewNotice("");
    try {
      const result =
        action === "approve"
          ? await bridge.approveInstruction(candidate.file_id, reportId, candidate.sha256)
          : await bridge.disableInstruction(candidate.file_id, reportId, candidate.sha256);
      if (!result.ok) {
        setReviewError(result.error);
        return;
      }
      setReviewNotice(
        action === "approve"
          ? `${candidate.relative_path} was approved for this exact content.`
          : `${candidate.relative_path} was disabled with a restore receipt.`
      );
      runReview("review");
    } catch {
      setReviewError("AuraScan could not be reached");
    } finally {
      setReviewBusy(false);
    }
  };

  const runIncidentAction = (action: "scan" | "resolve") => {
    if (!bridge) {
      return;
    }
    setDiagnosisLoading(true);
    setDiagnosisError("");
    setDiagnosisNotice("");
    const call = action === "scan" ? bridge.scanIncidents() : bridge.resolveIncidents();
    call
      .then((result) => {
        if (result.ok) {
          setDiagnosisRaw(result.payload);
          setDiagnosisNotice(
            action === "scan"
              ? "Diagnosis complete. No repair was applied."
              : "Markers acknowledged. The evidence itself is unchanged."
          );
          return;
        }
        if (!result.canceled) {
          setDiagnosisError(result.error);
        }
      })
      .catch(() => setDiagnosisError("AuraScan could not be reached"))
      .finally(() => setDiagnosisLoading(false));
  };

  const runShell = (operation: () => Promise<ShellResult>) => {    operation()
      .then(applyShellResult)
      .catch(() => setShellError("AuraScan could not be reached"));
  };

  const loadSettings = useCallback(() => {
    if (!bridge) {
      return;
    }
    setSettingsLoading(true);
    bridge
      .readSettings()
      .then((result) => {
        if (result.ok) {
          setSettingsRaw(result.payload);
          setSettingsError("");
          return;
        }
        if (!result.canceled) {
          setSettingsError(result.error);
        }
      })
      .catch(() => setSettingsError("AuraScan could not be reached"))
      .finally(() => setSettingsLoading(false));
  }, [bridge]);

  useEffect(() => {
    loadSettings();
  }, [loadSettings]);

  useEffect(() => {
    if (view === "instructions" && reviewRaw === null && !reviewLoading) {
      runReview("review");
    }
  }, [view, reviewRaw, reviewLoading, runReview]);

  const storeCredential = async (provider: string, secret: string) => {    if (!bridge) {
      return;
    }
    setSettingsBusy(true);
    setSettingsNotice("");
    setSettingsError("");
    try {
      const result = await bridge.setAiKey(provider, secret);
      if (!result.ok) {
        setSettingsError(result.error);
        return;
      }
      const written = parseSettingsWrite(result.payload);
      if (!written.ok) {
        setSettingsError(written.reason);
        return;
      }
      const label = written.ai.provider_label || written.ai.provider;
      setSettingsNotice(
        written.ai.enabled
          ? `Credential stored for ${label}. AI is enabled with the existing configuration.`
          : `Credential stored for ${label}. AI stays disabled until you enable it.`
      );
    } catch {
      setSettingsError("AuraScan could not be reached");
    } finally {
      setSettingsBusy(false);
    }
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
          <Incidents
            incidents={snapshot.incidents}
            diagnosis={diagnosis}
            loading={diagnosisLoading}
            error={diagnosisError || diagnosisParseError}
            notice={diagnosisNotice}
            busy={diagnosisLoading || diagnosisBusy}
            shellAvailable={Boolean(bridge)}
            onDiagnose={() => runIncidentAction("scan")}
            onResolve={() => {
              setDiagnosisBusy(true);
              runIncidentAction("resolve");
              setDiagnosisBusy(false);
            }}
          />
        )}
        {view === "instructions" && (
          <Instructions
            report={review}
            loading={reviewLoading}
            error={reviewError || reviewParseError}
            notice={reviewNotice}
            busy={reviewBusy}
            shellAvailable={Boolean(bridge)}
            onReload={() => runReview("review")}
            onScan={() => runReview("scan")}
            onApprove={(candidate) =>
              review ? runInstructionAction("approve", candidate, review.report_id) : Promise.resolve()
            }
            onDisable={(candidate) =>
              review ? runInstructionAction("disable", candidate, review.report_id) : Promise.resolve()
            }
          />
        )}
        {view === "settings" && (
          <Settings
            settings={settings}
            loading={settingsLoading}
            error={settingsError || settingsParseError}
            notice={settingsNotice}
            busy={settingsBusy}
            shellAvailable={Boolean(bridge)}
            onReload={loadSettings}
            onStoreCredential={storeCredential}
          />
        )}
        {view === "about" && <About snapshot={snapshot} />}
      </main>
    </div>
  );
}
