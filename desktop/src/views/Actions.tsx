import type { ActionSpec, NpmAuditReport } from "../contract";
import { StatusBadge } from "../components/StatusBadge";

const SHELL_ACTIONS = new Set(["refresh_snapshot", "project_report"]);

function ActionCard({
  action,
  shellAvailable,
  onRefresh,
  onOpenReport
}: {
  action: ActionSpec;
  shellAvailable: boolean;
  onRefresh: () => void;
  onOpenReport: () => void;
}) {
  const runnable = shellAvailable && SHELL_ACTIONS.has(action.id);
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
      {runnable ? (
        <button
          type="button"
          className="button"
          onClick={action.id === "refresh_snapshot" ? onRefresh : onOpenReport}
        >
          {action.id === "refresh_snapshot" ? "Refresh now" : "Choose report…"}
        </button>
      ) : null}
    </li>
  );
}

function AuditResult({ report }: { report: NpmAuditReport }) {
  const blocking = report.findings.filter((finding) => finding.blocks_installation);
  const review = report.findings.filter((finding) => !finding.blocks_installation);
  return (
    <div className="stack">
      <p className="card__note mono">{report.path}</p>
      <p className="card__note">
        Install-time files read: {report.inspected_install_files.length}. Project install code:{" "}
        {report.project_install_code}. Dependency lifecycle scripts: {report.dependency_lifecycle_scripts}.
      </p>
      {report.findings.length === 0 ? (
        <p className="card__note">
          Nothing in the project&apos;s own install-time code matched. That is not proof the
          project is safe to install.
        </p>
      ) : null}
      <ul className="rules">
        {[...blocking, ...review].map((finding) => (
          <li key={`${finding.rule_id}-${finding.file}-${finding.line}`}>
            <StatusBadge
              tone={finding.blocks_installation ? "error" : "warn"}
              label={`${finding.blocks_installation ? "BLOCK" : "REVIEW"} ${finding.severity}`}
            />{" "}
            <span className="mono">{finding.rule_id}</span>
            <div className="card__note mono">
              {finding.file}
              {finding.line > 0 ? `:${finding.line}` : ""}
            </div>
            <div className="card__note">{finding.explanation}</div>
            <div className="card__note">{finding.recommendation}</div>
          </li>
        ))}
      </ul>
      <p className="card__note">
        Static evidence does not prove the code ran. If you must install a project you do not
        trust, use a disposable environment without credentials, or install with npm install
        --ignore-scripts and run only the scripts you reviewed.
      </p>
    </div>
  );
}

export function Actions({
  actions,
  shellAvailable,
  notice,
  audit,
  auditLoading,
  auditError,
  onAuditProject,
  onRefresh,
  onOpenReport,
  onOpenUpgrade
}: {
  actions: ActionSpec[];
  shellAvailable: boolean;
  notice: string;
  audit: NpmAuditReport | null;
  auditLoading: boolean;
  auditError: string;
  onAuditProject: () => void;
  onRefresh: () => void;
  onOpenReport: () => void;
  onOpenUpgrade: () => void;
}) {
  const requestable = actions.filter((action) => action.renderer_may_request);
  const terminalOnly = actions.filter((action) => !action.renderer_may_request);

  return (
    <div className="stack">
      <section className="card">
        <header className="card__header">
          <h2>System upgrade</h2>
          <StatusBadge tone="neutral" label="needs root" />
        </header>
        <p className="card__note">
          An upgrade applies package transactions as root, so this console never runs it
          directly and never holds a password. The button opens the AuraScan upgrade wizard
          in a terminal: it runs the preflight, shows every risk it found, and takes your
          sudo prompt. That is the same fraction of a second a helper spends asking for
          elevation — the difference is that you see the plan first.
        </p>
        {shellAvailable ? (
          <button type="button" className="button" onClick={onOpenUpgrade}>
            Open upgrade in terminal
          </button>
        ) : (
          <pre className="argv">aurascan upgrade</pre>
        )}
        {notice ? <p className="card__note">{notice}</p> : null}
      </section>

      <section className="card">
        <header className="card__header">
          <h2>Review a project before npm install</h2>
          <StatusBadge tone="neutral" label="offline" />
        </header>
        <p className="card__note">
          A folder someone sent you can run code the moment you type npm install. This
          reads package.json and the project files its preinstall, install, postinstall,
          and prepare commands name, as inert text. It does not run npm, node, a shell, or
          the project, and it does not contact a registry.
        </p>
        {shellAvailable ? (
          <button type="button" className="button" onClick={onAuditProject} disabled={auditLoading}>
            {auditLoading ? "Reviewing…" : "Choose project folder…"}
          </button>
        ) : (
          <pre className="argv">aurascan npm-audit .</pre>
        )}
        {auditError ? <p className="card__note">{auditError}</p> : null}
        {audit ? <AuditResult report={audit} /> : null}
      </section>

      <section className="card card--muted">
        <h2>How actions work</h2>
        <ul className="rules">
          <li>The renderer selects an action ID and its declared arguments, never a command.</li>
          <li>The desktop shell runs the fixed argument vector shown on each action.</li>
          <li>Mutating actions stay in the terminal and require a fresh confirmation.</li>
          <li>
            {shellAvailable
              ? "The desktop shell runs the two read-only actions below through its fixed bridge."
              : "This browser prototype cannot execute actions. It lists the catalog only."}
          </li>
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
              <ActionCard
                action={action}
                key={action.id}
                shellAvailable={shellAvailable}
                onRefresh={onRefresh}
                onOpenReport={onOpenReport}
              />
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
              <ActionCard
                action={action}
                key={action.id}
                shellAvailable={false}
                onRefresh={onRefresh}
                onOpenReport={onOpenReport}
              />
            ))}
          </ul>
        </section>
      ) : null}
    </div>
  );
}
