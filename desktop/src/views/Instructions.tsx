import { useState } from "react";

import type { ReviewCandidate, ReviewReport } from "../contract";
import { shortDigest } from "../contract";
import { StatusBadge } from "../components/StatusBadge";

interface InstructionsProps {
  report: ReviewReport | null;
  loading: boolean;
  error: string;
  notice: string;
  busy: boolean;
  shellAvailable: boolean;
  onReload: () => void;
  onScan: () => void;
  onApprove: (candidate: ReviewCandidate) => Promise<void>;
  onDisable: (candidate: ReviewCandidate) => Promise<void>;
}

type Pending = { fileId: string; action: "approve" | "disable" } | null;

function lineRange(candidate: ReviewCandidate): string {
  const ranges = candidate.findings.flatMap((finding) => finding.ranges);
  if (ranges.length === 0) {
    return "";
  }
  const start = Math.min(...ranges.map((range) => range.start_line));
  const end = Math.max(...ranges.map((range) => range.end_line));
  return start === end ? `line ${start}` : `lines ${start}–${end}`;
}

export function Instructions({
  report,
  loading,
  error,
  notice,
  busy,
  shellAvailable,
  onReload,
  onScan,
  onApprove,
  onDisable
}: InstructionsProps) {
  const [pending, setPending] = useState<Pending>(null);

  if (!shellAvailable) {
    return (
      <section className="card card--muted">
        <h2>Agent instruction review needs the desktop shell</h2>
        <p>
          The browser prototype has no AuraScan process behind it, so it cannot read the
          Instruction Guard report. Run the Electron shell to review agent files.
        </p>
      </section>
    );
  }

  const shellActions = (
    <div className="chip-row">
      <button type="button" className="button" onClick={onReload} disabled={busy}>
        Reload latest report
      </button>
      <button type="button" className="button" onClick={onScan} disabled={busy}>
        Scan now
      </button>
    </div>
  );

  if (loading && report === null) {
    return (
      <section className="card card--muted">
        <p>Reading the latest Instruction Guard report…</p>
      </section>
    );
  }

  if (report === null) {
    return (
      <section className="card card--muted">
        <div className="card__header">
          <h2>No review report yet</h2>
        </div>
        <p>{error || "AuraScan has no Instruction Guard report to display."}</p>
        <p className="card__note">
          A scan reads agent control files as inert text in your home directory. It never
          executes them and writes only private state. Candidate actions below are
          available once a report exists.
        </p>
        {shellActions}
      </section>
    );
  }

  const pendingCandidate = pending
    ? report.candidates.find((candidate) => candidate.file_id === pending.fileId) ?? null
    : null;

  const confirm = async () => {
    if (!pendingCandidate || !pending) {
      return;
    }
    const action = pending.action;
    setPending(null);
    if (action === "approve") {
      await onApprove(pendingCandidate);
    } else {
      await onDisable(pendingCandidate);
    }
  };

  return (
    <>
      <section className="card">
        <div className="card__header">
          <h2>Report {shortDigest(report.report_id)}</h2>
          <StatusBadge
            tone={report.review_required ? "warn" : "ok"}
            label={report.review_required ? "review required" : "clear"}
          />
          <StatusBadge tone={report.highest_severity} />
        </div>
        <dl className="kv">
          <div>
            <dt>Candidates</dt>
            <dd>{report.candidate_count}</dd>
          </div>
          <div>
            <dt>Collected</dt>
            <dd className="mono">{report.created_at}</dd>
          </div>
          <div>
            <dt>Coverage</dt>
            <dd>
              {report.truncated
                ? "truncated"
                : report.continuation_pending
                  ? "continuation pending — this is not a full scan"
                  : "complete"}
            </dd>
          </div>
        </dl>
        {shellActions}
        {notice ? <p className="card__note">{notice}</p> : null}
        {error ? (
          <div className="banner banner--error" role="alert">
            {error}
          </div>
        ) : null}
      </section>

      {pendingCandidate && pending ? (
        <section className="card card--danger" role="alertdialog" aria-label="Confirm instruction action">
          <div className="card__header">
            <h2>{pending.action === "approve" ? "Approve this file?" : "Disable this file?"}</h2>
            <StatusBadge tone="warn" label="needs confirmation" />
          </div>
          <dl className="kv">
            <div>
              <dt>File</dt>
              <dd className="mono">{pendingCandidate.relative_path}</dd>
            </div>
            <div>
              <dt>File id</dt>
              <dd className="mono">{pendingCandidate.file_id}</dd>
            </div>
            <div>
              <dt>SHA-256</dt>
              <dd className="mono">{shortDigest(pendingCandidate.sha256)}</dd>
            </div>
            <div>
              <dt>Report</dt>
              <dd className="mono">{report.report_id}</dd>
            </div>
          </dl>
          <p className="card__note">
            {pending.action === "approve"
              ? "Approval records this exact content in your machine- and UID-bound baseline. It does not make the file trustworthy, and a later change is reported again."
              : "AuraScan renames the unchanged file and keeps a restore receipt. Files that are not standalone Markdown, settings, or linked elsewhere stay manual-only."}
          </p>
          <div className="chip-row">
            <button type="button" className="button" onClick={() => void confirm()} disabled={busy}>
              {pending.action === "approve" ? "Confirm approval" : "Confirm disable"}
            </button>
            <button type="button" className="button" onClick={() => setPending(null)} disabled={busy}>
              Cancel
            </button>
          </div>
        </section>
      ) : null}

      {report.candidates.length === 0 ? (
        <section className="card card--muted">
          <p>This report contains no candidates.</p>
        </section>
      ) : null}

      {report.candidates.map((candidate) => (
        <section className="card" key={candidate.file_id}>
          <div className="card__header">
            <h2 className="mono">{candidate.relative_path}</h2>
            <StatusBadge tone={candidate.content_risk} />
            <StatusBadge tone={candidate.review_required ? "warn" : "ok"} label={candidate.integrity_state} />
            {candidate.baseline ? null : <StatusBadge tone="neutral" label="content only" />}
          </div>
          <dl className="kv">
            <div>
              <dt>Surface</dt>
              <dd>{candidate.surface}</dd>
            </div>
            <div>
              <dt>SHA-256</dt>
              <dd className="mono">{shortDigest(candidate.sha256)}</dd>
            </div>
            <div>
              <dt>Evidence</dt>
              <dd>{lineRange(candidate) || "—"}</dd>
            </div>
          </dl>
          {candidate.findings.length === 0 ? (
            <p className="card__note">No content finding for this file.</p>
          ) : (
            <ul className="findings">
              {candidate.findings.map((finding) => (
                <li className="finding" key={`${candidate.file_id}-${finding.rule_id}`}>
                  <div className="finding__head">
                    <StatusBadge tone={finding.severity} />
                    <span className="finding__rule mono">{finding.rule_id}</span>
                  </div>
                  <div className="finding__title">{finding.title}</div>
                  <p className="finding__summary">{finding.reason}</p>
                </li>
              ))}
            </ul>
          )}
          <div className="chip-row">
            <button
              type="button"
              className="button"
              disabled={busy || !candidate.baseline || candidate.integrity_state === "approved"}
              onClick={() => setPending({ fileId: candidate.file_id, action: "approve" })}
            >
              Approve unchanged content
            </button>
            <button
              type="button"
              className="button"
              disabled={busy || !candidate.disable_eligible}
              onClick={() => setPending({ fileId: candidate.file_id, action: "disable" })}
            >
              Disable file
            </button>
          </div>
          <p className="card__note">
            The action is bound to this report and this SHA-256. If either changes before
            it runs, AuraScan refuses instead of acting.
          </p>
        </section>
      ))}
    </>
  );
}
