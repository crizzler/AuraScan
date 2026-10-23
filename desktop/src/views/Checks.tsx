import { useMemo, useState } from "react";

import type { CheckStatus, DoctorCheck } from "../contract";
import { StatusBadge } from "../components/StatusBadge";

const GROUPS = [
  "distro",
  "package",
  "desktop",
  "config",
  "ai",
  "instruction",
  "incident",
  "recovery",
  "security",
  "tool",
  "local",
  "hung",
  "updater"
];

const FILTERS: Array<{ id: "all" | CheckStatus; label: string }> = [
  { id: "all", label: "All" },
  { id: "error", label: "Errors" },
  { id: "warn", label: "Warnings" },
  { id: "ok", label: "Verified" }
];

function groupFor(name: string): string {
  const head = name.split("_")[0];
  return GROUPS.includes(head) ? head : "other";
}

export function Checks({ checks }: { checks: DoctorCheck[] }) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<"all" | CheckStatus>("all");

  const grouped = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const buckets = new Map<string, DoctorCheck[]>();
    for (const check of checks) {
      if (filter !== "all" && check.status !== filter) {
        continue;
      }
      if (needle && !`${check.name} ${check.message}`.toLowerCase().includes(needle)) {
        continue;
      }
      const key = groupFor(check.name);
      const bucket = buckets.get(key) ?? [];
      bucket.push(check);
      buckets.set(key, bucket);
    }
    return [...buckets.entries()].sort(([left], [right]) => left.localeCompare(right));
  }, [checks, filter, query]);

  const total = grouped.reduce((sum, [, bucket]) => sum + bucket.length, 0);

  return (
    <div className="stack">
      <div className="toolbar">
        <input
          className="input"
          type="search"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search checks"
          aria-label="Search checks"
        />
        <div className="segmented" role="group" aria-label="Filter by status">
          {FILTERS.map((option) => (
            <button
              key={option.id}
              type="button"
              className={filter === option.id ? "segmented__item is-active" : "segmented__item"}
              onClick={() => setFilter(option.id)}
              aria-pressed={filter === option.id}
            >
              {option.label}
            </button>
          ))}
        </div>
        <span className="toolbar__count">{total} shown</span>
      </div>

      {grouped.length === 0 ? (
        <p className="empty">No checks match this filter.</p>
      ) : (
        grouped.map(([group, bucket]) => (
          <section className="card" key={group}>
            <header className="card__header">
              <h2 className="group-title">{group}</h2>
              <span className="group-count">{bucket.length}</span>
            </header>
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Status</th>
                  <th scope="col">Check</th>
                  <th scope="col">Evidence</th>
                </tr>
              </thead>
              <tbody>
                {bucket.map((check) => (
                  <tr key={check.name}>
                    <td>
                      <StatusBadge tone={check.status} />
                    </td>
                    <td className="mono">{check.name}</td>
                    <td>{check.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        ))
      )}
    </div>
  );
}
