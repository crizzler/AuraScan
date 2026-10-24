import { useState } from "react";

import type { SettingsFeature, SettingsPayload } from "../contract";
import { StatusBadge } from "../components/StatusBadge";

interface SettingsProps {
  settings: SettingsPayload | null;
  loading: boolean;
  error: string;
  notice: string;
  busy: boolean;
  shellAvailable: boolean;
  onReload: () => void;
  onStoreCredential: (provider: string, secret: string) => Promise<void>;
}

function featureState(feature: SettingsFeature): { tone: "ok" | "warn" | "neutral"; label: string } {
  if (feature.enabled === true) {
    return { tone: "ok", label: "enabled" };
  }
  if (feature.enabled === false) {
    return { tone: "warn", label: "disabled" };
  }
  return { tone: "neutral", label: feature.declared ? "unrecognised" : "default" };
}

function credentialLabel(settings: SettingsPayload): string {
  const ai = settings.ai;
  if (ai.key_present) {
    return "stored";
  }
  return ai.requires_key ? "missing" : "not required";
}

export function Settings({
  settings,
  loading,
  error,
  notice,
  busy,
  shellAvailable,
  onReload,
  onStoreCredential
}: SettingsProps) {
  const [provider, setProvider] = useState("");
  const [secret, setSecret] = useState("");

  if (!shellAvailable) {
    return (
      <section className="card card--muted">
        <div className="card__header">
          <h2>Settings need the desktop shell</h2>
        </div>
        <p>
          This browser prototype has no AuraScan process behind it, so it cannot read or
          change configuration. Run the Electron shell to manage settings.
        </p>
      </section>
    );
  }

  if (loading && settings === null) {
    return (
      <section className="card card--muted">
        <p>Reading your AuraScan configuration…</p>
      </section>
    );
  }

  if (settings === null) {
    return (
      <section className="card card--danger">
        <div className="card__header">
          <h2>Settings unavailable</h2>
        </div>
        <p>{error || "AuraScan did not return a settings payload."}</p>
        <p className="card__note">
          The installed AuraScan may be older than this client, or the settings
          command may be missing. The rest of the console keeps working.
        </p>
        <button type="button" className="button" onClick={onReload} disabled={busy}>
          Try again
        </button>
      </section>
    );
  }

  const activeProvider = provider === "" ? settings.ai.provider : provider;
  const selected = settings.providers.find((entry) => entry.id === activeProvider);
  const needsKey = selected ? selected.requires_key : true;

  const submit = () => {
    const value = secret;
    if (value.trim().length === 0) {
      return;
    }
    setSecret("");
    void onStoreCredential(activeProvider, value).then(() => onReload());
  };

  return (
    <>
      <section className="card">
        <div className="card__header">
          <h2>Configuration file</h2>
          <StatusBadge tone={settings.config.present ? "ok" : "warn"} label={settings.config.present ? "present" : "not created"} />
        </div>
        <dl className="kv">
          <div>
            <dt>Path</dt>
            <dd className="mono">{settings.config.path}</dd>
          </div>
          <div>
            <dt>Permissions</dt>
            <dd>{settings.config.mode ?? "—"}{settings.config.mode_ok ? " (private)" : " (check this)"}</dd>
          </div>
          <div>
            <dt>Readable</dt>
            <dd>{settings.config.readable ? "yes" : "no"}</dd>
          </div>
        </dl>
        <p className="card__note">
          AuraScan reads this file itself. This console never displays stored secrets;
          it only reports whether a credential exists.
        </p>
      </section>

      <section className="card">
        <div className="card__header">
          <h2>AI assistance</h2>
          <StatusBadge tone={settings.ai.enabled ? "ok" : "neutral"} label={settings.ai.enabled ? "enabled" : "disabled"} />
          <StatusBadge tone={settings.ai.ready ? "ok" : "warn"} label={settings.ai.ready ? "ready" : "not ready"} />
        </div>
        <dl className="kv">
          <div>
            <dt>Provider</dt>
            <dd>{settings.ai.provider_label || settings.ai.provider}</dd>
          </div>
          <div>
            <dt>Model</dt>
            <dd className="mono">{settings.ai.model || "—"}</dd>
          </div>
          <div>
            <dt>Endpoint</dt>
            <dd className="mono">{settings.ai.base_url ?? (settings.ai.local ? "—" : "provider default")}</dd>
          </div>
          <div>
            <dt>Credential</dt>
            <dd className="mono">
              {credentialLabel(settings)} <span className="sidebar__muted">({settings.ai.key_env})</span>
            </dd>
          </div>
        </dl>
        {settings.ai.error ? (
          <p className="card__note">Configuration problem: {settings.ai.error}</p>
        ) : null}
        <p className="card__note">
          AI stays opt-in and advisory. Storing a credential does not enable it, and it
          can never lower a deterministic finding.
        </p>
      </section>

      <section className="card">
        <div className="card__header">
          <h2>Store a provider credential</h2>
        </div>
        <form
          className="chip-row"
          onSubmit={(event) => {
            event.preventDefault();
            submit();
          }}
        >
          <select
            className="input"
            aria-label="AI provider"
            value={activeProvider}
            onChange={(event) => setProvider(event.target.value)}
            disabled={busy}
          >
            {settings.providers.map((entry) => (
              <option key={entry.id} value={entry.id}>
                {entry.label}
                {entry.local ? " (local)" : ""}
                {entry.key_present ? " — stored" : ""}
              </option>
            ))}
          </select>
          <input
            className="input"
            type="password"
            aria-label="Provider credential"
            placeholder={needsKey ? "Paste the provider API key" : "Optional for a local endpoint"}
            value={secret}
            autoComplete="off"
            spellCheck={false}
            onChange={(event) => setSecret(event.target.value)}
            disabled={busy}
          />
          <button
            type="submit"
            className="button"
            disabled={busy || secret.trim().length === 0}
          >
            Store credential
          </button>
        </form>
        <p className="card__note">
          The value is written straight to the configuration file with private
          permissions and is never shown again, logged, or sent anywhere by this console.
        </p>
        {notice ? <p className="card__note">{notice}</p> : null}
        {error ? <div className="banner banner--error" role="alert">{error}</div> : null}
      </section>

      <section className="card">
        <div className="card__header">
          <h2>Providers</h2>
        </div>
        <table className="table">
          <thead>
            <tr>
              <th>Provider</th>
              <th>Kind</th>
              <th>Credential</th>
              <th>Default model</th>
            </tr>
          </thead>
          <tbody>
            {settings.providers.map((entry) => (
              <tr key={entry.id}>
                <td>{entry.label}</td>
                <td>{entry.local ? "local endpoint" : "cloud"}</td>
                <td>{entry.key_present ? "stored" : entry.requires_key ? "missing" : "not required"}</td>
                <td className="mono">{entry.default_model}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="card">
        <div className="card__header">
          <h2>Features</h2>
        </div>
        <ul className="chip-row">
          {settings.features.map((feature) => {
            const state = featureState(feature);
            return (
              <li key={feature.id} className="chip">
                <span>{feature.label}</span>
                <StatusBadge tone={state.tone} label={state.label} />
              </li>
            );
          })}
        </ul>
        <p className="card__note">
          Switches are read-only in this version. Changing them needs the consent-bound
          write path described in the control-center plan.
        </p>
      </section>
    </>
  );
}
