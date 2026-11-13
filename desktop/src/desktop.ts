/**
 * Renderer-side handle for the desktop shell bridge.
 *
 * The browser prototype has no bridge. The Electron preload exposes only fixed
 * operations. The renderer never receives a command, an executable, or a path,
 * and a credential it sends leaves only through that bridge.
 */

export interface ShellPayloadResult {
  ok: true;
  payload: unknown;
  exitCode?: number;
}

export interface ShellErrorResult {
  ok: false;
  error: string;
  canceled?: boolean;
}

export type ShellResult = ShellPayloadResult | ShellErrorResult;

export interface AiConfigInput {
  provider: string;
  model?: string;
  base_url?: string;
  enabled?: boolean;
}

export interface DesktopBridge {
  refresh(): Promise<ShellResult>;
  openReport(): Promise<ShellResult>;
  readSettings(): Promise<ShellResult>;
  setAiKey(provider: string, secret: string): Promise<ShellResult>;
  configureAi(values: AiConfigInput): Promise<ShellResult>;
  reviewInstructions(): Promise<ShellResult>;
  scanInstructions(): Promise<ShellResult>;
  approveInstruction(fileId: string, reportId: string, sha256: string): Promise<ShellResult>;
  disableInstruction(fileId: string, reportId: string, sha256: string): Promise<ShellResult>;
  scanIncidents(): Promise<ShellResult>;
  resolveIncidents(): Promise<ShellResult>;
  openUpgrade(): Promise<ShellResult>;
  npmAudit(): Promise<ShellResult>;
  auditAgent(surface: string): Promise<ShellResult>;
}

export function desktopBridge(): DesktopBridge | null {
  const candidate = (globalThis as { aurascanDesktop?: unknown }).aurascanDesktop;
  if (typeof candidate !== "object" || candidate === null) {
    return null;
  }
  const bridge = candidate as Record<string, unknown>;
  const names = [
    "refresh",
    "openReport",
    "readSettings",
    "setAiKey",
    "configureAi",
    "reviewInstructions",
    "scanInstructions",
    "approveInstruction",
    "disableInstruction",
    "scanIncidents",
    "resolveIncidents",
    "openUpgrade",
    "npmAudit",
    "auditAgent"
  ] as const;
  for (const name of names) {
    if (typeof bridge[name] !== "function") {
      return null;
    }
  }
  const call = (name: (typeof names)[number]) =>
    (bridge[name] as (...args: unknown[]) => Promise<ShellResult>).bind(candidate);
  return {
    refresh: () => call("refresh")(),
    openReport: () => call("openReport")(),
    readSettings: () => call("readSettings")(),
    setAiKey: (provider: string, secret: string) => call("setAiKey")(provider, secret),
    configureAi: (values: AiConfigInput) => call("configureAi")(values),
    reviewInstructions: () => call("reviewInstructions")(),
    scanInstructions: () => call("scanInstructions")(),
    approveInstruction: (fileId: string, reportId: string, sha256: string) =>
      call("approveInstruction")(fileId, reportId, sha256),
    disableInstruction: (fileId: string, reportId: string, sha256: string) =>
      call("disableInstruction")(fileId, reportId, sha256),
    scanIncidents: () => call("scanIncidents")(),
    resolveIncidents: () => call("resolveIncidents")(),
    openUpgrade: () => call("openUpgrade")(),
    npmAudit: () => call("npmAudit")(),
    auditAgent: (surface: string) => call("auditAgent")(surface)
  };
}
