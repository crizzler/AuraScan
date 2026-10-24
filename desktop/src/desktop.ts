/**
 * Renderer-side handle for the desktop shell bridge.
 *
 * The browser prototype has no bridge. The Electron preload exposes exactly
 * four fixed operations. The renderer never receives a command, an executable,
 * or a path, and a credential it sends leaves only through that bridge.
 */

export interface ShellPayloadResult {
  ok: true;
  payload: unknown;
}

export interface ShellErrorResult {
  ok: false;
  error: string;
  canceled?: boolean;
}

export type ShellResult = ShellPayloadResult | ShellErrorResult;

export interface DesktopBridge {
  refresh(): Promise<ShellResult>;
  openReport(): Promise<ShellResult>;
  readSettings(): Promise<ShellResult>;
  setAiKey(provider: string, secret: string): Promise<ShellResult>;
}

export function desktopBridge(): DesktopBridge | null {
  const candidate = (globalThis as { aurascanDesktop?: unknown }).aurascanDesktop;
  if (typeof candidate !== "object" || candidate === null) {
    return null;
  }
  const bridge = candidate as Record<string, unknown>;
  const refresh = bridge.refresh;
  const openReport = bridge.openReport;
  const readSettings = bridge.readSettings;
  const setAiKey = bridge.setAiKey;
  if (
    typeof refresh !== "function" ||
    typeof openReport !== "function" ||
    typeof readSettings !== "function" ||
    typeof setAiKey !== "function"
  ) {
    return null;
  }
  return {
    refresh: () => (refresh as () => Promise<ShellResult>).call(candidate),
    openReport: () => (openReport as () => Promise<ShellResult>).call(candidate),
    readSettings: () => (readSettings as () => Promise<ShellResult>).call(candidate),
    setAiKey: (provider: string, secret: string) =>
      (setAiKey as (nextProvider: string, nextSecret: string) => Promise<ShellResult>).call(
        candidate,
        provider,
        secret
      )
  };
}
