/**
 * Renderer-side handle for the desktop shell bridge.
 *
 * The browser prototype has no bridge. The Electron preload exposes exactly
 * two operations and never a command, a path, or an executable.
 */

export interface ShellSnapshotResult {
  ok: true;
  snapshot: unknown;
}

export interface ShellErrorResult {
  ok: false;
  error: string;
  canceled?: boolean;
}

export type ShellResult = ShellSnapshotResult | ShellErrorResult;

export interface DesktopBridge {
  refresh(): Promise<ShellResult>;
  openReport(): Promise<ShellResult>;
}

export function desktopBridge(): DesktopBridge | null {
  const candidate = (globalThis as { aurascanDesktop?: unknown }).aurascanDesktop;
  if (typeof candidate !== "object" || candidate === null) {
    return null;
  }
  const bridge = candidate as Record<string, unknown>;
  const refresh = bridge.refresh;
  const openReport = bridge.openReport;
  if (typeof refresh !== "function" || typeof openReport !== "function") {
    return null;
  }
  return {
    refresh: () => (refresh as () => Promise<ShellResult>).call(candidate),
    openReport: () => (openReport as () => Promise<ShellResult>).call(candidate)
  };
}
