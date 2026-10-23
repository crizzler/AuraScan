# AuraScan Desktop (prototype)

Read-only evidence console for AuraScan. This directory is the phase 2
renderer described in [`../docs/DESKTOP_UI_DESIGN.md`](../docs/DESKTOP_UI_DESIGN.md).

**Status:** development prototype. Not packaged, not installed by the `aurascan`
package, and not part of any release artifact. There is no Electron shell yet.

## What it does

- parses the `aurascan-ui/1` snapshot contract and fails closed on anything it
  does not fully understand;
- renders the snapshot as an overview, a check browser, and an incident view;
- never computes severity, confidence, or coverage;
- never executes a process, opens a network connection, or calls a model.

The bundled `src/fixtures/snapshot.sample.json` is synthetic and sanitized.

## Development

```bash
cd desktop
npm install
npm run dev        # http://127.0.0.1:5174
```

Verification:

```bash
npm run typecheck
npm test
npm run build
```

## Using real local evidence

`aurascan ui --json` prints the snapshot this renderer expects. It is read-only
and never mutates local state:

```bash
# from the repository root, with the working tree on PYTHONPATH
python -m aurascan ui --json > desktop/src/fixtures/local.snapshot.json
```

Local snapshots can contain host-specific paths and user state. They are
git-ignored on purpose; never commit them.

To preview one, point the import in `src/App.tsx` at the local file. A small
loader that reads the file at startup arrives with the shell in phase 4.

## Contract rules

- `aurascan-ui/1` is frozen for this phase. Adding a field is allowed; removing,
  renaming, or retyping one requires `aurascan-ui/2` plus a parser update.
- Unknown top-level keys are ignored. Unknown check statuses, malformed
  evidence, or more than 1000 checks reject the whole snapshot.
- An unavailable incident state renders as "unavailable", never as zero.

## Security notes for the shell phase

- The renderer must stay a pure view: `contextIsolation`, `sandbox`, no Node
  integration, navigation denied, no `<webview>`, `autoUpdater` disabled.
- The development CSP allows inline styles and the local Vite HMR socket. The
  packaged shell must enforce `style-src 'self'` and `connect-src 'none'`.
- Actions, when they exist, are enumerated intent IDs that the Python core
  revalidates. The renderer never receives a command string or a free path.
