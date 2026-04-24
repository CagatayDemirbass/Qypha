# Qypha Desktop (Tauri 2)

Cross-platform desktop shell for Qypha with security-first defaults.

## Prerequisites

- Rust stable (`rustup`)
- Node.js 22.16+
- Platform toolchain:
  - macOS: Xcode Command Line Tools
  - Windows: MSVC Build Tools + WebView2 runtime
  - Linux: `webkit2gtk`, `libayatana-appindicator` (or distro equivalents)

## One-command repo setup

From the repository root:

macOS:

```bash
chmod +x ./setup.sh
./setup.sh
```

Linux:

```bash
chmod +x ./setup.sh
./setup.sh
```

Windows (run PowerShell as Administrator):

```powershell
powershell -ExecutionPolicy Bypass -File .\setup_windows.ps1
```

By default this setup flow also:
- builds the packaged Tauri desktop app
- installs it as a normal double-clickable application
- creates a Desktop shortcut
- adds a `Qypha-desktop` terminal launcher

What users do after setup:
- macOS: open `Qypha.app` from Desktop or Applications, or run `Qypha-desktop`
- Linux: open `Qypha.desktop` from Desktop or the app menu, or run `Qypha-desktop`
- Windows: open the Desktop shortcut or Start Menu app, or run `Qypha-desktop`

## Install

```bash
cd apps/qypha-desktop
npm ci
```

## Run (desktop)

```bash
Qypha-desktop
```

For local UI development:

```bash
npm run tauri:dev
```

## Runtime Flows (Now Wired)

- Agent setup is available in-app:
  - `Create Agent` runs `Qypha init`
  - explicit `Listen Port` is supported (e.g. 9090/9091)
- `Start`: launches `Qypha start` in headless control mode.
- `Ghost + Tor`: app starts via non-interactive `Qypha launch --name ... --transport tor --log-mode ghost --port ...`
- `Stop`: sends `/quit`, then force-stops if needed.
- `/peers`, `/invite`, `/invite_g` buttons send real runtime commands.
- Peer selection opens a dedicated DM conversation per connection.
- Conversation model:
  - `Group Chat` tab sends with `/send <message>`
  - `DM` tabs send with `/sendto <did> <message>`
- `Transfer` uses `/transfer <path> <did>`.
- Approval controls use:
  - `/accept <did>`
  - `/reject <did>`
  - `/accept_always <did>`
  - `/accept_ask <did>`
- `Connect` box sends `/connect <code>`.

## Run (web-only UI)

```bash
npm run dev:web
```

## Build packages

```bash
npm run tauri:build
```

## Security Notes

- Tauri permissions are deny-by-default via capability file.
- CSP is strict and only allows app-local scripts/styles + local dev url.
- This shell is intentionally thin: crypto/transport policy remains in Rust core.
- Ghost mode policy target: ephemeral keys, no persistent chat logs, secure temp wipe.
- In-app runtime start supports `safe`; `ghost` remains launch-only.

## Test Checklist

1. Use a valid config path and passphrase, then click `Start`.
2. Confirm status shows `running=true` and a PID.
3. Click `/peers`; verify peer list and logs update.
4. Select a peer and send a message.
5. Send a transfer and test accept/reject controls.
6. Click `Stop`; verify runtime exits cleanly.
