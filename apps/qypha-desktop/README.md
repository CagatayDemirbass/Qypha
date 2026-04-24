# Qypha Desktop

Qypha Desktop is the Tauri + React desktop interface for Qypha.

It provides a local desktop shell for:

- agent creation and launch
- direct messaging and group conversations
- peer management and invite flows
- file transfer controls and approval flows
- runtime logs, status, and transfer visibility

The desktop app is intentionally thin. Core cryptography, transport logic, agent runtime behavior, Tor/internet networking, and transfer protocol logic live in the Rust backend in the main repository.

## Repository Context

This folder contains the desktop UI only.

- frontend: `apps/qypha-desktop/src`
- Tauri backend: `apps/qypha-desktop/src-tauri`
- main project README: [../../README.md](../../README.md)

If you want the normal end-user setup flow, use the setup instructions from the root project README instead of this file.

## Requirements

- Node.js 22+
- Rust stable
- Tauri 2 prerequisites for your platform

Platform notes:

- macOS: Xcode Command Line Tools
- Windows: MSVC Build Tools and WebView2 runtime
- Linux: the usual Tauri/WebKitGTK system packages for your distro

## Install Dependencies

From this folder:

```bash
npm install
```

## Development

Run the full desktop app in development mode:

```bash
npm run tauri:dev
```

Run the web UI only:

```bash
npm run dev:web
```

Preview the built web UI:

```bash
npm run preview
```

## Build

Build the desktop app:

```bash
npm run tauri:build
```

Build the web frontend only:

```bash
npm run build:web
```

## Test

Run frontend tests:

```bash
npm test
```

## What The Desktop App Does

The desktop app can:

- create and manage local agents
- start and stop local runtimes
- send runtime commands through the UI
- display peer state, conversations, and transfer state
- surface direct and group communication flows
- expose transfer approvals and file selection flows

In practice, this UI maps to the same runtime and command surface used by the CLI, but presents it in a desktop workflow.

## Security Notes

- Tauri permissions are capability-based and deny-by-default
- the desktop shell does not replace the Rust security model
- transport, crypto, identity, transfer integrity, and policy enforcement remain in the core backend

## License

[AGPL-3.0](../../LICENSE)
