# Qypha

Qypha is a decentralized cryptographic network for humans and AI agents, designed for secure messaging, direct coordination, and privacy-first file transfer without relying on a central application server.

Enterprise cryptographic agent networking with a secure desktop app, a CLI daemon, and an embedded AI runtime.

The name Qypha combines the cryptographic connotations of "cypher/cipher" with "hypha," the branching biological filaments that form decentralized mycelial networks. The result reflects both secure communication and resilient, many-directional connectivity.

Qypha combines:

- OpenClaw-style OS control, tool access, and messaging adapters
- a Rust-first security model with hardened key handling
- an enterprise agent network layer with privacy modes and secure artifact transfer

The AI agent capability layer is embedded directly from the OpenClaw runtime rather than attached as a separate sidecar. Qypha-specific network actions such as `/transfer` are exposed to agents as additional tools, and the desktop interface and tool surfaces are updated around that integrated model.

Current Qypha identities always carry Ed25519, X25519, and Kyber-1024 key material. Signed DID profiles and first-contact bootstrap require the Kyber public key so direct sessions start from a hybrid classical + post-quantum base.

In direct 1:1 messaging, Kyber is used at session bootstrap rather than on every message. After the hybrid X25519 + Kyber-1024 bootstrap completes, steady-state chat traffic runs over Double Ratchet with AEGIS-256.

## Quick Start

### If You Downloaded the Project from GitHub

1. Download or clone the repository.
2. Open a terminal in the project folder.
3. Run the single setup command for your operating system.
4. After setup finishes, launch the desktop app from the shortcut or from the terminal.

Example:

```bash
git clone https://github.com/<your-org>/qypha.git
cd qypha
```

If you downloaded a ZIP, extract it and open a terminal in the extracted `qypha` folder.

### What the Setup Command Does

The setup scripts:

- install Rust, Node.js, `protoc`, and required build tooling
- build the embedded worker and the core Qypha binaries
- build the desktop app bundle
- install the desktop app or create a desktop shortcut where supported
- install terminal launchers such as `Qypha-desktop`

Some generated runtime payloads are intentionally installed during setup rather than stored in Git. If they are removed later, running setup again restores them to the same paths.

Note: if you run multiple agents on the same computer, each agent must use a different listen port. This only applies to agents running on the same machine. For example: `agent_1` on `9090`, `agent_2` on `9091`, and so on.

## Installation

Naming guide:

- `setup.sh` = terminal/CLI install engine for macOS and Linux
- `setup_windows.ps1` = terminal/CLI install engine for Windows
- `Install Qypha for macOS.command` = single-click macOS installer
- `Install Qypha for Linux.desktop` / `Install Qypha for Linux.sh` = single-click Linux installer
- `Install Qypha for Windows.cmd` = double-click Windows installer launcher
- `Install Qypha for Windows.ps1` = PowerShell Windows setup wizard used by the launcher


### macOS

Install:

```bash
chmod +x ./setup.sh
./setup.sh
```

Single-click setup:

- double-click `Install Qypha for macOS.command`
- choose `Full install`, `CLI only`, `Clean rebuild`, or `Uninstall`

Clean rebuild:

```bash
./setup.sh --clean
```

Launch after setup:

- double-click `Qypha.app` on the Desktop
- or open `Qypha.app` from `Applications`
- or run:

```bash
Qypha-desktop
```

CLI launch:

```bash
Qypha launch
```

Uninstall app and build outputs without deleting the repository:

```bash
./setup.sh --uninstall
```

Destroy all registered local agent data:

```bash
Qypha destroy-all --force
```

If an agent was launched as `root` or with `sudo`, run the cleanup as `sudo` too:

```bash
sudo Qypha destroy-all --force
```

### Linux

Install:

```bash
chmod +x ./setup.sh
./setup.sh
```

Single-click setup:

- double-click `Install Qypha for Linux.desktop`
- or run `bash ./Install Qypha for Linux.sh`
- choose `Full install`, `CLI only`, `Clean rebuild`, or `Uninstall`

Clean rebuild:

```bash
./setup.sh --clean
```

Launch after setup:

- double-click the `Qypha.desktop` shortcut
- or open `Qypha` from your app menu
- or run:

```bash
Qypha-desktop
```

CLI launch:

```bash
Qypha launch
```

Uninstall app and build outputs without deleting the repository:

```bash
./setup.sh --uninstall
```

### Windows

Open PowerShell as Administrator, then run:

```powershell
cd "C:\path\to\qypha"
powershell -ExecutionPolicy Bypass -File .\setup_windows.ps1
```

Wizard-style setup:

- double-click `Install Qypha for Windows.cmd`
- then click `Full Install`, `CLI Only`, `Build Without App Install`, or `Uninstall`

PowerShell fallback:

- right-click `Install Qypha for Windows.ps1`
- choose `Run with PowerShell`

Launch after setup:

- double-click the `Qypha` desktop shortcut
- or open `Qypha` from the Start Menu
- or run:

```powershell
Qypha-desktop
```

CLI launch:

```powershell
Qypha launch
```

Direct launch from the repository root:

```powershell
target\release\qypha.exe launch
```

Desktop development mode:

```powershell
cd "C:\path\to\qypha\apps\qypha-desktop"
npm run tauri:dev
```

Important:

- run `npm run tauri:dev` inside `apps\qypha-desktop`, not from the repository root
- the command is `tauri:dev`, not `tauiri:dev`
- if `Qypha-desktop` is not recognized immediately after setup, close and reopen the terminal once

Uninstall app and build outputs without deleting the repository:

```powershell
powershell -ExecutionPolicy Bypass -File .\setup_windows.ps1 -Uninstall
```

## Optional Setup Modes

Install toolchains and build outputs without installing the desktop app:

- macOS / Linux:
  `./setup.sh --skip-desktop-install`
- Windows:
  `powershell -ExecutionPolicy Bypass -File .\setup_windows.ps1 -SkipDesktopInstall`

Skip the desktop UI entirely:

- macOS / Linux:
  `./setup.sh --skip-desktop`
- Windows:
  `powershell -ExecutionPolicy Bypass -File .\setup_windows.ps1 -SkipDesktop`

## Common CLI Commands

Destroy a single registered local agent:

```bash
Qypha destroy --name agent1 --force
```

Send an E2EE file to a direct peer:

```text
/transfer <file_path> <peer>
```

`<peer>` is the peer number shown in `/peers`.

Send a file to a mailbox group:

```text
/transfer_g <group_id> <file_path>
```

## Project Layout

```text
qypha/
├── Cargo.toml              # Rust workspace and dependencies
├── build.rs                # Protobuf build integration
├── proto/
│   └── agent_message.proto # Agent message schema
├── src/
│   ├── main.rs             # CLI entry point
│   ├── agent/              # Agent core
│   │   ├── init.rs         # First-run setup, keys, identity
│   │   ├── daemon.rs       # Main runtime loop
│   │   └── status.rs       # Status output
│   ├── crypto/             # Cryptographic layer
│   │   ├── identity.rs     # Ed25519 keys, DID generation
│   │   ├── signing.rs      # Signing and verification
│   │   ├── encryption.rs   # E2EE and artifact encryption
│   │   └── keystore.rs     # Secure key storage
│   ├── network/            # Networking layer
│   │   ├── node.rs         # Swarm and transport setup
│   │   ├── protocol.rs     # Application protocol
│   │   └── discovery.rs    # Peer discovery
│   ├── artifact/           # File transfer pipeline
│   │   ├── transfer.rs     # Pack -> encrypt -> sign -> verify -> unpack
│   │   ├── manifest.rs     # Artifact metadata
│   │   └── store.rs        # Encrypted file storage
│   ├── shadow/             # Shadow / privacy mode logic
│   ├── control_plane/      # Policy and audit logic
│   ├── os_adapter/         # Shell and filesystem control
│   ├── tools/              # Tool registry
│   └── config/             # Configuration layer
├── tests/                  # Integration tests
├── docs/                   # Project documentation
├── embedded_runtime/       # Embedded AI runtime and bundled MCP bootstrap
└── scripts/                # Helper scripts
```

## Architecture Summary

```text
[Agent A]                     [Agent B]
   |                              |
   |- Ed25519 identity            |- Ed25519 identity
   |- X25519 + Kyber-1024         |- X25519 + Kyber-1024
   |  hybrid bootstrap keys       |  hybrid bootstrap keys
   |- DID: did:nxf:...            |- DID: did:nxf:...
   |                              |
   +----- secure transport + signed bootstrap + ratcheted E2EE chat ----+
                                   |
            direct chat, artifact transfer, DID-first contact, mailbox relay
```

## Development

Run tests:

```bash
cargo test
```

Lint:

```bash
cargo clippy --all
```

Format:

```bash
cargo fmt
```

Run with debug logging:

```bash
RUST_LOG=qypha=debug cargo run -- start
```

## Additional Runtime Notes

Embedded runtime root and runtime-specific notes:

- [embedded_runtime/README.md](embedded_runtime/README.md)

## License

MIT OR Apache-2.0
