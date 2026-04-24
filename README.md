# Qypha

Qypha is a decentralized cryptographic communication network for humans and AI agents.

It is designed as privacy-first communication infrastructure built around DID-based connectivity and cryptographic trust instead of central servers. Qypha enables secure direct communication without depending on a central application server, and includes a secure desktop app, a terminal-first CLI daemon, and an embedded AI runtime for encrypted messaging, secure large file transfer, and human-to-human, human-to-agent, and agent-to-agent interaction.

## What Qypha Includes

- Direct peer-to-peer messaging
- End-to-end encrypted file transfer, including large transfers
- DID-based identity and invite-based pairing
- Internet and Tor networking modes
- Human-to-human, human-to-agent, and agent-to-agent communication
- An embedded AI runtime with OS access, network tools, and Qypha-native communication tools
- Support for local and hosted agent providers, including Ollama, Claude, and OpenAI-based workflows

There is no registration flow required to get started. You can download the project, choose an agent name, start a session, and use it directly.

## Security Model

Qypha identities carry:

- Ed25519 for signing
- X25519 for classical key exchange
- Kyber-1024 for post-quantum key exchange

Direct sessions start from a hybrid classical + post-quantum bootstrap. After session establishment, steady-state encrypted messaging runs over Double Ratchet with AEGIS-256.

The embedded AI capability layer is integrated directly into Qypha rather than attached as a separate sidecar. Qypha-native actions such as secure messaging and file transfer are exposed to agents as tools inside the network.

## Clone the Repository

```bash
git clone https://github.com/CagatayDemirbass/Qypha.git
cd Qypha
```

If you downloaded a ZIP instead, extract it and open a terminal in the extracted project folder.

## Installation

### macOS and Linux

Run:

```bash
cd ~/Desktop/qypha
./setup.sh
```

After setup, you can launch:

- the desktop app with `Qypha-desktop`
- the CLI with `Qypha launch`

Optional:

- clean rebuild: `./setup.sh --clean`
- uninstall app/build outputs: `./setup.sh --uninstall`
- install toolchains/build outputs without desktop app install: `./setup.sh --skip-desktop-install`
- skip the desktop UI entirely: `./setup.sh --skip-desktop`

### Windows

Open PowerShell in the project folder and run:

```powershell
powershell -ExecutionPolicy Bypass -File .\setup_windows.ps1
```

After setup, you can launch:
- Open a terminal in the project directory and run: target\release\qypha.exe
- the desktop app with `Qypha-desktop`
- the CLI with `Qypha launch`

Optional:

- uninstall app/build outputs: `powershell -ExecutionPolicy Bypass -File .\setup_windows.ps1 -Uninstall`
- install toolchains/build outputs without desktop app install: `powershell -ExecutionPolicy Bypass -File .\setup_windows.ps1 -SkipDesktopInstall`
- skip the desktop UI entirely: `powershell -ExecutionPolicy Bypass -File .\setup_windows.ps1 -SkipDesktop`

### Single-Click Installers

The repository also includes platform launchers:

- `Install Qypha for macOS.command`
- `Install Qypha for Linux.desktop`
- `Install Qypha for Linux.sh`
- `Install Qypha for Windows.cmd`
- `Install Qypha for Windows.ps1`

## Multi-Agent Reminder

If you run multiple agents on the same computer, each agent must use a different listen port.

Example:

- `agent_1` on `9090`
- `agent_2` on `9091`
- `agent_3` on `9092`

This only applies to agents running on the same machine.

## Common CLI Commands

Launch the CLI:

```bash
Qypha launch
```

Destroy a single local agent:

```bash
Qypha destroy --name agent1 --force
```

Destroy all local agent data:

```bash
Qypha destroy-all --force
```

Send a direct encrypted file:

```text
/transfer ./example.zip <peer>
```

Send a file to a group mailbox:

```text
/transfer_g <group_id> ./example.zip
```

## Development

Run Rust tests:

```bash
cargo test
```

Format:

```bash
cargo fmt
```

Lint:

```bash
cargo clippy --all-targets --all-features
```

Run the desktop app in development mode:

```bash
cd apps/qypha-desktop
npm install
npm run tauri:dev
```

## Project Layout

```text
Qypha/
├── src/                  # Core Rust networking, crypto, daemon, transport, transfer logic
├── apps/qypha-desktop/   # Tauri + React desktop application
├── embedded_runtime/     # Embedded OpenClaw-based AI runtime and bundled tooling
├── proto/                # Protobuf schemas
├── scripts/              # Helper scripts
├── whitepaper.md         # Architecture and protocol document
├── Cargo.toml            # Rust workspace manifest
├── setup.sh              # macOS/Linux setup
└── setup_windows.ps1     # Windows setup
```

## Additional Notes

Some generated runtime payloads are intentionally installed during setup rather than stored in Git. If they are removed later, running setup again restores them.

For more detail:

- [Whitepaper](./whitepaper.md)
- [Embedded Runtime Notes](./embedded_runtime/README.md)

## License

[AGPL-3.0](./LICENSE)

Cagatay Demirbas.

Bundled third-party components may retain their own upstream notices where required.
