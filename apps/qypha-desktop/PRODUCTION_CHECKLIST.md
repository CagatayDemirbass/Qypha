# Qypha Desktop: Debug to Production Checklist

## 1) Local Dev (Every Commit)

1. `npm run build:web`
2. `cargo check --manifest-path src-tauri/Cargo.toml`
3. `npm run tauri:dev` and test:
   - app opens
   - `Refresh Runtime` works
   - no console errors

## 2) Security Gates

1. Tauri permissions stay minimum in `src-tauri/capabilities/default.json`.
2. No wildcard shell/fs/http permissions unless explicitly required.
3. CSP stays strict in `src-tauri/tauri.conf.json`.
4. No plaintext secrets in frontend code.
5. Ghost mode IPC paths must avoid persistence.

## 3) Core Integration Gates

1. Connect Rust commands to Qypha core (no business logic in JS).
2. Add typed commands:
   - `start_agent`, `stop_agent`
   - `invite`, `invite_group`, `connect`
   - `send_to`, `transfer_start`, `accept`, `reject`
3. Event stream from backend for:
   - peer connect/disconnect
   - transfer pending/approved/rejected
   - transfer progress + errors

## 4) Privacy Regression Tests

1. Ghost mode: no persistent chat DB files.
2. Ghost mode: no persistent key files.
3. Disk chunk staging is secure-wiped after transfer/exit.
4. Recovery test: crash/restart janitor cleans stale temp artifacts.
5. Safe mode keeps encrypted-only at-rest policy.

## 5) Packaging + Signing

1. macOS: notarized `.dmg`
2. Windows: signed `.msi`
3. Linux: signed package artifacts (`.deb`/`.AppImage`)
4. Verify auto-update signature validation before enabling updater.

## 6) Performance Targets

1. Idle CPU < 2% on desktop.
2. Memory baseline < 300 MB without active transfer.
3. 10 GB transfer should complete without RAM runaway.
4. UI stays responsive during transfer (> 45 FPS animation target).
