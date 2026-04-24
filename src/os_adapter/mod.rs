pub mod filesystem;
pub mod home;
pub mod secure_wipe;
/// OS Adapter — cross-platform system control
///
/// Inspired by OpenClaw's full OS control capabilities.
/// Each agent can interact with the host machine as a "digital employee":
/// - Execute shell commands
/// - Read/write files
/// - Control browser (CDP protocol)
/// - Manage calendar, email (via APIs)
/// - Screen capture and OCR
///
/// Platform-specific implementations:
/// - Windows: Win32/COM/PowerShell
/// - macOS: AppleScript/NSWorkspace/osascript
/// - Linux: D-Bus/systemd/xdotool
pub mod shell;

pub use filesystem::{list_directory, read_file, write_file};
pub use secure_wipe::{secure_wipe_dir, secure_wipe_file};
pub use shell::execute_command;
