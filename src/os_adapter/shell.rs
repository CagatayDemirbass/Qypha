use anyhow::Result;
use std::process::Command;

/// Execute a shell command in a sandboxed context
///
/// SECURITY: In production, commands run inside Firecracker microVM or WASM sandbox.
/// The agent cannot escape the sandbox to affect the host system unless explicitly
/// granted permission during enrollment.
pub fn execute_command(cmd: &str) -> Result<CommandOutput> {
    tracing::info!(cmd = %cmd, "Executing shell command");

    let output = if cfg!(target_os = "windows") {
        Command::new("cmd").args(["/C", cmd]).output()?
    } else {
        Command::new("sh").args(["-c", cmd]).output()?
    };

    let result = CommandOutput {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        exit_code: output.status.code().unwrap_or(-1),
    };

    if !output.status.success() {
        tracing::warn!(
            exit_code = result.exit_code,
            stderr = %result.stderr,
            "Command failed"
        );
    }

    Ok(result)
}

#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// Get OS information
pub fn get_os_info() -> OsInfo {
    OsInfo {
        os_type: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        family: std::env::consts::FAMILY.to_string(),
    }
}

#[derive(Debug, Clone)]
pub struct OsInfo {
    pub os_type: String,
    pub arch: String,
    pub family: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_echo() {
        let result = execute_command("echo hello").unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("hello"));
    }

    #[test]
    fn test_os_info() {
        let info = get_os_info();
        assert!(!info.os_type.is_empty());
    }
}
