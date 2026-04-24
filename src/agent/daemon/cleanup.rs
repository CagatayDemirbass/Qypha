use std::sync::atomic::Ordering;

use super::GHOST_MODE_ACTIVE;

pub(crate) fn emergency_ghost_cleanup_signal_safe() {
    // Clear terminal screen + scrollback using raw write (signal-safe)
    #[cfg(unix)]
    {
        let clear_seq = b"\x1b[2J\x1b[H\x1b[3J";
        unsafe {
            libc::write(
                1,
                clear_seq.as_ptr() as *const libc::c_void,
                clear_seq.len(),
            )
        };
    }
    #[cfg(windows)]
    {
        // On Windows, ANSI escapes work in Windows Terminal
        let clear_seq = b"\x1b[2J\x1b[H\x1b[3J";
        use std::io::Write;
        let _ = std::io::stdout().write_all(clear_seq);
        let _ = std::io::stdout().flush();
    }

    // Overwrite sensitive env vars with zeros THEN remove
    // (env::remove_var alone doesn't zero the backing memory)
    for var in &[
        "QYPHA_CONFIG",
        "QYPHA_PASSPHRASE",
        "QYPHA_LOG_MODE",
        "QYPHA_RUNTIME_TMPDIR",
        "_QYPHA_GHOST_SESSION_START_UNIX",
        "_QYPHA_FDE_OFF",
        "_QYPHA_ORIG_HIBERNATEMODE",
        "_QYPHA_ORIG_PREFETCH",
        "_QYPHA_PS_HISTORY",
    ] {
        std::env::set_var(
            var,
            "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        );
        std::env::remove_var(var);
    }

    GHOST_MODE_ACTIVE.store(false, Ordering::SeqCst);
}

pub(crate) fn emergency_ghost_cleanup() {
    emergency_ghost_cleanup_signal_safe();

    #[cfg(target_os = "macos")]
    {
        use std::io::Write;
        if let Ok(mut child) = std::process::Command::new("pbcopy")
            .stdin(std::process::Stdio::piped())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(b"");
            }
            let _ = child.wait();
        }
    }
    #[cfg(target_os = "linux")]
    {
        use std::io::Write;

        if let Ok(mut child) = std::process::Command::new("xclip")
            .args(["-selection", "clipboard"])
            .stdin(std::process::Stdio::piped())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(b"");
            }
            let _ = child.wait();
        }
        let _ = std::process::Command::new("wl-copy")
            .arg("--clear")
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .output();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("powershell")
            .args(["-Command", "Set-Clipboard -Value $null"])
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .output();
    }
}
