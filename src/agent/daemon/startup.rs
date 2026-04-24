use anyhow::Result;
use colored::{ColoredString, Colorize};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::agent::contact_identity::read_agent_contact_did;
use crate::config::{AppConfig, TransportMode};
use crate::control_plane::audit::{AuditLog, LogMode};
use crate::crypto::identity::AgentKeyPair;
use crate::network::NetworkNode;

use super::cleanup::emergency_ghost_cleanup_signal_safe;
use super::paths::wipe_stale_zero_trace_temp_artifacts;
use super::GHOST_MODE_ACTIVE;

pub(crate) struct RuntimeModeContext {
    pub(crate) log_mode: LogMode,
    pub(crate) log_mode_str: String,
    pub(crate) is_zero_trace: bool,
    pub(crate) privacy_hardened_mode: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeGuardProfile {
    Safe,
    Ghost,
}

pub(crate) fn configure_runtime_mode(
    config: &mut AppConfig,
    log_mode_override: Option<String>,
) -> Result<RuntimeModeContext> {
    let requested_log_mode = log_mode_override.unwrap_or_else(|| config.logging.mode.clone());
    let log_mode = LogMode::try_from_str(&requested_log_mode).ok_or_else(|| {
        anyhow::anyhow!(
            "Invalid log mode '{}'. Use one of: safe, ghost.",
            requested_log_mode
        )
    })?;
    let log_mode_str = log_mode.as_str().to_string();
    config.logging.mode = log_mode_str.clone();
    config.security.log_mode = log_mode_str.clone();

    let is_zero_trace = matches!(log_mode, LogMode::Ghost);
    let is_safe_mode = matches!(log_mode, LogMode::Safe);
    let privacy_hardened_mode = is_zero_trace || is_safe_mode;

    crate::shadow::channel::set_zero_trace_mode(is_zero_trace);
    if is_zero_trace {
        let wiped = wipe_stale_zero_trace_temp_artifacts();
        if wiped > 0 {
            println!(
                "   {} startup janitor wiped {} stale temp artifact dir(s)",
                "GHOST:".red().bold(),
                wiped
            );
        }
    }

    if is_safe_mode {
        config.network.enable_mdns = false;
        config.network.enable_kademlia = false;
        if matches!(config.network.transport_mode, TransportMode::Internet) {
            config.network.iroh.relay_enabled = true;
            config.network.iroh.direct_enabled = false;
        }
    }

    // Never expose local/public IP via UI or invite payload display.
    config.network.hide_ip = true;

    Ok(RuntimeModeContext {
        log_mode,
        log_mode_str,
        is_zero_trace,
        privacy_hardened_mode,
    })
}

fn runtime_guard_profile(log_mode: &LogMode) -> RuntimeGuardProfile {
    match log_mode {
        LogMode::Safe => RuntimeGuardProfile::Safe,
        LogMode::Ghost => RuntimeGuardProfile::Ghost,
    }
}

pub(crate) fn install_runtime_guards(keypair: &AgentKeyPair, log_mode: &LogMode) {
    let guard_profile = runtime_guard_profile(log_mode);
    GHOST_MODE_ACTIVE.store(
        guard_profile == RuntimeGuardProfile::Ghost,
        Ordering::SeqCst,
    );

    // Panic hooks may fire while Tokio runtime holds mutexes, so we
    // must avoid fork/exec and only run signal-safe cleanup.
    if guard_profile == RuntimeGuardProfile::Ghost {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if GHOST_MODE_ACTIVE.load(Ordering::SeqCst) {
                #[cfg(unix)]
                {
                    let msg =
                        b"\n   \x1b[31m\x1b[1mGHOST PANIC: Emergency cleanup triggered...\x1b[0m\n";
                    unsafe { libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len()) };
                }
                #[cfg(not(unix))]
                {
                    eprintln!(
                        "\n   \x1b[31m\x1b[1mGHOST PANIC: Emergency cleanup triggered...\x1b[0m"
                    );
                }
                emergency_ghost_cleanup_signal_safe();
            }
            default_hook(info);
        }));
    }

    #[cfg(unix)]
    {
        let zero_limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero_limit) };

        #[cfg(target_os = "linux")]
        {
            unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
        }
    }

    #[cfg(target_os = "linux")]
    {
        let lock_all_memory = guard_profile == RuntimeGuardProfile::Ghost;
        if lock_all_memory {
            let result = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
            if result == 0 {
                println!(
                    "   {} {}",
                    "MLOCK:".green().bold(),
                    "All memory locked — keys protected from swap (mlockall)"
                );
            } else {
                install_key_memory_guard_unix(
                    keypair,
                    "mlockall failed — key-only lock fallback active when permitted",
                );
            }
        } else {
            install_key_memory_guard_unix(
                keypair,
                "mlock failed — key memory remains protected only by dump disablement",
            );
        }
    }

    #[cfg(target_os = "macos")]
    {
        install_key_memory_guard_unix(
            keypair,
            "mlock failed — core dumps disabled, enable FileVault for full swap protection",
        );
    }

    #[cfg(windows)]
    {
        unsafe {
            windows_sys::Win32::System::Diagnostics::Debug::SetErrorMode(0x0001 | 0x0002);
        }

        install_key_memory_guard_windows(
            keypair,
            "VirtualLock failed — enable BitLocker for pagefile protection",
        );
    }

    #[cfg(not(any(unix, windows)))]
    {
        println!(
            "   {} Memory locking not available — ensure full disk encryption is ON",
            "WARNING:".yellow().bold()
        );
    }

    println!(
        "   {} {}",
        "COREDUMP:".green().bold(),
        if guard_profile == RuntimeGuardProfile::Ghost {
            "Core dumps disabled — no crash dump key extraction possible"
        } else {
            "Core dumps disabled for Safe mode — crash dump key extraction blocked"
        }
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn install_key_memory_guard_unix(keypair: &AgentKeyPair, failure_message: &str) {
    let key_ptr = keypair as *const _ as *const libc::c_void;
    let key_size = std::mem::size_of_val(keypair);
    let mlock_result = unsafe { libc::mlock(key_ptr, key_size) };
    if mlock_result == 0 {
        println!(
            "   {} {}",
            "MLOCK:".green().bold(),
            "Key memory locked — crypto keys protected from swap"
        );
    } else {
        println!("   {} {}", "WARNING:".yellow().bold(), failure_message);
    }
    #[cfg(target_os = "linux")]
    unsafe {
        libc::madvise(key_ptr as *mut libc::c_void, key_size, libc::MADV_DONTDUMP);
    }
}

#[cfg(windows)]
fn install_key_memory_guard_windows(keypair: &AgentKeyPair, failure_message: &str) {
    let key_ptr = keypair as *const _ as *const std::ffi::c_void;
    let key_size = std::mem::size_of_val(keypair);
    let result = unsafe { windows_sys::Win32::System::Memory::VirtualLock(key_ptr, key_size) };
    if result != 0 {
        println!(
            "   {} {}",
            "MLOCK:".green().bold(),
            "Key memory locked — VirtualLock active, keys protected from pagefile"
        );
    } else {
        println!("   {} {}", "WARNING:".yellow().bold(), failure_message);
    }
}

fn log_mode_label(log_mode: &LogMode) -> ColoredString {
    match log_mode {
        LogMode::Safe => "safe (privacy-hardened encrypted log)".yellow().bold(),
        LogMode::Ghost => "GHOST (zero trace, immutable)".red().bold(),
    }
}

pub(crate) fn print_startup_banner(
    config: &AppConfig,
    network: Option<&NetworkNode>,
    internet_mode: bool,
    iroh_endpoint_id: Option<&str>,
    iroh_invite_addr: Option<&iroh::EndpointAddr>,
    our_peer_id: &libp2p::PeerId,
    log_mode: &LogMode,
    runtime_contact_did: Option<&str>,
) {
    let transport_label = match config.network.transport_mode {
        TransportMode::Tcp => "LAN".green(),
        TransportMode::Tor => "libp2p over Tor bridge (Tor)".magenta(),
        TransportMode::Internet => "iroh/QUIC relay transport (Internet)".blue(),
    };

    println!("\n{}", "Agent online!".green().bold());
    println!("   Name:      {}", config.agent.name.cyan());
    if let Some(contact_did) = read_agent_contact_did(&config.agent.name)
        .or_else(|| runtime_contact_did.map(str::to_owned))
    {
        println!("   Contact DID: {}", contact_did.green());
    } else {
        println!("   Contact DID: {}", "not exported yet".yellow());
    }
    println!("   Peer ID:   {}", our_peer_id.to_string().dimmed());
    println!("   Port:      {}", config.network.listen_port);
    println!("   Transport: {}", transport_label);
    if let Some(onion) = network.and_then(|n| n.onion_address.as_ref()) {
        println!(
            "   Onion:     {}",
            format!("{}.onion", onion).magenta().bold()
        );
    }
    if internet_mode {
        if let Some(eid) = iroh_endpoint_id {
            println!("   Iroh ID:   {}", eid.dimmed());
        }
        if config.network.hide_ip {
            println!("   Address:   {}", "[hidden]".dimmed());
        } else if let Some(addr) = iroh_invite_addr {
            let direct = addr
                .ip_addrs()
                .map(|a| a.to_string())
                .collect::<Vec<String>>();
            let relay_count = addr.relay_urls().count();
            if !direct.is_empty() {
                println!("   Direct:    {}", direct.join(", ").blue().bold());
            }
            println!(
                "   Relay:     {}",
                if relay_count > 0 {
                    format!("enabled ({} relay route)", relay_count)
                        .green()
                        .to_string()
                } else {
                    "disabled".yellow().to_string()
                }
            );
        } else {
            println!("   Address:   {}", "unknown".yellow());
        }
    }
    println!("   Log Mode:  {}", log_mode_label(log_mode));
    println!(
        "   E2EE:      {}",
        "active — hybrid bootstrap (X25519 + Kyber-1024) + Double Ratchet + AEGIS-256"
            .green()
            .bold()
    );
    println!(
        "   Security:  replay_guard={} rate_limit={}/min",
        config.security.replay_window_seconds, config.security.rate_limit_per_minute
    );
    println!("\n{}", "   Commands:".yellow().bold());
    println!("   {}       — list connected agents", "/peers".cyan());
    println!(
        "   {}         — list all known direct peers (online + offline)",
        "/all".cyan()
    );
    println!("   {}      — list active groups", "/groups".cyan());
    println!(
        "   {} <msg> — send encrypted chat to all peers",
        "/send".cyan()
    );
    println!(
        "   {} <peer|group_id> <msg> — send encrypted chat to one peer or one group",
        "/sendto".cyan()
    );
    println!(
        "   {} <peer> — disconnect one peer; DID works even if the peer is offline",
        "/disconnect".cyan()
    );
    println!(
        "   {}        — switch active chat peer (empty line only)",
        "Tab/Shift+Tab".cyan()
    );
    println!("   {} <file> <peer> — send E2EE file", "/transfer".cyan());
    println!(
        "   {} <group_id> <file> — send E2EE file to a specific group",
        "/transfer_g".cyan()
    );
    println!(
        "   {} [peer] <path> — set receive directory (or reset)",
        "/receive_dir".cyan()
    );
    println!(
        "   {} <peer> — approve one pending incoming transfer",
        "/accept".cyan()
    );
    println!(
        "   {} <peer> — always accept incoming transfers from peer",
        "/accept_always".cyan()
    );
    println!(
        "   {} <peer> — switch peer back to ask-on-each-transfer",
        "/accept_ask".cyan()
    );
    println!(
        "   {} <peer> — reject pending incoming file transfer",
        "/reject".cyan()
    );
    println!("   {}      — show identity details", "/whoami".cyan());
    if matches!(
        config.network.transport_mode,
        TransportMode::Tor | TransportMode::Internet
    ) {
        println!(
            "   {}     — generate invite code for peers",
            "/invite".cyan()
        );
        println!(
            "   {} <group-name> — create a reusable durable group",
            "/group_normal".cyan()
        );
        println!(
            "   {} <group-id> — generate a fresh invite for an existing durable group",
            "/invite_g".cyan()
        );
        println!(
            "   {} [group-name] — create a Ghost-only anonymous group and print its invite code",
            "/group_anon".cyan()
        );
        println!(
            "   {} <group-special-id> — regenerate an anonymous group invite",
            "/invite_anon".cyan()
        );
        println!(
            "   {} <group-member-did> — send a direct-handshake request to a group member (cooldown protected)",
            "/invite_h".cyan()
        );
        println!(
            "   {} <group-id> <group-member-did> — send a direct-handshake request scoped to one mailbox group (cooldown protected)",
            "/invite_hg".cyan()
        );
        println!(
            "   {} <group-member-did>  |  {} <group-member-did> — block or unblock direct-handshake requests from one member",
            "/block".cyan(),
            "/unblock".cyan()
        );
        println!(
            "   {} <peer-did>  |  {} <peer-did> — block or allow DID/invite first-contact requests from one peer",
            "/block_inv".cyan(),
            "/unlock_inv".cyan()
        );
        println!(
            "   {} <group-member-did>  |  {} <group-member-did> — legacy aliases for direct-handshake request blocking",
            "/block_r".cyan(),
            "/unblock_r".cyan()
        );
        println!(
            "   {} <group-member-did> — accept a pending /invite_h request",
            "/accept".cyan()
        );
        println!(
            "   {} [group-member-did] — reject a pending /invite_h request (no arg works when only one is pending)",
            "/reject".cyan()
        );
        println!(
            "   {}  |  {} — block or allow all incoming direct-handshake requests",
            "/block_all_r".cyan(),
            "/unblock_all_r".cyan()
        );
        println!("   {} <code> — connect via invite", "/connect".cyan());
        println!(
            "   {} <peer> — group owner removes member from group",
            "/kick_g".cyan()
        );
        println!(
            "   {} <group-id> — group owner locks mailbox group joins",
            "/lock_g".cyan()
        );
        println!(
            "   {} <group-id> — group owner unlocks mailbox group joins",
            "/unlock_g".cyan()
        );
        println!(
            "   {} <group-id> — leave and forget a joined mailbox group",
            "/leave_g".cyan()
        );
        println!(
            "   {} <group-id> — group owner disbands a mailbox group",
            "/disband".cyan()
        );
        if matches!(config.network.transport_mode, TransportMode::Tor) {
            println!("   {}       — show your .onion address", "/onion".cyan());
        }
    }
    println!("   {}        — quit", "/quit".cyan());
    println!("{}", "   ─────────────────────────────────".dimmed());
}

pub(crate) async fn record_agent_start(
    audit: &Arc<tokio::sync::Mutex<AuditLog>>,
    agent_did: &str,
    listen_port: u16,
    log_mode_str: &str,
) {
    let mut audit = audit.lock().await;
    audit.record(
        "AGENT_START",
        agent_did,
        &format!("port={} log_mode={}", listen_port, log_mode_str),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_guard_profile_matches_log_mode() {
        assert_eq!(
            runtime_guard_profile(&LogMode::Safe),
            RuntimeGuardProfile::Safe
        );
        assert_eq!(
            runtime_guard_profile(&LogMode::Ghost),
            RuntimeGuardProfile::Ghost
        );
    }
}
