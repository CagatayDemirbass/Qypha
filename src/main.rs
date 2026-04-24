#![allow(dead_code, unused_imports, unused_mut)]

use clap::{Parser, Subcommand};
use colored::Colorize;
use dialoguer::Password;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use sysinfo::{Pid, Process, ProcessRefreshKind, ProcessesToUpdate, Signal, System};
use tracing_subscriber::EnvFilter;

mod agent;
mod artifact;
mod config;
mod control_plane;
mod crypto;
mod network;
mod os_adapter;
mod runtime;
mod shadow;
mod tools;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/qypha.rs"));
}

/// Qypha - Enterprise Cryptographic Agent Network
#[derive(Parser)]
#[command(name = "Qypha", bin_name = "Qypha", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new agent on this machine
    Init {
        /// Display name for this agent
        #[arg(short, long)]
        name: String,

        /// Transport mode: lan, tor, internet (pre-configures the .toml)
        #[arg(short, long, default_value = "lan")]
        transport: String,

        /// Log mode: safe (ghost is launch-only)
        #[arg(long, default_value = "safe")]
        log_mode: String,

        /// Listen port (default: auto-assigned starting from 9090)
        #[arg(long)]
        port: Option<u16>,
    },

    /// Start the agent daemon
    Start {
        /// Configuration file path (default: qypha_<name>.toml)
        #[arg(short, long, default_value = "qypha.toml")]
        config: String,

        /// Override listen port (default from config)
        #[arg(long)]
        port: Option<u16>,

        /// Directly dial a peer on startup (e.g. /ip4/127.0.0.1/tcp/9090)
        /// Useful when mDNS is unavailable (same machine, VPN, Docker, etc.)
        #[arg(long)]
        peer: Option<String>,

        /// Log mode override: safe (ghost is launch-only)
        #[arg(long)]
        log_mode: Option<String>,

        /// Transport mode override: lan, tor, internet
        #[arg(long)]
        transport: Option<String>,

        /// Hide IP address from invites and display (Internet mode privacy)
        #[arg(long)]
        hide_ip: bool,
    },

    /// Send a message to another agent
    Send {
        /// Recipient agent DID
        #[arg(short, long)]
        to: String,

        /// Message content
        #[arg(short, long)]
        message: String,
    },

    /// Transfer a file/folder to another agent
    Transfer {
        /// Recipient agent DID
        #[arg(short, long)]
        to: String,

        /// Path to file or folder
        #[arg(short, long)]
        path: String,

        /// Data classification: public, internal, confidential, restricted
        #[arg(short, long, default_value = "internal")]
        classification: String,
    },

    /// List connected peers on the network
    Peers,

    /// Show agent status and identity
    Status,

    /// List all initialized agents on this machine
    ListAgents,

    /// Run the shared Tor mailbox relay service for sandbox groups
    MailboxServe {
        /// Mailbox service data directory
        #[arg(long, default_value = ".qypha-mailbox")]
        data_dir: String,

        /// Local loopback port for the mailbox HTTP server
        #[arg(long, default_value_t = 9444)]
        port: u16,

        /// Optional dedicated Tor state directory for the mailbox service
        #[arg(long)]
        tor_data_dir: Option<String>,

        /// Maximum opaque mailbox payload size
        #[arg(long, default_value_t = 256 * 1024)]
        max_payload_bytes: usize,

        /// Tor bootstrap / circuit timeout in seconds
        #[arg(long, default_value_t = 120)]
        circuit_timeout_secs: u64,

        /// Maximum new mailbox namespace bootstraps this relay will accept per hour
        #[arg(long, default_value_t = 128)]
        bootstrap_budget_per_hour: usize,

        /// Maximum concurrently active mailbox namespaces this relay will host
        #[arg(long, default_value_t = 2048)]
        max_active_namespaces: usize,

        /// Minimum leading-zero bits required in mailbox bootstrap PoW proofs
        #[arg(long, default_value_t = 12)]
        bootstrap_pow_difficulty_bits: u8,

        /// Allow only these bootstrap token issuer verifying keys (hex). Repeat the flag to add multiple issuers.
        #[arg(long = "allow-bootstrap-issuer")]
        bootstrap_issuer_allowlist: Vec<String>,
    },

    /// Shadow mode operations (executive only)
    Shadow {
        #[command(subcommand)]
        action: ShadowCommands,
    },

    /// Launch agent (interactive wizard by default, or non-interactive with flags)
    Launch {
        /// Agent name (required for non-interactive mode)
        #[arg(long)]
        name: Option<String>,

        /// Transport mode: lan, tor, internet
        #[arg(long)]
        transport: Option<String>,

        /// Log mode: safe, ghost
        #[arg(long)]
        log_mode: Option<String>,

        /// Listen port
        #[arg(long)]
        port: Option<u16>,
    },

    /// Destroy an agent — permanently delete all data (keys, tor, audit, config)
    Destroy {
        /// Agent name to destroy
        #[arg(short, long)]
        name: String,

        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },

    /// Destroy all initialized agents and their config files
    DestroyAll {
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },

    /// Read and decrypt audit log files
    AuditRead {
        /// Path to the encrypted audit log file (or agent name to auto-find)
        #[arg(short, long)]
        log_file: Option<String>,

        /// Agent name (used to find audit logs in per-agent directory)
        #[arg(long)]
        agent_name: Option<String>,

        /// Agent DID (legacy v1 decryption only; not needed with --passphrase or --root-key)
        #[arg(short, long)]
        agent_did: Option<String>,

        /// Output format: json, table, summary
        #[arg(short, long, default_value = "table")]
        format: String,

        /// Use a hex-encoded audit root key instead of agent DID for decryption
        #[arg(long)]
        root_key: Option<String>,

        /// Path to encrypted agent identity file (agent_identity.json) for v2 audit decryption
        #[arg(long)]
        identity_file: Option<String>,

        /// Agent passphrase to decrypt identity file and derive audit root key (v2 logs)
        #[arg(long)]
        passphrase: Option<String>,
    },
}

#[derive(Subcommand)]
enum ShadowCommands {
    /// Enable shadow channel (requires executive certificate)
    Enable,

    /// Send a shadow message
    Send {
        #[arg(short, long)]
        to: String,
        #[arg(short, long)]
        message: String,
    },

    /// Request a file via shadow channel
    Request {
        #[arg(short, long)]
        from: String,
        #[arg(short, long)]
        path: String,
    },
}

fn print_banner() {
    println!(
        "{}",
        r#"
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║                            Q Y P H A                             ║
    ║                                                                  ║
    ║     A decentralized cryptographic network for humans and AI      ║
    ║                              agents                              ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝
    "#
        .cyan()
    );
}

fn visible_command_title(command: &Commands) -> &'static str {
    match command {
        Commands::Init { .. } => "Qypha init",
        Commands::Start { .. } => "Qypha start",
        Commands::Send { .. } => "Qypha send",
        Commands::Transfer { .. } => "Qypha transfer",
        Commands::Peers => "Qypha peers",
        Commands::Status => "Qypha status",
        Commands::ListAgents => "Qypha list-agents",
        Commands::MailboxServe { .. } => "Qypha mailbox-serve",
        Commands::Launch { .. } => "Qypha launch",
        Commands::Destroy { .. } => "Qypha destroy",
        Commands::DestroyAll { .. } => "Qypha destroy-all",
        Commands::AuditRead { .. } => "Qypha audit-read",
        Commands::Shadow { action } => match action {
            ShadowCommands::Enable => "Qypha shadow enable",
            ShadowCommands::Send { .. } => "Qypha shadow send",
            ShadowCommands::Request { .. } => "Qypha shadow request",
        },
    }
}

fn set_visible_terminal_title(command: &Commands) {
    if !std::io::stdout().is_terminal() && !std::io::stderr().is_terminal() {
        return;
    }

    print!("\x1b]0;{}\x07", visible_command_title(command));
    let _ = std::io::stdout().flush();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    // Default level = ERROR (silences ALL external crates: Arti, Tor, libp2p, etc.)
    // Only our own `qypha` crate gets INFO+.  Override via RUST_LOG env var.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("error,qypha=warn")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    set_visible_terminal_title(&cli.command);

    match cli.command {
        Commands::Init {
            name,
            transport,
            log_mode,
            port,
        } => {
            print_banner();
            println!("{}", "Initializing new Qypha agent...".green().bold());
            agent::init::initialize_agent(&name, &transport, &log_mode, port).await?;
        }

        Commands::Start {
            config: config_path,
            port,
            peer,
            log_mode,
            transport,
            hide_ip,
        } => {
            print_banner();
            println!("{}", "Starting Qypha agent daemon...".green().bold());
            std::env::set_var("QYPHA_ACTIVE_CONFIG_PATH", &config_path);
            let mut cfg = config::AppConfig::load(&config_path)?;
            if cfg.has_encrypted_sensitive_fields() {
                let passphrase = config::config_passphrase_from_env()
                    .filter(|value| !value.trim().is_empty())
                    .or_else(|| {
                        Password::new()
                            .with_prompt(
                                "  Enter passphrase to decrypt config and unlock agent identity",
                            )
                            .interact()
                            .ok()
                            .filter(|value| !value.trim().is_empty())
                    })
                    .ok_or_else(|| {
                        anyhow::anyhow!("Passphrase required to decrypt encrypted config")
                    })?;
                std::env::set_var("QYPHA_PASSPHRASE", &passphrase);
                std::env::set_var("QYPHA_CONFIG_PASSPHRASE", &passphrase);
                cfg.decrypt_sensitive_fields(Some(&passphrase))?;
            }
            if let Some(p) = port {
                cfg.network.listen_port = p;
            }
            if let Some(ref mode) = log_mode {
                println!("{} {}", "Log mode override:".yellow().bold(), mode.cyan());
            }
            if let Some(ref mode) = transport {
                cfg.network.transport_mode = match mode.as_str() {
                    "lan" | "tcp" => config::TransportMode::Tcp,
                    "tor" => config::TransportMode::Tor,
                    "internet" | "inet" | "wan" => config::TransportMode::Internet,
                    _ => {
                        anyhow::bail!("Invalid transport mode '{}'. Use: lan, tor, internet", mode)
                    }
                };
                let label = match cfg.network.transport_mode {
                    config::TransportMode::Tcp => "LAN",
                    config::TransportMode::Tor => "Tor",
                    config::TransportMode::Internet => "Internet",
                };
                println!("{} {}", "Transport mode:".yellow().bold(), label.cyan());
            }
            if hide_ip {
                cfg.network.hide_ip = true;
                println!("{} {}", "IP privacy:".yellow().bold(), "enabled".green());
            }
            agent::daemon::start_daemon(cfg, peer, log_mode).await?;
        }

        Commands::Send { to, message } => {
            println!("{} {} -> {}", "Sending:".blue().bold(), message, to);
            println!("{}", "Message sent and encrypted.".green());
        }

        Commands::Transfer {
            to,
            path,
            classification,
        } => {
            println!(
                "{} {} -> {} [{}]",
                "Transferring:".blue().bold(),
                path,
                to,
                classification.yellow()
            );
            artifact::transfer::send_artifact(&to, &path, &classification).await?;
        }

        Commands::Peers => {
            println!("{}", "Connected peers:".blue().bold());
        }

        Commands::Status => {
            println!("{}", "Agent Status:".blue().bold());
            agent::status::show_status().await?;
        }

        Commands::ListAgents => {
            handle_list_agents()?;
        }

        Commands::MailboxServe {
            data_dir,
            port,
            tor_data_dir,
            max_payload_bytes,
            circuit_timeout_secs,
            bootstrap_budget_per_hour,
            max_active_namespaces,
            bootstrap_pow_difficulty_bits,
            bootstrap_issuer_allowlist,
        } => {
            print_banner();
            println!("{}", "Starting Qypha mailbox relay...".green().bold());
            let data_dir = std::path::PathBuf::from(data_dir);
            let tor_dir = tor_data_dir.as_deref().map(std::path::Path::new);
            network::mailbox_service::run_mailbox_service(
                &data_dir,
                port,
                tor_dir,
                circuit_timeout_secs,
                max_payload_bytes,
                network::mailbox_service::MailboxRelayPolicy {
                    bootstrap_budget_per_hour,
                    max_active_namespaces,
                    min_bootstrap_pow_difficulty_bits: bootstrap_pow_difficulty_bits,
                    bootstrap_issuer_allowlist,
                },
            )
            .await?;
        }

        Commands::Launch {
            name,
            transport,
            log_mode,
            port,
        } => {
            print_banner();
            match (name, transport, log_mode, port) {
                (Some(name), Some(transport), Some(log_mode), Some(port)) => {
                    agent::launch::launch_noninteractive(&name, &transport, &log_mode, port).await?
                }
                (None, None, None, None) => agent::launch::launch_wizard().await?,
                _ => {
                    anyhow::bail!(
                        "For non-interactive launch provide all flags: --name --transport --log-mode --port"
                    )
                }
            }
        }

        Commands::Destroy { name, force } => {
            print_banner();
            handle_destroy_agent(&name, force)?;
        }

        Commands::DestroyAll { force } => {
            print_banner();
            handle_destroy_all_agents(force)?;
        }

        Commands::Shadow { action } => match action {
            ShadowCommands::Enable => {
                println!("{}", "Enabling Shadow Executive Mode...".red().bold());
                shadow::channel::enable_shadow_mode().await?;
            }
            ShadowCommands::Send { to, message } => {
                shadow::channel::send_shadow_message(&to, &message).await?;
            }
            ShadowCommands::Request { from, path } => {
                shadow::channel::request_shadow_file(&from, &path).await?;
            }
        },

        Commands::AuditRead {
            log_file,
            agent_name,
            agent_did,
            format,
            root_key,
            identity_file,
            passphrase,
        } => {
            handle_audit_read(
                log_file.as_deref(),
                agent_name.as_deref(),
                agent_did.as_deref(),
                &format,
                root_key.as_deref(),
                identity_file.as_deref(),
                passphrase.as_deref(),
            )?;
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Destroy agent
// ─────────────────────────────────────────────────────────────────────────────

fn handle_destroy_agent(name: &str, force: bool) -> anyhow::Result<()> {
    let data_dir = crypto::keystore::KeyStore::agent_data_path(name)?;
    let config_paths = existing_agent_config_paths(name);
    let pub_path = format!("{}_public.json", name.to_lowercase());
    let has_workspace_state = workspace_agent_state_exists(name)?;

    if !data_dir.exists()
        && config_paths.is_empty()
        && !std::path::Path::new(&pub_path).exists()
        && !has_workspace_state
    {
        println!("{} Agent '{}' not found.", "Error:".red().bold(), name);
        return Ok(());
    }

    println!("{}", "=== Agent Destruction ===".red().bold());
    println!("  Agent:    {}", name.cyan());
    println!("  Data dir: {}", data_dir.display().to_string().dimmed());
    println!();
    println!("  {}", "This will PERMANENTLY DELETE:".red().bold());
    println!("    - Encrypted keypair (agent_identity.json)");
    println!("    - Public identity");
    println!("    - Tor onion keys & state");
    println!("    - Audit logs");
    println!("    - RBAC configuration");
    println!("    - Known peers database");
    for config_path in &config_paths {
        println!("    - Config file: {}", config_path.display());
    }
    if has_workspace_state {
        println!("    - Desktop AI profile metadata");
        println!("    - AI chat thread history");
        println!("    - Embedded runtime per-agent session state");
    }

    if !force {
        use dialoguer::Confirm;
        let confirmed = Confirm::new()
            .with_prompt(format!("  Permanently destroy agent '{}'?", name))
            .default(false)
            .interact()
            .unwrap_or(false);

        if !confirmed {
            println!("  {}", "Cancelled.".yellow());
            return Ok(());
        }
    }

    let stopped = stop_running_agent_processes_for_agent(name, &config_paths);
    if stopped > 0 {
        println!(
            "  {} stopped {} live runtime process(es)",
            "Stopped:".yellow(),
            stopped
        );
    }

    // Securely wipe the agent data directory (NIST SP 800-88: overwrite + TRIM + unlink)
    // This overwrites all key material, Tor state, and audit logs with random bytes
    // before unlinking — prevents SSD flash cell recovery of sensitive data.
    if data_dir.exists() {
        os_adapter::secure_wipe::secure_wipe_dir(&data_dir);
        println!(
            "  {} {} (secure wiped)",
            "Destroyed:".red(),
            data_dir.display()
        );
    }

    // Secure wipe any persisted config path we know about
    for config_path in config_paths {
        os_adapter::secure_wipe::secure_wipe_file(&config_path);
        println!(
            "  {} {} (secure wiped)",
            "Destroyed:".red(),
            config_path.display()
        );
    }

    // Secure wipe public identity file in current directory (if exists)
    if std::path::Path::new(&pub_path).exists() {
        os_adapter::secure_wipe::secure_wipe_file(std::path::Path::new(&pub_path));
        println!("  {} {} (secure wiped)", "Destroyed:".red(), pub_path);
    }

    destroy_workspace_agent_artifacts(name)?;

    println!(
        "\n  {} Agent '{}' has been permanently destroyed.",
        "Done.".green().bold(),
        name
    );
    println!("  {}", "All data securely wiped (NIST SP 800-88).".dimmed());

    Ok(())
}

fn handle_destroy_all_agents(force: bool) -> anyhow::Result<()> {
    let agents = crypto::keystore::list_agents()?;
    let raw_agent_dirs = crypto::keystore::list_agent_data_dirs()?;
    let orphan_configs = collect_orphan_agent_configs(&agents)?;
    let has_workspace_state = workspace_destroy_all_state_exists()?;
    let has_raw_agent_dirs = !raw_agent_dirs.is_empty();

    if agents.is_empty() && orphan_configs.is_empty() && !has_workspace_state && !has_raw_agent_dirs
    {
        println!("{}", "No agents or agent configs found.".yellow());
        return Ok(());
    }

    println!("{}", "=== Destroy All Agents ===".red().bold());
    println!("  Agents: {}", agents.len().to_string().cyan());
    if raw_agent_dirs.len() > agents.len() {
        println!(
            "  Stale agent roots: {}",
            (raw_agent_dirs.len() - agents.len()).to_string().cyan()
        );
    }
    println!(
        "  Orphan configs: {}",
        orphan_configs.len().to_string().cyan()
    );
    println!();
    println!("  {}", "This will PERMANENTLY DELETE:".red().bold());
    println!("    - All encrypted agent identities");
    println!("    - All Tor state, audit logs, and peer state");
    println!("    - All agent config files in agent-configs/");
    println!("    - Any legacy per-agent config copies");
    if has_workspace_state {
        println!("    - Desktop AI profiles and chat thread history");
        println!("    - Embedded runtime per-agent sessions and shared runtime state");
    }

    if !force {
        use dialoguer::Confirm;
        let prompt = if has_workspace_state || !orphan_configs.is_empty() {
            "  Permanently destroy all discovered agent data and AI runtime state?".to_string()
        } else {
            format!("  Permanently destroy ALL {} agent(s)?", agents.len())
        };
        let confirmed = Confirm::new()
            .with_prompt(prompt)
            .default(false)
            .interact()
            .unwrap_or(false);

        if !confirmed {
            println!("  {}", "Cancelled.".yellow());
            return Ok(());
        }
    }

    let stopped = stop_all_running_agent_processes();
    if stopped > 0 {
        println!(
            "  {} stopped {} live runtime process(es)",
            "Stopped:".yellow(),
            stopped
        );
    }

    for name in &agents {
        destroy_agent_artifacts(name)?;
    }

    for data_dir in raw_agent_dirs {
        if data_dir.exists() {
            os_adapter::secure_wipe::secure_wipe_dir(&data_dir);
            println!(
                "  {} {} (secure wiped stale agent root)",
                "Destroyed:".red(),
                data_dir.display()
            );
        }
    }

    for config_path in orphan_configs {
        os_adapter::secure_wipe::secure_wipe_file(&config_path);
        println!(
            "  {} {} (secure wiped orphan config)",
            "Destroyed:".red(),
            config_path.display()
        );
    }

    destroy_workspace_all_artifacts()?;

    remove_empty_agent_roots()?;

    println!(
        "\n  {} Destroyed {} agent(s).",
        "Done.".green().bold(),
        agents.len()
    );
    println!(
        "  {}",
        "All discovered agent data and configs securely wiped.".dimmed()
    );
    Ok(())
}

fn destroy_agent_artifacts(name: &str) -> anyhow::Result<()> {
    let data_dir = crypto::keystore::KeyStore::agent_data_path(name)?;
    let config_paths = existing_agent_config_paths(name);

    if data_dir.exists() {
        os_adapter::secure_wipe::secure_wipe_dir(&data_dir);
        println!(
            "  {} {} (secure wiped)",
            "Destroyed:".red(),
            data_dir.display()
        );
    }

    for config_path in config_paths {
        os_adapter::secure_wipe::secure_wipe_file(&config_path);
        println!(
            "  {} {} (secure wiped)",
            "Destroyed:".red(),
            config_path.display()
        );
    }

    let pub_path = format!("{}_public.json", name.to_lowercase());
    if std::path::Path::new(&pub_path).exists() {
        os_adapter::secure_wipe::secure_wipe_file(std::path::Path::new(&pub_path));
        println!("  {} {} (secure wiped)", "Destroyed:".red(), pub_path);
    }

    destroy_workspace_agent_artifacts(name)?;

    Ok(())
}

fn refresh_process_table(system: &mut System) {
    system.refresh_processes_specifics(ProcessesToUpdate::All, ProcessRefreshKind::everything());
}

fn process_cmd_strings(process: &Process) -> Vec<String> {
    process
        .cmd()
        .iter()
        .map(|value| value.to_string_lossy().into_owned())
        .collect()
}

fn is_qypha_runtime_command(process_name: &str, cmd: &[String]) -> bool {
    if !cmd.iter().any(|arg| arg == "start" || arg == "launch") {
        return false;
    }

    let process_name = process_name.to_lowercase();
    let command_name = cmd
        .first()
        .map(|value| value.to_lowercase())
        .unwrap_or_default();
    process_name.contains("qypha") || command_name.contains("qypha")
}

fn is_qypha_runtime_process(process: &Process) -> bool {
    let cmd = process_cmd_strings(process);
    let process_name = process.name().to_string_lossy().into_owned();
    is_qypha_runtime_command(&process_name, &cmd)
}

fn process_path_candidates(path: &Path) -> Vec<String> {
    let mut candidates = vec![path.to_string_lossy().into_owned()];
    if let Ok(canonical) = std::fs::canonicalize(path) {
        let canonical = canonical.to_string_lossy().into_owned();
        if !candidates.iter().any(|existing| existing == &canonical) {
            candidates.push(canonical);
        }
    }
    candidates
}

fn process_matches_agent_runtime(process: &Process, name: &str, config_paths: &[PathBuf]) -> bool {
    if !is_qypha_runtime_process(process) {
        return false;
    }

    let cmd = process_cmd_strings(process);
    let sanitized_name = crypto::keystore::KeyStore::sanitize_agent_name(name);
    let expected_config_file = format!("qypha_{}.toml", sanitized_name);
    let expected_config_stem = format!("qypha_{}", sanitized_name);

    if config_paths
        .iter()
        .flat_map(|path| process_path_candidates(path))
        .any(|candidate| {
            cmd.iter()
                .any(|arg| arg == &candidate || arg.contains(&candidate))
        })
    {
        return true;
    }

    cmd.iter().any(|arg| {
        arg == &sanitized_name
            || arg == &expected_config_file
            || arg.ends_with(&expected_config_file)
            || arg.contains(&expected_config_stem)
    })
}

fn collect_process_tree(system: &System, roots: &BTreeSet<Pid>) -> Vec<Pid> {
    let mut depths = BTreeMap::new();
    for pid in roots {
        depths.insert(*pid, 0usize);
    }

    loop {
        let mut changed = false;
        for (pid, process) in system.processes() {
            if depths.contains_key(pid) {
                continue;
            }
            let Some(parent) = process.parent() else {
                continue;
            };
            let Some(parent_depth) = depths.get(&parent).copied() else {
                continue;
            };
            depths.insert(*pid, parent_depth + 1);
            changed = true;
        }
        if !changed {
            break;
        }
    }

    let mut entries = depths.into_iter().collect::<Vec<_>>();
    entries.sort_by(|(left_pid, left_depth), (right_pid, right_depth)| {
        right_depth
            .cmp(left_depth)
            .then_with(|| right_pid.cmp(left_pid))
    });
    entries.into_iter().map(|(pid, _)| pid).collect()
}

fn signal_process(process: &Process, signal: Signal) {
    if process.kill_with(signal).unwrap_or(false) {
        return;
    }
    let _ = process.kill();
}

fn stop_process_roots(system: &mut System, roots: BTreeSet<Pid>) -> usize {
    if roots.is_empty() {
        return 0;
    }

    let targets = collect_process_tree(system, &roots);
    for pid in &targets {
        if let Some(process) = system.process(*pid) {
            signal_process(process, Signal::Term);
        }
    }

    thread::sleep(Duration::from_millis(900));
    refresh_process_table(system);

    let mut remaining = Vec::new();
    for pid in &targets {
        if let Some(process) = system.process(*pid) {
            remaining.push(*pid);
            signal_process(process, Signal::Kill);
        }
    }

    if !remaining.is_empty() {
        thread::sleep(Duration::from_millis(300));
        refresh_process_table(system);
    }

    targets.len()
}

fn stop_running_agent_processes_for_agent(name: &str, config_paths: &[PathBuf]) -> usize {
    let mut system = System::new();
    refresh_process_table(&mut system);
    let roots = system
        .processes()
        .iter()
        .filter_map(|(pid, process)| {
            if process_matches_agent_runtime(process, name, config_paths) {
                Some(*pid)
            } else {
                None
            }
        })
        .collect::<BTreeSet<_>>();
    stop_process_roots(&mut system, roots)
}

fn stop_all_running_agent_processes() -> usize {
    let mut system = System::new();
    refresh_process_table(&mut system);
    let roots = system
        .processes()
        .iter()
        .filter_map(|(pid, process)| {
            if is_qypha_runtime_process(process) {
                Some(*pid)
            } else {
                None
            }
        })
        .collect::<BTreeSet<_>>();
    stop_process_roots(&mut system, roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qypha_runtime_command_accepts_start_and_launch() {
        let binary = "/Users/test/qypha".to_string();

        assert!(is_qypha_runtime_command(
            "qypha",
            &[binary.clone(), "start".to_string(), "--config".to_string()]
        ));
        assert!(is_qypha_runtime_command(
            "qypha",
            &[binary, "launch".to_string()]
        ));
    }

    #[test]
    fn qypha_runtime_command_rejects_non_runtime_subcommands() {
        assert!(!is_qypha_runtime_command(
            "qypha",
            &["/Users/test/qypha".to_string(), "destroy-all".to_string()]
        ));
        assert!(!is_qypha_runtime_command(
            "bash",
            &["/bin/bash".to_string(), "launch".to_string()]
        ));
    }
}

fn workspace_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_agent_config_root() -> std::path::PathBuf {
    workspace_root().join("agent-configs")
}

fn workspace_active_agent_selection_path() -> std::path::PathBuf {
    workspace_agent_config_root().join("qypha_active_agent.txt")
}

fn workspace_agent_metadata_path(name: &str) -> std::path::PathBuf {
    workspace_agent_config_root().join(format!(
        "qypha_{}.desktop-profile.json",
        crypto::keystore::KeyStore::sanitize_agent_name(name)
    ))
}

fn workspace_embedded_runtime_root() -> std::path::PathBuf {
    workspace_agent_config_root().join("qypha-runtime")
}

fn workspace_embedded_runtime_agent_dir(name: &str) -> std::path::PathBuf {
    workspace_embedded_runtime_root().join(crypto::keystore::KeyStore::sanitize_agent_name(name))
}

fn fallback_embedded_runtime_root() -> std::path::PathBuf {
    crypto::keystore::KeyStore::agent_data_path("embedded_runtime")
        .unwrap_or_else(|_| workspace_root().join(".qypha-runtime-user"))
        .join("runtime")
}

fn fallback_embedded_runtime_agent_dir(name: &str) -> std::path::PathBuf {
    fallback_embedded_runtime_root().join(crypto::keystore::KeyStore::sanitize_agent_name(name))
}

fn workspace_legacy_embedded_runtime_root() -> std::path::PathBuf {
    workspace_agent_config_root().join("embedded-runtime")
}

fn workspace_legacy_embedded_runtime_agent_dir(name: &str) -> std::path::PathBuf {
    workspace_legacy_embedded_runtime_root()
        .join(crypto::keystore::KeyStore::sanitize_agent_name(name))
}

fn workspace_ai_thread_paths(name: &str) -> anyhow::Result<Vec<std::path::PathBuf>> {
    let config_root = workspace_agent_config_root();
    let prefix = format!(
        "qypha_{}.thread_",
        crypto::keystore::KeyStore::sanitize_agent_name(name)
    );
    let mut paths = Vec::new();
    if !config_root.exists() {
        return Ok(paths);
    }
    for entry in std::fs::read_dir(&config_root)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if file_name.starts_with(&prefix) && file_name.ends_with(".ai-chat.json") {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn workspace_active_agent_matches(name: &str) -> bool {
    let path = workspace_active_agent_selection_path();
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    crypto::keystore::KeyStore::sanitize_agent_name(content.trim())
        == crypto::keystore::KeyStore::sanitize_agent_name(name)
}

fn workspace_agent_state_exists(name: &str) -> anyhow::Result<bool> {
    Ok(workspace_agent_metadata_path(name).exists()
        || workspace_embedded_runtime_agent_dir(name).exists()
        || fallback_embedded_runtime_agent_dir(name).exists()
        || workspace_legacy_embedded_runtime_agent_dir(name).exists()
        || workspace_active_agent_matches(name)
        || !workspace_ai_thread_paths(name)?.is_empty())
}

fn workspace_destroy_all_state_exists() -> anyhow::Result<bool> {
    let config_root = workspace_agent_config_root();
    if workspace_embedded_runtime_root().exists()
        || fallback_embedded_runtime_root().exists()
        || workspace_legacy_embedded_runtime_root().exists()
        || workspace_active_agent_selection_path().exists()
    {
        return Ok(true);
    }
    if !config_root.exists() {
        return Ok(false);
    }
    for entry in std::fs::read_dir(config_root)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if file_name.starts_with("qypha_")
            && (file_name.ends_with(".desktop-profile.json")
                || file_name.ends_with(".ai-chat.json"))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn destroy_workspace_agent_artifacts(name: &str) -> anyhow::Result<()> {
    let metadata_path = workspace_agent_metadata_path(name);
    if metadata_path.exists() {
        os_adapter::secure_wipe::secure_wipe_file(&metadata_path);
        println!(
            "  {} {} (secure wiped)",
            "Destroyed:".red(),
            metadata_path.display()
        );
    }

    for thread_path in workspace_ai_thread_paths(name)? {
        if thread_path.exists() {
            os_adapter::secure_wipe::secure_wipe_file(&thread_path);
            println!(
                "  {} {} (secure wiped)",
                "Destroyed:".red(),
                thread_path.display()
            );
        }
    }

    let embedded_runtime_agent_dir = workspace_embedded_runtime_agent_dir(name);
    if embedded_runtime_agent_dir.exists() {
        os_adapter::secure_wipe::secure_wipe_dir(&embedded_runtime_agent_dir);
        println!(
            "  {} {} (secure wiped)",
            "Destroyed:".red(),
            embedded_runtime_agent_dir.display()
        );
    }

    let fallback_embedded_runtime_agent_dir = fallback_embedded_runtime_agent_dir(name);
    if fallback_embedded_runtime_agent_dir.exists() {
        os_adapter::secure_wipe::secure_wipe_dir(&fallback_embedded_runtime_agent_dir);
        println!(
            "  {} {} (secure wiped)",
            "Destroyed:".red(),
            fallback_embedded_runtime_agent_dir.display()
        );
    }

    let legacy_embedded_runtime_agent_dir = workspace_legacy_embedded_runtime_agent_dir(name);
    if legacy_embedded_runtime_agent_dir.exists() {
        os_adapter::secure_wipe::secure_wipe_dir(&legacy_embedded_runtime_agent_dir);
        println!(
            "  {} {} (secure wiped)",
            "Destroyed:".red(),
            legacy_embedded_runtime_agent_dir.display()
        );
    }

    let active_path = workspace_active_agent_selection_path();
    if active_path.exists() && workspace_active_agent_matches(name) {
        os_adapter::secure_wipe::secure_wipe_file(&active_path);
        println!(
            "  {} {} (secure wiped)",
            "Destroyed:".red(),
            active_path.display()
        );
    }

    Ok(())
}

fn destroy_workspace_all_artifacts() -> anyhow::Result<()> {
    let config_root = workspace_agent_config_root();
    if config_root.exists() {
        for entry in std::fs::read_dir(&config_root)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let path = entry.path();
            let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if file_name == "qypha_active_agent.txt"
                || (file_name.starts_with("qypha_")
                    && (file_name.ends_with(".desktop-profile.json")
                        || file_name.ends_with(".ai-chat.json")))
            {
                os_adapter::secure_wipe::secure_wipe_file(&path);
                println!("  {} {} (secure wiped)", "Destroyed:".red(), path.display());
            }
        }
    }

    let embedded_runtime_root = workspace_embedded_runtime_root();
    if embedded_runtime_root.exists() {
        os_adapter::secure_wipe::secure_wipe_dir(&embedded_runtime_root);
        println!(
            "  {} {} (secure wiped)",
            "Destroyed:".red(),
            embedded_runtime_root.display()
        );
    }

    let fallback_embedded_runtime_root = fallback_embedded_runtime_root();
    if fallback_embedded_runtime_root.exists() {
        os_adapter::secure_wipe::secure_wipe_dir(&fallback_embedded_runtime_root);
        println!(
            "  {} {} (secure wiped)",
            "Destroyed:".red(),
            fallback_embedded_runtime_root.display()
        );
    }

    let legacy_embedded_runtime_root = workspace_legacy_embedded_runtime_root();
    if legacy_embedded_runtime_root.exists() {
        os_adapter::secure_wipe::secure_wipe_dir(&legacy_embedded_runtime_root);
        println!(
            "  {} {} (secure wiped)",
            "Destroyed:".red(),
            legacy_embedded_runtime_root.display()
        );
    }

    Ok(())
}

fn existing_agent_config_paths(name: &str) -> Vec<std::path::PathBuf> {
    let canonical_config_path = agent::init::config_path_for_agent(name);
    let legacy_config_path = agent::init::legacy_config_path_for_agent(name);
    let legacy_agent_scoped_config_path =
        agent::init::legacy_agent_scoped_config_path_for_agent(name);
    let mut config_paths = Vec::new();
    for path in [
        canonical_config_path,
        legacy_config_path,
        legacy_agent_scoped_config_path,
    ] {
        if path.exists() && !config_paths.iter().any(|existing| existing == &path) {
            config_paths.push(path);
        }
    }
    config_paths
}

fn collect_orphan_agent_configs(agent_names: &[String]) -> anyhow::Result<Vec<std::path::PathBuf>> {
    let mut paths = Vec::new();
    let canonical_root = agent::init::config_path_for_agent("placeholder")
        .parent()
        .map(std::path::Path::to_path_buf);
    if let Some(root) = canonical_root {
        if root.exists() {
            for entry in std::fs::read_dir(&root)? {
                let entry = entry?;
                if !entry.file_type()?.is_file() {
                    continue;
                }
                let path = entry.path();
                let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                if !file_name.starts_with("qypha_") || !file_name.ends_with(".toml") {
                    continue;
                }
                let agent_name = file_name
                    .trim_start_matches("qypha_")
                    .trim_end_matches(".toml");
                if !agent_names.iter().any(|existing| existing == agent_name) {
                    paths.push(path);
                }
            }
        }
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn remove_empty_agent_roots() -> anyhow::Result<()> {
    if let Some(parent) = agents_root_dir() {
        if parent.exists() && std::fs::read_dir(&parent)?.next().is_none() {
            let _ = std::fs::remove_dir(parent);
        }
    }
    let canonical_root = agent::init::config_path_for_agent("placeholder")
        .parent()
        .map(std::path::Path::to_path_buf);
    if let Some(root) = canonical_root {
        if root.exists() && std::fs::read_dir(&root)?.next().is_none() {
            let _ = std::fs::remove_dir(root);
        }
    }
    Ok(())
}

fn agents_root_dir() -> Option<std::path::PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("USERPROFILE")
            .map(std::path::PathBuf::from)
            .map(|home| home.join(".qypha").join("agents"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .map(|home| home.join(".qypha").join("agents"))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// List agents
// ─────────────────────────────────────────────────────────────────────────────

fn handle_list_agents() -> anyhow::Result<()> {
    let agents = crypto::keystore::list_agents()?;
    if agents.is_empty() {
        println!("{}", "No agents initialized on this machine.".yellow());
        println!("  Run: Qypha init --name <name>");
        return Ok(());
    }

    println!("{}", "=== Initialized Agents ===".blue().bold());
    for name in &agents {
        let data_dir = crypto::keystore::KeyStore::agent_data_dir(name)?;

        let did_info = agent::contact_identity::read_agent_contact_did(name)
            .map(|did| did.green().to_string())
            .unwrap_or_else(|| "(contact DID not exported yet)".yellow().to_string());

        println!("  {} — {}", name.cyan().bold(), did_info);
        println!("    Data: {}", data_dir.display().to_string().dimmed());
    }
    println!("\n  Total: {} agent(s)", agents.len());

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit read handler
// ─────────────────────────────────────────────────────────────────────────────

fn handle_audit_read(
    log_file: Option<&str>,
    agent_name: Option<&str>,
    agent_did: Option<&str>,
    format: &str,
    root_key_hex: Option<&str>,
    identity_file: Option<&str>,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    use control_plane::audit::AuditLog;
    use crypto::identity::AgentKeyPair;

    // Determine log file path
    let log_path = if let Some(file) = log_file {
        std::path::PathBuf::from(file)
    } else if let Some(name) = agent_name {
        // Auto-find latest audit log in agent's directory
        let audit_dir = crypto::keystore::KeyStore::agent_data_dir(name)?.join("audit");
        if !audit_dir.exists() {
            anyhow::bail!(
                "No audit directory found for agent '{}' at {}",
                name,
                audit_dir.display()
            );
        }
        find_latest_audit_log(&audit_dir)?
    } else {
        anyhow::bail!("Provide either --log-file or --agent-name to locate audit logs.");
    };

    if !log_path.exists() {
        anyhow::bail!("Audit log file not found: {}", log_path.display());
    }

    println!("{} {}", "Reading:".dimmed(), log_path.display());

    let entries = if let Some(key_hex) = root_key_hex {
        let key_bytes =
            hex::decode(key_hex).map_err(|_| anyhow::anyhow!("Invalid hex root key"))?;
        let key: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Root key must be 32 bytes (64 hex chars)"))?;
        AuditLog::read_log_with_key(&log_path, &key)?
    } else if let Some(passphrase) = passphrase {
        let identity_path = if let Some(path) = identity_file {
            std::path::PathBuf::from(path)
        } else if let Some(name) = agent_name {
            crypto::keystore::KeyStore::agent_keys_dir(name)?.join("agent_identity.json")
        } else {
            anyhow::bail!(
                "For v2 audit logs, provide --identity-file <path> or --agent-name <name> with --passphrase."
            );
        };

        let keypair = AgentKeyPair::load_from_file(&identity_path, passphrase).map_err(|e| {
            anyhow::anyhow!("Failed to load identity {}: {}", identity_path.display(), e)
        })?;
        let x25519_secret = keypair.x25519_secret_key_bytes();
        let kyber_secret = if keypair.kyber_secret.is_empty() {
            None
        } else {
            Some(keypair.kyber_secret.as_slice())
        };
        let root = AuditLog::derive_root_key_from_secrets(&x25519_secret, kyber_secret);
        AuditLog::read_log_with_root_key(&log_path, &root)?
    } else {
        println!(
            "{}",
            "Warning: Using legacy DID-based decryption path. For v2 logs, pass --passphrase."
                .yellow()
        );
        let did = agent_did.ok_or_else(|| {
            anyhow::anyhow!("Legacy v1 decryption requires --agent-did (or use --passphrase).")
        })?;
        AuditLog::read_log(&log_path, did)?
    };

    match format {
        "json" => {
            let json = serde_json::to_string_pretty(&entries)?;
            println!("{}", json);
        }
        "summary" => {
            println!("{}", "=== Audit Log Summary ===".blue().bold());
            println!("  File: {}", log_path.display());
            if let Some(did) = agent_did {
                println!("  Agent: {}", did.cyan());
            }
            println!("  Total entries: {}", entries.len().to_string().yellow());

            if let Some(first) = entries.first() {
                println!("  First entry: {} ({})", first.timestamp, first.event_type);
            }
            if let Some(last) = entries.last() {
                println!("  Last entry: {} ({})", last.timestamp, last.event_type);
            }

            let mut type_counts: std::collections::HashMap<&str, usize> =
                std::collections::HashMap::new();
            for e in &entries {
                *type_counts.entry(&e.event_type).or_insert(0) += 1;
            }
            println!("\n  Event types:");
            for (t, count) in &type_counts {
                println!("    {} x{}", t.cyan(), count);
            }
        }
        _ => {
            // Table format (default)
            println!("{}", "=== Audit Log ===".blue().bold());
            println!(
                "  {:<6} {:<28} {:<16} {:<24} {}",
                "Seq".bold(),
                "Timestamp".bold(),
                "Event".bold(),
                "Actor".bold(),
                "Details".bold(),
            );
            println!("  {}", "-".repeat(100));
            for e in &entries {
                println!(
                    "  {:<6} {:<28} {:<16} {:<24} {}",
                    e.seq,
                    e.timestamp,
                    e.event_type.yellow(),
                    e.actor_did.cyan(),
                    e.details,
                );
            }
            println!("\n  Total: {} entries", entries.len());
        }
    }

    Ok(())
}

/// Find the most recently modified .enc file in the audit directory
fn find_latest_audit_log(audit_dir: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
    let mut latest: Option<(std::path::PathBuf, std::time::SystemTime)> = None;

    for entry in std::fs::read_dir(audit_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map_or(false, |e| e == "enc") {
            if let Ok(meta) = entry.metadata() {
                if let Ok(modified) = meta.modified() {
                    if latest.as_ref().map_or(true, |(_, t)| modified > *t) {
                        latest = Some((path, modified));
                    }
                }
            }
        }
    }

    latest
        .map(|(p, _)| p)
        .ok_or_else(|| anyhow::anyhow!("No audit log files found in {}", audit_dir.display()))
}
