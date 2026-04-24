use crate::config::{AppConfig, LoggingConfig, NetworkConfig, SecurityConfig, TransportMode};
use crate::crypto::identity::AgentKeyPair;
use crate::crypto::keystore::{harden_private_dir, list_agents, write_private_file, KeyStore};
use crate::network::contact_did::encode_contact_did;
use crate::network::did_profile::DidProfile;
use anyhow::{Context, Result};
use colored::Colorize;
use std::path::{Path, PathBuf};

const MIN_SAFE_PASSPHRASE_LEN: usize = 6;

pub(crate) struct ExportedContactArtifacts {
    pub(crate) contact_did: String,
    pub(crate) contact_did_path: PathBuf,
    pub(crate) profile: DidProfile,
}

/// Initialize a new agent on this machine.
///
/// Each agent gets its own isolated data directory:
///   ~/.qypha/agents/<name>/keys/agent_identity.json
///   ~/.qypha/agents/<name>/audit/
///   ~/.qypha/agents/<name>/rbac.json
///
/// Config file is written under the workspace config directory:
///   /Users/cagatayd/Desktop/qypha/agent-configs/qypha_<name>.toml
/// Older workspace-root and per-agent config copies are migrated forward.
pub async fn initialize_agent(
    name: &str,
    transport: &str,
    log_mode: &str,
    port: Option<u16>,
) -> Result<()> {
    const DEFAULT_AGENT_ROLE: &str = "agent";
    println!("\n{}", "═══ Agent Initialization ═══".cyan().bold());

    // Use explicit port if provided, otherwise auto-assign (9090 + existing agent count)
    let listen_port = if let Some(p) = port {
        p
    } else {
        let existing_count = list_agents().unwrap_or_default().len() as u16;
        9090 + existing_count
    };

    // Validate transport mode
    let transport_mode = match transport.to_lowercase().as_str() {
        "lan" | "tcp" => crate::config::TransportMode::Tcp,
        "tor" => crate::config::TransportMode::Tor,
        "internet" | "inet" | "wan" => crate::config::TransportMode::Internet,
        _ => {
            anyhow::bail!(
                "Invalid transport mode: '{}'. Use: lan, tor, or internet",
                transport
            );
        }
    };

    // Validate log mode
    let effective_log_mode = match log_mode.to_lowercase().as_str() {
        "safe" => "safe".to_string(),
        "ghost" => {
            anyhow::bail!(
                "Ghost mode does not allow persistent agent initialization. \
                 Use `Qypha launch` and choose Ghost."
            );
        }
        _ => {
            anyhow::bail!(
                "Invalid log mode: '{}'. Use: safe (ghost is launch-only).",
                log_mode
            );
        }
    };
    let effective_log_mode = effective_log_mode;

    // Step 1: Generate cryptographic identity
    println!(
        "\n{}",
        "Step 1/4: Generating cryptographic identity...".yellow()
    );
    let keypair = AgentKeyPair::generate(name, DEFAULT_AGENT_ROLE);
    println!("  Identity: {}", "generated".green());
    println!(
        "  Public Key: {}...",
        &hex::encode(keypair.verifying_key.as_bytes())[..16].dimmed()
    );

    // Step 2: Save encrypted identity — prompt for passphrase interactively
    println!("\n{}", "Step 2/4: Saving encrypted identity...".yellow());
    let keys_dir = KeyStore::agent_keys_dir(name)?;
    let keystore = KeyStore::new(&keys_dir);

    let passphrase = prompt_passphrase()?;
    std::env::set_var("QYPHA_PASSPHRASE", &passphrase);
    std::env::set_var("QYPHA_CONFIG_PASSPHRASE", &passphrase);
    keypair.save_to_file(&keystore.identity_path(), &passphrase)?;
    println!("  Saved to: {}", keystore.identity_path().display());

    // Step 3: Create default configuration
    println!("\n{}", "Step 3/4: Creating configuration...".yellow());

    // Log mode is explicit and must be one of the supported modes.
    let final_log_mode = effective_log_mode.clone();

    let config = build_persistent_agent_config(
        name,
        DEFAULT_AGENT_ROLE,
        &keypair.did,
        transport_mode.clone(),
        &final_log_mode,
        listen_port,
    );

    let config_path = persist_agent_config(name, &config, Some(&passphrase))?;
    let config_filename = config_path.display().to_string();
    println!("  Config: {}", config_path.display());

    // Step 4: Save public identity for peer sharing
    println!("\n{}", "Step 4/4: Exporting public identity...".yellow());
    let pub_identity = keypair.public_identity();
    let pub_json = serde_json::to_string_pretty(&pub_identity)?;
    let pub_path = keys_dir.join("public_identity.json");
    std::fs::write(&pub_path, &pub_json)?;
    println!("  Public identity: {}", pub_path.display());

    let agent_data_dir = KeyStore::agent_data_dir(name)?;
    let exported_contact = export_contact_artifacts(
        &keys_dir,
        &agent_data_dir,
        &keypair,
        &config,
        &crate::control_plane::audit::LogMode::Safe,
    )?;
    println!("  Contact DID: {}", exported_contact.contact_did.green());
    println!(
        "  Contact file: {}",
        exported_contact.contact_did_path.display()
    );

    println!("\n{}", "═══ Agent Ready! ═══".green().bold());
    println!("\n  Name:      {}", name.cyan());
    println!("  Transport: {}", format_transport(&transport_mode).cyan());
    println!("  Log Mode:  {}", format_log_mode(&final_log_mode).cyan());
    println!("  Contact DID: {}", exported_contact.contact_did.green());
    println!(
        "  Contact file: {}",
        exported_contact
            .contact_did_path
            .display()
            .to_string()
            .cyan()
    );
    println!("  Port:      {}", listen_port.to_string().cyan());
    println!(
        "  Data dir:  {}",
        agent_data_dir.display().to_string().dimmed()
    );

    // Show appropriate start command
    let transport_flag = match transport_mode {
        crate::config::TransportMode::Tcp => "",
        crate::config::TransportMode::Tor => " --transport tor",
        crate::config::TransportMode::Internet => " --transport internet",
    };

    let log_flag = if final_log_mode != "safe" {
        format!(" --log-mode {}", final_log_mode)
    } else {
        String::new()
    };

    println!(
        "\n  Start with: {} {} {} {}{}{}",
        "Qypha".bold(),
        "start".green(),
        "--config".dimmed(),
        config_filename.cyan(),
        transport_flag.green(),
        log_flag.green()
    );

    if matches!(transport_mode, crate::config::TransportMode::Tor) {
        println!("\n  {}", "Tor mode notes:".yellow().bold());
        println!("    - First startup takes 30-120s (Tor bootstrap)");
        println!("    - Use {} to generate invite code", "/invite".green());
        println!(
            "    - Use {} to connect to a peer",
            "/connect <code>".green()
        );
        println!(
            "    - Share {} for DID-first remote contact",
            "keys/contact_did.txt".green()
        );
        println!("    - No IP addresses are ever exposed");
    }

    if transport_mode == crate::config::TransportMode::Internet {
        println!("\n  {}", "Internet mode notes:".blue().bold());
        println!("    - Internet transport uses iroh with privacy-first routing");
        println!("    - Direct IP path is disabled by default to avoid peer IP exposure");
        println!("    - All application messages/files remain E2EE end-to-end");
        println!(
            "    - Use {} to generate invite code for remote peers",
            "/invite".green()
        );
        println!(
            "    - Use {} to connect to a peer",
            "/connect <code>".green()
        );
        println!(
            "    - DID-first remote contact uses {}",
            "/connect did:qypha:...".green()
        );
        println!("    - IP addresses stay hidden in UI/invites by default");
        println!("    - Enable direct only if both sides explicitly want speed over IP privacy");
        println!("    - Optional tuning: [network.iroh] in your .toml");
    }

    if final_log_mode == "safe" {
        println!("\n  {}", "SAFE mode hardening:".yellow().bold());
        println!("    - REPL command history disabled");
        println!("    - Known-peer pairing disabled by default; enable per peer");
        println!("    - One-time invite usage cache persisted to block replay");
        println!("    - Ratchet session persistence disabled");
        println!("    - Incoming files use configured receive path");
    }

    if final_log_mode == "ghost" {
        println!("\n  {}", "GHOST mode active:".red().bold());
        println!("    - Zero disk traces, zero memory traces");
        println!("    - Admin cannot read or override logs");
        println!("    - This mode is IMMUTABLE — cannot be changed after start");
        println!("    - Agent will leave no forensic evidence");
    }
    println!();

    Ok(())
}

pub(crate) fn export_contact_artifacts(
    keys_dir: &Path,
    agent_data_dir: &Path,
    keypair: &AgentKeyPair,
    config: &AppConfig,
    log_mode: &crate::control_plane::audit::LogMode,
) -> Result<ExportedContactArtifacts> {
    let (did_profile, contact_did) =
        build_contact_identity_artifacts(agent_data_dir, keypair, config, log_mode)?;
    let contact_did_path = keys_dir.join("contact_did.txt");
    write_private_file(&contact_did_path, contact_did.as_bytes())?;

    Ok(ExportedContactArtifacts {
        contact_did,
        contact_did_path,
        profile: did_profile,
    })
}

pub(crate) fn build_contact_identity_artifacts(
    agent_data_dir: &Path,
    keypair: &AgentKeyPair,
    config: &AppConfig,
    log_mode: &crate::control_plane::audit::LogMode,
) -> Result<(DidProfile, String)> {
    let iroh_contact_endpoint_addr_json = if matches!(
        config.network.transport_mode,
        crate::config::TransportMode::Internet
    ) {
        let endpoint_secret_bytes =
            crate::agent::daemon::iroh_identity::resolve_iroh_endpoint_secret_bytes(
                agent_data_dir,
                log_mode,
                &config.network.transport_mode,
                keypair,
            )?;
        crate::network::discovery::iroh::build_public_iroh_contact_endpoint_addr_json(
            &config.network.iroh,
            endpoint_secret_bytes,
        )?
    } else {
        None
    };

    let did_profile =
        crate::network::discovery::build_local_did_profile_with_iroh_contact_endpoint(
            keypair,
            config,
            None,
            iroh_contact_endpoint_addr_json.as_deref(),
        )?;
    let contact_did = encode_contact_did(&did_profile)?;
    Ok((did_profile, contact_did))
}

pub(crate) fn config_filename_for_agent(name: &str) -> String {
    format!("qypha_{}.toml", KeyStore::sanitize_agent_name(name))
}

pub(crate) fn legacy_config_path_for_agent(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(config_filename_for_agent(name))
}

pub(crate) fn legacy_agent_scoped_config_path_for_agent(name: &str) -> PathBuf {
    KeyStore::agent_data_path(name)
        .map(|root| root.join("config").join(config_filename_for_agent(name)))
        .unwrap_or_else(|_| {
            PathBuf::from(".qypha")
                .join("agents")
                .join(KeyStore::sanitize_agent_name(name))
                .join("config")
                .join(config_filename_for_agent(name))
        })
}

pub(crate) fn config_path_for_agent(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("agent-configs")
        .join(config_filename_for_agent(name))
}

fn move_or_copy_file(src: &Path, dst: &Path) -> Result<()> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::rename(src, dst) {
        Ok(_) => Ok(()),
        Err(_) => {
            std::fs::copy(src, dst).with_context(|| {
                format!(
                    "Failed to copy legacy config from {} to {}",
                    src.display(),
                    dst.display()
                )
            })?;
            std::fs::remove_file(src).with_context(|| {
                format!(
                    "Failed to remove legacy config after migration {}",
                    src.display()
                )
            })?;
            Ok(())
        }
    }
}

pub(crate) fn ensure_canonical_config_path_for_agent(name: &str) -> Result<PathBuf> {
    let canonical = config_path_for_agent(name);
    if canonical.exists() {
        return Ok(canonical);
    }

    let legacy_paths = [
        legacy_config_path_for_agent(name),
        legacy_agent_scoped_config_path_for_agent(name),
    ];
    for legacy in legacy_paths {
        if !legacy.exists() || legacy == canonical {
            continue;
        }
        move_or_copy_file(&legacy, &canonical)?;
        return Ok(canonical);
    }
    Ok(canonical)
}

pub(crate) fn resolve_existing_config_path_for_agent(name: &str) -> PathBuf {
    let canonical = config_path_for_agent(name);
    if canonical.exists() {
        return canonical;
    }
    let legacy = legacy_config_path_for_agent(name);
    if legacy.exists() {
        return legacy;
    }
    let legacy_agent_scoped = legacy_agent_scoped_config_path_for_agent(name);
    if legacy_agent_scoped.exists() {
        return legacy_agent_scoped;
    }
    canonical
}

pub(crate) fn build_persistent_agent_config(
    name: &str,
    role: &str,
    did: &str,
    transport_mode: TransportMode,
    log_mode: &str,
    listen_port: u16,
) -> AppConfig {
    let mut network_config = NetworkConfig::default();
    network_config.listen_port = listen_port;
    network_config.transport_mode = transport_mode.clone();

    if matches!(transport_mode, TransportMode::Tor) {
        network_config.enable_mdns = false;
    }
    if log_mode == "safe" {
        network_config.enable_mdns = false;
        network_config.enable_kademlia = false;
        if matches!(transport_mode, TransportMode::Internet) {
            network_config.hide_ip = true;
            network_config.iroh.relay_enabled = true;
            network_config.iroh.direct_enabled = false;
        }
    }

    let mut security_config = SecurityConfig::default();
    security_config.log_mode = log_mode.to_string();

    let mut logging_config = LoggingConfig::default();
    logging_config.mode = log_mode.to_string();

    AppConfig {
        agent: crate::config::AgentConfig {
            name: name.to_string(),
            role: role.to_string(),
            did: did.to_string(),
        },
        network: network_config,
        security: security_config,
        logging: logging_config,
        roles: crate::config::RolesConfig::default(),
        transfer: crate::config::TransferConfig::default(),
    }
}

pub(crate) fn sync_config_identity_fields(config: &mut AppConfig, keypair: &AgentKeyPair) -> bool {
    let mut changed = false;

    if config.agent.did != keypair.did {
        config.agent.did = keypair.did.clone();
        changed = true;
    }
    if config.agent.name != keypair.metadata.display_name {
        config.agent.name = keypair.metadata.display_name.clone();
        changed = true;
    }
    if config.agent.role != keypair.metadata.role {
        config.agent.role = keypair.metadata.role.clone();
        changed = true;
    }

    changed
}

pub(crate) fn persist_agent_config(
    name: &str,
    config: &AppConfig,
    passphrase: Option<&str>,
) -> Result<PathBuf> {
    let config_path = config_path_for_agent(name);
    write_config_to_path(&config_path, config, passphrase)?;
    Ok(config_path)
}

pub(crate) fn write_config_to_path(
    path: &Path,
    config: &AppConfig,
    passphrase: Option<&str>,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        harden_private_dir(parent)?;
    }
    let toml_str = config.to_toml_string_pretty_with_sensitive_encryption(passphrase)?;
    write_private_file(path, toml_str.as_bytes())?;
    Ok(())
}

/// Prompt user for a passphrase with confirmation.
fn prompt_passphrase() -> Result<String> {
    use dialoguer::Password;

    if let Ok(passphrase) = std::env::var("QYPHA_INIT_PASSPHRASE") {
        std::env::remove_var("QYPHA_INIT_PASSPHRASE");
        if passphrase.len() < MIN_SAFE_PASSPHRASE_LEN {
            anyhow::bail!(
                "Passphrase too short (minimum {} characters)",
                MIN_SAFE_PASSPHRASE_LEN
            );
        }
        return Ok(passphrase);
    }

    let passphrase = Password::new()
        .with_prompt("  Set a passphrase for key encryption (min 6 chars)")
        .with_confirmation(
            "  Confirm passphrase",
            "  Passphrases don't match, try again",
        )
        .interact()?;

    if passphrase.len() < MIN_SAFE_PASSPHRASE_LEN {
        anyhow::bail!(
            "Passphrase too short (minimum {} characters)",
            MIN_SAFE_PASSPHRASE_LEN
        );
    }

    Ok(passphrase)
}

fn format_transport(mode: &crate::config::TransportMode) -> &'static str {
    match mode {
        crate::config::TransportMode::Tcp => "LAN",
        crate::config::TransportMode::Tor => "Tor",
        crate::config::TransportMode::Internet => "Internet",
    }
}

fn format_log_mode(mode: &str) -> &'static str {
    match mode {
        "safe" => "SAFE (privacy-hardened, reduced persistence)",
        "ghost" => "GHOST (zero trace, immutable, unbreakable)",
        _ => "SAFE (default)",
    }
}
