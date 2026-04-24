use anyhow::Result;
use colored::Colorize;

pub async fn show_status() -> Result<()> {
    // Try to load agent identity
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    let id_path = std::path::Path::new(&home)
        .join(".qypha")
        .join("keys")
        .join("public_identity.json");
    let contact_did_path = crate::agent::contact_identity::default_contact_did_path();
    let contact_did = crate::agent::contact_identity::read_default_contact_did();

    if id_path.exists() {
        let json = std::fs::read_to_string(&id_path)?;
        let identity: crate::crypto::identity::AgentPublicIdentity = serde_json::from_str(&json)?;

        println!("\n{}", "═══ Agent Status ═══".cyan().bold());
        if let Some(contact_did) = contact_did {
            println!("  Contact DID: {}", contact_did.green());
        } else {
            println!("  Contact DID: {}", "not exported yet".yellow());
        }
        if let Some(contact_did_path) = contact_did_path.filter(|path| path.exists()) {
            println!(
                "  Contact file: {}",
                contact_did_path.display().to_string().cyan()
            );
        }
        println!("  Name:     {}", identity.metadata.display_name);
        println!("  Key:      {}...", &identity.public_key_hex[..16].dimmed());
        println!("  Status:   {}", "Initialized (not running)".yellow());
    } else {
        println!("\n{}", "Agent not initialized.".red());
        println!("Run: {} {} --name <name>", "qypha".bold(), "init".green());
    }

    Ok(())
}
