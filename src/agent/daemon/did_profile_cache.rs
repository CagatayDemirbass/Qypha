use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::crypto::identity::is_valid_did;
use crate::network::did_profile::{DidContactService, DidProfile};
use crate::network::did_profile_store::DidProfileStore;

const DID_PROFILE_CACHE_DIR: &str = "did-profiles";

pub(crate) fn did_profile_store(agent_data_dir: &Path) -> Result<DidProfileStore> {
    DidProfileStore::open(&agent_data_dir.join(DID_PROFILE_CACHE_DIR))
}

pub(crate) fn import_verified_did_profile(
    agent_data_dir: &Path,
    profile: &DidProfile,
) -> Result<PathBuf> {
    validate_did(profile.did.as_str())?;
    did_profile_store(agent_data_dir)?.import_verified(profile)
}

pub(crate) fn summarize_contact_services(profile: &DidProfile) -> String {
    let mut labels = profile
        .services
        .iter()
        .map(|service| match service {
            DidContactService::IrohRelay { .. } => "iroh relay contact",
            DidContactService::TorMailbox { .. } => "Tor mailbox contact",
            DidContactService::TorDirect { .. } => "Tor direct contact",
        })
        .collect::<Vec<_>>();
    labels.sort_unstable();
    labels.dedup();
    if labels.is_empty() {
        "no public contact services".to_string()
    } else {
        labels.join(", ")
    }
}

fn validate_did(did: &str) -> Result<()> {
    if !is_valid_did(did) {
        anyhow::bail!("Invalid DID format: '{did}'");
    }
    Ok(())
}
