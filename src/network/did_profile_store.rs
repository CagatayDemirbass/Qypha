use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::crypto::identity::is_valid_did;
use crate::crypto::keystore::{harden_private_dir, write_private_file};

use super::did_profile::DidProfile;

#[derive(Debug, Clone)]
pub struct DidProfileStore {
    dir: PathBuf,
}

impl DidProfileStore {
    pub fn open(base_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(base_dir).with_context(|| {
            format!("Failed to create DID profile store {}", base_dir.display())
        })?;
        harden_private_dir(base_dir)?;
        Ok(Self {
            dir: base_dir.to_path_buf(),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn import_verified(&self, profile: &DidProfile) -> Result<PathBuf> {
        validate_did(profile.did.as_str())?;
        if !profile.verify()? {
            anyhow::bail!("Refusing to import DID profile with invalid signature");
        }

        let path = self.path_for_did(&profile.did);
        let encoded =
            serde_json::to_vec_pretty(profile).context("Failed to encode DID profile for store")?;
        write_private_file(&path, &encoded)?;
        Ok(path)
    }

    pub fn load_verified(&self, did: &str) -> Result<Option<DidProfile>> {
        validate_did(did)?;
        let path = self.path_for_did(did);
        if !path.exists() {
            return Ok(None);
        }

        let bytes = std::fs::read(&path)
            .with_context(|| format!("Failed to read DID profile {}", path.display()))?;
        let profile: DidProfile = serde_json::from_slice(&bytes)
            .with_context(|| format!("Invalid DID profile JSON {}", path.display()))?;
        validate_did(profile.did.as_str())?;
        if profile.did != did {
            anyhow::bail!(
                "Stored DID profile path mismatch: expected '{}', found '{}'",
                did,
                profile.did
            );
        }
        if !profile.verify()? {
            anyhow::bail!("Stored DID profile signature is invalid for '{}'", did);
        }
        Ok(Some(profile))
    }

    fn path_for_did(&self, did: &str) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(b"QYPHA_DID_PROFILE_STORE_V1:");
        hasher.update(did.as_bytes());
        let digest = hex::encode(hasher.finalize());
        self.dir.join(format!("{digest}.json"))
    }
}

fn validate_did(did: &str) -> Result<()> {
    if !is_valid_did(did) {
        anyhow::bail!("Invalid DID format: '{did}'");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::AgentKeyPair;
    use crate::network::did_profile::{DidContactService, DidProfile};
    use ed25519_dalek::Signer;

    #[test]
    fn did_profile_store_roundtrip_verifies_profile() {
        let temp = tempfile::tempdir().unwrap();
        let store = DidProfileStore::open(temp.path()).unwrap();
        let keypair = AgentKeyPair::generate("StoreOwner", "agent");
        let profile = DidProfile::generate(
            &keypair,
            vec![DidContactService::IrohRelay {
                relay_urls: vec!["https://relay.example.com".to_string()],
                mailbox_topic: "did-contact:test".to_string(),
                endpoint_addr_json: None,
            }],
            None,
        );

        let stored_path = store.import_verified(&profile).unwrap();
        assert!(stored_path.exists());

        let loaded = store.load_verified(&profile.did).unwrap().unwrap();
        assert_eq!(loaded, profile);
    }

    #[test]
    fn did_profile_store_rejects_invalid_profile() {
        let temp = tempfile::tempdir().unwrap();
        let store = DidProfileStore::open(temp.path()).unwrap();
        let keypair = AgentKeyPair::generate("StoreOwner", "agent");
        let mut profile = DidProfile::generate(&keypair, Vec::new(), None);
        profile.did =
            "did:nxf:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();

        assert!(store.import_verified(&profile).is_err());
    }

    #[test]
    fn did_profile_store_rejects_invalid_did_format_on_import() {
        let temp = tempfile::tempdir().unwrap();
        let store = DidProfileStore::open(temp.path()).unwrap();
        let keypair = AgentKeyPair::generate("StoreOwner", "agent");
        let mut profile = DidProfile::generate(&keypair, Vec::new(), None);
        profile.did = "not-a-did".to_string();
        profile.signature = keypair
            .signing_key
            .sign(&serde_json::to_vec(&profile).unwrap())
            .to_vec();

        let error = store.import_verified(&profile).unwrap_err().to_string();
        assert!(error.contains("Invalid DID format"));
    }

    #[test]
    fn did_profile_store_rejects_invalid_did_lookup() {
        let temp = tempfile::tempdir().unwrap();
        let store = DidProfileStore::open(temp.path()).unwrap();

        let error = store.load_verified("not-a-did").unwrap_err().to_string();
        assert!(error.contains("Invalid DID format"));
    }
}
