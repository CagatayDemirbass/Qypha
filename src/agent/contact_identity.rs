use std::path::{Path, PathBuf};

use crate::crypto::keystore::KeyStore;
use crate::network::contact_did::{
    contact_did_from_canonical_did, contact_did_from_verifying_key_bytes, encode_contact_did,
    is_contact_did,
};
use crate::network::did_profile_store::DidProfileStore;
use crate::os_adapter::home::preferred_user_home_dir;

const DID_PROFILE_CACHE_DIR: &str = "did-profiles";

fn normalized_canonical_did_for_display(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let fingerprint = trimmed.strip_prefix("did:nxf:")?;
    let normalized_fingerprint = fingerprint.trim().to_ascii_lowercase();
    let is_hex = normalized_fingerprint
        .as_bytes()
        .iter()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
    (normalized_fingerprint.len() == 64 && is_hex)
        .then(|| format!("did:nxf:{normalized_fingerprint}"))
}

fn read_contact_did_file(path: &Path) -> Option<String> {
    let value = std::fs::read_to_string(path).ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() || !is_contact_did(trimmed) {
        return None;
    }
    Some(trimmed.to_string())
}

pub(crate) fn default_contact_did_path() -> Option<PathBuf> {
    preferred_user_home_dir().map(|home| home.join(".qypha").join("keys").join("contact_did.txt"))
}

pub(crate) fn read_default_contact_did() -> Option<String> {
    read_contact_did_file(&default_contact_did_path()?)
}

pub(crate) fn agent_contact_did_path(agent_name: &str) -> Option<PathBuf> {
    let agent_root = KeyStore::agent_data_path(agent_name).ok()?;
    Some(agent_root.join("keys").join("contact_did.txt"))
}

pub(crate) fn read_agent_contact_did(agent_name: &str) -> Option<String> {
    read_contact_did_file(&agent_contact_did_path(agent_name)?)
}

pub(crate) fn cached_peer_contact_did(
    agent_data_dir: &Path,
    canonical_did: &str,
) -> Option<String> {
    let canonical_did = normalized_canonical_did_for_display(canonical_did)
        .unwrap_or_else(|| canonical_did.trim().to_string());
    let store = DidProfileStore::open(&agent_data_dir.join(DID_PROFILE_CACHE_DIR)).ok()?;
    let profile = store.load_verified(&canonical_did).ok()??;
    encode_contact_did(&profile).ok()
}

pub(crate) fn displayed_did(value: &str) -> String {
    let trimmed = value.trim();
    if is_contact_did(trimmed) {
        return trimmed.to_string();
    }
    if let Some(normalized) = normalized_canonical_did_for_display(trimmed) {
        return contact_did_from_canonical_did(&normalized).unwrap_or_else(|_| trimmed.to_string());
    }
    trimmed.to_string()
}

pub(crate) fn displayed_peer_contact_did(
    agent_data_dir: &Path,
    canonical_did: &str,
    verifying_key: Option<[u8; 32]>,
) -> Option<String> {
    cached_peer_contact_did(agent_data_dir, canonical_did)
        .or_else(|| verifying_key.map(contact_did_from_verifying_key_bytes))
        .or_else(|| Some(displayed_did(canonical_did)))
}

pub(crate) fn displayed_known_peer_contact_did(
    agent_data_dir: &Path,
    canonical_did: &str,
) -> String {
    cached_peer_contact_did(agent_data_dir, canonical_did)
        .unwrap_or_else(|| displayed_did(canonical_did))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displayed_known_peer_contact_did_falls_back_to_contact_encoding() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let canonical = "did:nxf:4d637eed734f0621d4a059d3fb4166a073148dac4f2ba99b94e5adf905fd0c02";

        let displayed = displayed_known_peer_contact_did(tmp.path(), canonical);

        assert_eq!(
            displayed,
            contact_did_from_canonical_did(canonical).expect("canonical DID should convert")
        );
    }

    #[test]
    fn displayed_did_normalizes_trimmed_uppercase_canonical_did() {
        let canonical =
            "  did:nxf:4D637EED734F0621D4A059D3FB4166A073148DAC4F2BA99B94E5ADF905FD0C02  ";

        let displayed = displayed_did(canonical);

        assert_eq!(
            displayed,
            contact_did_from_canonical_did(
                "did:nxf:4d637eed734f0621d4a059d3fb4166a073148dac4f2ba99b94e5adf905fd0c02"
            )
            .expect("canonical DID should convert")
        );
    }
}
