use super::*;

use crate::crypto::at_rest::{
    derive_agent_scoped_persist_key, read_persisted_bytes, write_persisted_bytes,
};
use anyhow::Context;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

const SAFE_IROH_ENDPOINT_SECRET_STORE_KEY_SCOPE: &[u8] = b"safe-iroh-endpoint-store-key-v1";
const SAFE_IROH_ENDPOINT_SECRET_BLOB_SCOPE: &[u8] = b"safe-iroh-endpoint-secret-v1";
const SAFE_IROH_ENDPOINT_SECRET_FILENAME: &str = "iroh_endpoint_safe.bin";

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
enum PersistedIrohEndpointSecretSource {
    RandomIndependent,
    LegacySigningSeed,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PersistedIrohEndpointSecret {
    version: u8,
    source: PersistedIrohEndpointSecretSource,
    secret: [u8; 32],
}

pub(crate) fn resolve_iroh_endpoint_secret_bytes(
    agent_data_dir: &std::path::Path,
    log_mode: &LogMode,
    transport_mode: &TransportMode,
    keypair: &AgentKeyPair,
) -> Result<[u8; 32]> {
    if !matches!(transport_mode, TransportMode::Internet) || !matches!(log_mode, LogMode::Safe) {
        return Ok(keypair.signing_key.to_bytes());
    }

    load_or_create_safe_iroh_endpoint_secret(agent_data_dir, keypair)
}

fn load_or_create_safe_iroh_endpoint_secret(
    agent_data_dir: &std::path::Path,
    keypair: &AgentKeyPair,
) -> Result<[u8; 32]> {
    let path = agent_data_dir.join(SAFE_IROH_ENDPOINT_SECRET_FILENAME);
    let persist_key = zeroize::Zeroizing::new(derive_agent_scoped_persist_key(
        keypair,
        SAFE_IROH_ENDPOINT_SECRET_STORE_KEY_SCOPE,
    ));
    let continuity_required =
        has_existing_safe_iroh_peer_continuity_requirement(agent_data_dir, keypair);

    if let Some(mut plaintext) = match read_persisted_bytes(
        &path,
        Some(&*persist_key),
        SAFE_IROH_ENDPOINT_SECRET_BLOB_SCOPE,
    ) {
        Ok(plaintext) => plaintext,
        Err(error) => {
            recover_from_invalid_safe_iroh_endpoint_secret(&path, continuity_required, &error)?;
            None
        }
    } {
        let persisted: PersistedIrohEndpointSecret = match bincode::deserialize(&plaintext) {
            Ok(persisted) => persisted,
            Err(error) => {
                plaintext.zeroize();
                recover_from_invalid_safe_iroh_endpoint_secret(&path, continuity_required, &error)?;
                return provision_safe_iroh_endpoint_secret(
                    &path,
                    &persist_key,
                    keypair,
                    continuity_required,
                );
            }
        };
        plaintext.zeroize();
        if persisted.version != 1 {
            anyhow::bail!(
                "Unsupported Safe iroh endpoint identity version {} in {}",
                persisted.version,
                path.display()
            );
        }
        tracing::info!(
            path = %path.display(),
            source = ?persisted.source,
            "Loaded Safe iroh endpoint identity"
        );
        return Ok(persisted.secret);
    }

    provision_safe_iroh_endpoint_secret(&path, &persist_key, keypair, continuity_required)
}

fn provision_safe_iroh_endpoint_secret(
    path: &std::path::Path,
    persist_key: &[u8; 32],
    keypair: &AgentKeyPair,
    continuity_required: bool,
) -> Result<[u8; 32]> {
    let source = if continuity_required {
        PersistedIrohEndpointSecretSource::LegacySigningSeed
    } else {
        PersistedIrohEndpointSecretSource::RandomIndependent
    };
    let secret = match source {
        PersistedIrohEndpointSecretSource::RandomIndependent => rand::random::<[u8; 32]>(),
        PersistedIrohEndpointSecretSource::LegacySigningSeed => keypair.signing_key.to_bytes(),
    };
    let persisted = PersistedIrohEndpointSecret {
        version: 1,
        source,
        secret,
    };
    let mut plaintext =
        bincode::serialize(&persisted).context("Failed to encode Safe iroh endpoint identity")?;
    write_persisted_bytes(
        path,
        Some(persist_key),
        SAFE_IROH_ENDPOINT_SECRET_BLOB_SCOPE,
        &plaintext,
    )
    .with_context(|| {
        format!(
            "Failed to persist Safe iroh endpoint identity {}",
            path.display()
        )
    })?;
    plaintext.zeroize();

    match source {
        PersistedIrohEndpointSecretSource::RandomIndependent => tracing::info!(
            path = %path.display(),
            "Provisioned decoupled Safe iroh endpoint identity"
        ),
        PersistedIrohEndpointSecretSource::LegacySigningSeed => tracing::warn!(
            path = %path.display(),
            "Seeded Safe iroh endpoint identity from the legacy signing secret to preserve existing reconnect continuity"
        ),
    }

    Ok(secret)
}

fn recover_from_invalid_safe_iroh_endpoint_secret(
    path: &std::path::Path,
    continuity_required: bool,
    error: &dyn std::fmt::Display,
) -> Result<()> {
    quarantine_invalid_safe_iroh_endpoint_secret(path)?;
    if continuity_required {
        tracing::warn!(
            path = %path.display(),
            reason = %error,
            "Quarantined unreadable Safe iroh endpoint identity; falling back to a signing-seed endpoint identity for best-effort reconnect continuity"
        );
    } else {
        tracing::warn!(
            path = %path.display(),
            reason = %error,
            "Quarantined unreadable Safe iroh endpoint identity and provisioning a fresh decoupled one"
        );
    }
    Ok(())
}

fn has_existing_safe_iroh_peer_continuity_requirement(
    agent_data_dir: &std::path::Path,
    keypair: &AgentKeyPair,
) -> bool {
    let Some(peer_store_path) = peer_store::store_path_for_mode(agent_data_dir, "safe") else {
        return false;
    };
    if !peer_store_path.exists() {
        return false;
    }

    let peer_store_persist_key = zeroize::Zeroizing::new(derive_agent_scoped_persist_key(
        keypair,
        SAFE_PEER_STORE_PERSIST_KEY_SCOPE,
    ));
    let store = PeerStore::load_with_persist_key(
        Some(peer_store_path.as_path()),
        Some(*peer_store_persist_key),
    );
    store
        .all_peers()
        .into_iter()
        .any(|peer| peer.iroh_endpoint_addr.is_some())
}

fn quarantine_invalid_safe_iroh_endpoint_secret(path: &std::path::Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(SAFE_IROH_ENDPOINT_SECRET_FILENAME);
    let quarantine_path = path.with_file_name(format!("{file_name}.corrupt-{ts}"));
    std::fs::rename(path, &quarantine_path).with_context(|| {
        format!(
            "Failed to quarantine invalid Safe iroh endpoint identity {} -> {}",
            path.display(),
            quarantine_path.display()
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_safe_internet_peer() -> KnownPeer {
        KnownPeer {
            did: "did:nxf:peer".to_string(),
            name: "Peer".to_string(),
            role: "agent".to_string(),
            peer_id: "12D3KooWPeer".to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: Some(
                crate::network::discovery::iroh::sample_relay_only_iroh_endpoint_addr_json(71),
            ),
            onion_port: 9090,
            encryption_public_key_hex: None,
            verifying_key_hex: None,
            kyber_public_key_hex: None,
            last_seen: 1,
            auto_reconnect: true,
        }
    }

    #[test]
    fn fresh_safe_internet_identity_is_decoupled_and_stable() {
        let dir = tempfile::tempdir().unwrap();
        let keypair = AgentKeyPair::generate("Alice", "agent");

        let first = resolve_iroh_endpoint_secret_bytes(
            dir.path(),
            &LogMode::Safe,
            &TransportMode::Internet,
            &keypair,
        )
        .unwrap();
        let second = resolve_iroh_endpoint_secret_bytes(
            dir.path(),
            &LogMode::Safe,
            &TransportMode::Internet,
            &keypair,
        )
        .unwrap();

        assert_eq!(first, second);
        assert_ne!(first, keypair.signing_key.to_bytes());

        let on_disk = std::fs::read(dir.path().join(SAFE_IROH_ENDPOINT_SECRET_FILENAME)).unwrap();
        assert!(
            !on_disk.windows(first.len()).any(|window| window == first),
            "safe iroh endpoint secret should not be written to disk in plaintext"
        );
    }

    #[test]
    fn existing_safe_internet_peer_store_preserves_legacy_identity() {
        let dir = tempfile::tempdir().unwrap();
        let keypair = AgentKeyPair::generate("Bob", "agent");
        let peer_store_key =
            derive_agent_scoped_persist_key(&keypair, SAFE_PEER_STORE_PERSIST_KEY_SCOPE);
        let peer_store_path =
            peer_store::store_path_for_mode(dir.path(), "safe").expect("safe peer store path");
        let mut store = PeerStore::with_persist_key(Some(&peer_store_path), Some(peer_store_key));
        store.upsert(sample_safe_internet_peer());

        let secret = resolve_iroh_endpoint_secret_bytes(
            dir.path(),
            &LogMode::Safe,
            &TransportMode::Internet,
            &keypair,
        )
        .unwrap();

        assert_eq!(secret, keypair.signing_key.to_bytes());
    }

    #[test]
    fn tampered_safe_iroh_identity_without_existing_peers_is_reprovisioned() {
        let dir = tempfile::tempdir().unwrap();
        let keypair = AgentKeyPair::generate("Carol", "agent");
        let path = dir.path().join(SAFE_IROH_ENDPOINT_SECRET_FILENAME);

        let original = resolve_iroh_endpoint_secret_bytes(
            dir.path(),
            &LogMode::Safe,
            &TransportMode::Internet,
            &keypair,
        )
        .unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x55;
        std::fs::write(&path, bytes).unwrap();

        let reprovisioned = resolve_iroh_endpoint_secret_bytes(
            dir.path(),
            &LogMode::Safe,
            &TransportMode::Internet,
            &keypair,
        )
        .unwrap();
        assert_ne!(original, reprovisioned);
        assert!(dir
            .path()
            .read_dir()
            .unwrap()
            .filter_map(|entry| entry.ok())
            .any(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with("iroh_endpoint_safe.bin.corrupt-")));
    }

    #[test]
    fn tampered_safe_iroh_identity_with_existing_peers_falls_back_to_legacy_continuity_seed() {
        let dir = tempfile::tempdir().unwrap();
        let keypair = AgentKeyPair::generate("Dave", "agent");
        let peer_store_key =
            derive_agent_scoped_persist_key(&keypair, SAFE_PEER_STORE_PERSIST_KEY_SCOPE);
        let peer_store_path =
            peer_store::store_path_for_mode(dir.path(), "safe").expect("safe peer store path");
        let mut store = PeerStore::with_persist_key(Some(&peer_store_path), Some(peer_store_key));
        store.upsert(sample_safe_internet_peer());
        let path = dir.path().join(SAFE_IROH_ENDPOINT_SECRET_FILENAME);

        let _ = resolve_iroh_endpoint_secret_bytes(
            dir.path(),
            &LogMode::Safe,
            &TransportMode::Internet,
            &keypair,
        )
        .unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x33;
        std::fs::write(&path, bytes).unwrap();

        let recovered = resolve_iroh_endpoint_secret_bytes(
            dir.path(),
            &LogMode::Safe,
            &TransportMode::Internet,
            &keypair,
        )
        .unwrap();

        assert_eq!(recovered, keypair.signing_key.to_bytes());
        assert!(dir
            .path()
            .read_dir()
            .unwrap()
            .filter_map(|entry| entry.ok())
            .any(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with("iroh_endpoint_safe.bin.corrupt-")));
    }
}
