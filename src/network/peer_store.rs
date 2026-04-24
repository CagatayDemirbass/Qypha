//! Persistent known-peer storage for auto-reconnect.
//!
//! Saves peer connection info (DID, .onion address, TCP address, etc.) to disk
//! so agents can automatically reconnect to known peers after restart.
//!
//! **Respects log mode:**
//! - Safe → trusted direct peers are saved to a dedicated file and auto-reconnect
//!   stays enabled until the operator explicitly forgets them
//! - Ghost → nothing saved, no auto-reconnect
//!
//! Works across the supported transport modes (TCP, Tor, Internet).
//! Ghost mode agents leave zero forensic trace — no peer history on disk.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::crypto::at_rest::{read_persisted_bytes, write_persisted_bytes};
use crate::network::discovery::iroh::sanitize_relay_only_iroh_endpoint_addr_json;
use crate::os_adapter::secure_wipe::secure_wipe_file;

const PEER_STORE_PERSIST_SCOPE: &[u8] = b"peer-store-v1";

/// A known peer's connection info
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnownPeer {
    pub did: String,
    pub name: String,
    pub role: String,
    pub peer_id: String,
    /// .onion v3 address (56 chars, no ".onion" suffix)
    #[serde(default)]
    pub onion_address: Option<String>,
    /// TCP multiaddr for LAN mode
    #[serde(default)]
    pub tcp_address: Option<String>,
    /// Serialized iroh EndpointAddr (JSON string) for Internet mode reconnect
    #[serde(default)]
    pub iroh_endpoint_addr: Option<String>,
    /// Onion service port
    #[serde(default = "default_onion_port")]
    pub onion_port: u16,
    /// X25519 encryption public key (hex)
    #[serde(default)]
    pub encryption_public_key_hex: Option<String>,
    /// Ed25519 verifying key (hex) for pre-handshake reconnect auth.
    #[serde(default)]
    pub verifying_key_hex: Option<String>,
    /// Kyber-1024 post-quantum public key (hex)
    #[serde(default)]
    pub kyber_public_key_hex: Option<String>,
    /// Last successful connection (UNIX seconds)
    pub last_seen: u64,
    /// Whether this peer should be auto-reconnected on future launches.
    #[serde(default = "default_auto_reconnect")]
    pub auto_reconnect: bool,
}

fn default_onion_port() -> u16 {
    9090
}

fn default_auto_reconnect() -> bool {
    true
}

/// Persistent peer store — disabled only in Ghost mode.
pub struct PeerStore {
    peers: HashMap<String, KnownPeer>,
    /// None = zero-trace mode (ghost), no disk writes
    store_path: Option<PathBuf>,
    persist_key: Option<[u8; 32]>,
}

impl PeerStore {
    /// Create a new peer store.
    ///
    /// `store_path` = None means zero-trace (Ghost mode).
    /// No file is ever created or read.
    pub fn new(store_path: Option<&Path>) -> Self {
        Self::with_persist_key(store_path, None)
    }

    pub fn with_persist_key(store_path: Option<&Path>, persist_key: Option<[u8; 32]>) -> Self {
        Self {
            peers: HashMap::new(),
            store_path: store_path.map(|p| p.to_path_buf()),
            persist_key,
        }
    }

    /// Load existing known peers from disk.
    /// Returns empty store if file doesn't exist or mode is zero-trace.
    pub fn load(store_path: Option<&Path>) -> Self {
        Self::load_with_persist_key(store_path, None)
    }

    pub fn load_with_persist_key(store_path: Option<&Path>, persist_key: Option<[u8; 32]>) -> Self {
        let Some(path) = store_path else {
            return Self::new(None);
        };
        if let Some(legacy_path) = legacy_normal_store_path(path).filter(|legacy| legacy.exists()) {
            secure_wipe_file(&legacy_path);
        }

        match read_persisted_bytes(path, persist_key.as_ref(), PEER_STORE_PERSIST_SCOPE) {
            Ok(Some(bytes)) => match serde_json::from_slice::<StoredPeers>(&bytes) {
                Ok(stored) => {
                    let loaded_count = stored.peers.len();
                    let (peers, sanitized) = sanitize_loaded_peers(stored.peers);
                    tracing::info!(count = loaded_count, "Loaded known peers from disk");
                    let mut store = Self {
                        peers,
                        store_path: Some(path.to_path_buf()),
                        persist_key,
                    };
                    if sanitized {
                        tracing::info!(
                            "Sanitized stored known-peer reconnect routes to relay-only"
                        );
                        if let Err(e) = store.save() {
                            tracing::warn!("Failed to rewrite sanitized known peer store: {}", e);
                        }
                    }
                    store
                }
                Err(e) => {
                    tracing::warn!("Failed to parse known peer store: {}", e);
                    Self::with_persist_key(Some(path), persist_key)
                }
            },
            Ok(None) => Self::with_persist_key(Some(path), persist_key),
            Err(e) => {
                tracing::warn!("Failed to read known peer store: {}", e);
                Self::with_persist_key(Some(path), persist_key)
            }
        }
    }

    /// Add or update a known peer. Saves to disk if persistent mode.
    pub fn upsert(&mut self, peer: KnownPeer) {
        let peer = sanitize_known_peer(peer);
        self.peers.insert(peer.did.clone(), peer);
        if let Err(e) = self.save() {
            tracing::warn!("Failed to save known peers: {}", e);
        }
    }

    /// Remove a peer by DID.
    pub fn remove(&mut self, did: &str) {
        self.peers.remove(did);
        if let Err(e) = self.save() {
            tracing::warn!("Failed to save known peers after removal: {}", e);
        }
    }

    /// Get all known peers, including unpaired records.
    pub fn all_peers(&self) -> Vec<&KnownPeer> {
        self.peers.values().collect()
    }

    /// Get only peers that are explicitly paired for auto-reconnect.
    pub fn auto_reconnect_peers(&self) -> Vec<&KnownPeer> {
        self.peers
            .values()
            .filter(|peer| peer.auto_reconnect)
            .collect()
    }

    pub fn scrub_for_private_transport_mode(&mut self) -> usize {
        let mut changed = 0;
        for peer in self.peers.values_mut() {
            let mut sanitized = sanitize_known_peer(peer.clone());
            sanitized.tcp_address = None;
            if *peer != sanitized {
                *peer = sanitized;
                changed += 1;
            }
        }
        if changed > 0 {
            if let Err(error) = self.save() {
                tracing::warn!(%error, "Failed to persist scrubbed private-mode peer store");
            }
        }
        changed
    }

    /// Get a specific peer by DID.
    pub fn get(&self, did: &str) -> Option<&KnownPeer> {
        self.peers.get(did)
    }

    /// Number of known peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether persistent mode is active (disk writes enabled).
    pub fn is_persistent(&self) -> bool {
        self.store_path.is_some()
    }

    /// Save to disk (no-op if zero-trace mode).
    fn save(&self) -> Result<()> {
        let Some(ref path) = self.store_path else {
            return Ok(());
        };

        let stored = StoredPeers {
            peers: self.peers.clone(),
        };
        let json = serde_json::to_vec_pretty(&stored)?;
        write_persisted_bytes(
            path,
            self.persist_key.as_ref(),
            PEER_STORE_PERSIST_SCOPE,
            &json,
        )?;

        tracing::debug!(path = %path.display(), count = self.peers.len(), "Saved known peers");
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct StoredPeers {
    peers: HashMap<String, KnownPeer>,
}

pub fn sanitize_known_peer(mut peer: KnownPeer) -> KnownPeer {
    peer.iroh_endpoint_addr = peer
        .iroh_endpoint_addr
        .as_deref()
        .and_then(|json| sanitize_relay_only_iroh_endpoint_addr_json(json).ok());

    if peer.iroh_endpoint_addr.is_some() {
        peer.onion_address = None;
        peer.tcp_address = None;
    } else if peer.onion_address.is_some() {
        peer.tcp_address = None;
    }

    peer
}

fn sanitize_loaded_peers(peers: HashMap<String, KnownPeer>) -> (HashMap<String, KnownPeer>, bool) {
    let mut sanitized = false;
    let peers = peers
        .into_iter()
        .map(|(did, peer)| {
            let cleaned = sanitize_known_peer(peer.clone());
            if cleaned != peer {
                sanitized = true;
            }
            (did, cleaned)
        })
        .collect();
    (peers, sanitized)
}

/// Determine the store path based on log mode.
/// Returns None only for zero-trace mode (Ghost).
pub fn store_path_for_mode(agent_data_dir: &Path, log_mode: &str) -> Option<PathBuf> {
    match log_mode {
        "safe" => Some(agent_data_dir.join("known_peers_safe.json")),
        // Ghost (and unknown): no peer history persistence.
        _ => None,
    }
}

fn legacy_normal_store_path(path: &Path) -> Option<PathBuf> {
    let file_name = path.file_name()?.to_str()?;
    if file_name == "known_peers_safe.json" {
        Some(path.with_file_name("known_peers.json"))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_persistent_store_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known_peers.json");

        let mut store = PeerStore::new(Some(&path));
        store.upsert(KnownPeer {
            did: "did:nxf:alice".to_string(),
            name: "Alice".to_string(),
            role: "agent".to_string(),
            peer_id: "12D3KooWTest".to_string(),
            onion_address: Some("abcdef1234567890".to_string()),
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            encryption_public_key_hex: Some("aabb".to_string()),
            verifying_key_hex: Some("bbcc".to_string()),
            kyber_public_key_hex: None,
            last_seen: 1700000000,
            auto_reconnect: true,
        });

        assert_eq!(store.len(), 1);
        assert!(path.exists());

        // Load from disk
        let loaded = PeerStore::load(Some(&path));
        assert_eq!(loaded.len(), 1);
        let alice = loaded.get("did:nxf:alice").unwrap();
        assert_eq!(alice.name, "Alice");
        assert_eq!(alice.onion_address.as_deref(), Some("abcdef1234567890"));
        assert_eq!(alice.verifying_key_hex.as_deref(), Some("bbcc"));
    }

    #[test]
    fn test_ghost_store_writes_nothing() {
        let mut store = PeerStore::new(None);
        store.upsert(KnownPeer {
            did: "did:nxf:ghost".to_string(),
            name: "Ghost".to_string(),
            role: "agent".to_string(),
            peer_id: "12D3KooWGhost".to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            encryption_public_key_hex: None,
            verifying_key_hex: None,
            kyber_public_key_hex: None,
            last_seen: 1700000000,
            auto_reconnect: true,
        });

        // In-memory only — no file created
        assert_eq!(store.len(), 1);
        assert!(!store.is_persistent());
    }

    #[test]
    fn test_store_path_for_mode() {
        let dir = std::path::PathBuf::from("/tmp/test");
        assert_eq!(
            store_path_for_mode(&dir, "safe"),
            Some(dir.join("known_peers_safe.json"))
        );
        assert!(store_path_for_mode(&dir, "ghost").is_none());
    }

    #[test]
    fn test_safe_store_discards_legacy_normal_path() {
        let dir = tempdir().unwrap();
        let legacy_path = dir.path().join("known_peers.json");
        let safe_path = dir.path().join("known_peers_safe.json");

        let mut store = PeerStore::new(Some(&legacy_path));
        store.upsert(KnownPeer {
            did: "did:nxf:legacy".to_string(),
            name: "Legacy".to_string(),
            role: "agent".to_string(),
            peer_id: "12D3KooWLegacy".to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            encryption_public_key_hex: None,
            verifying_key_hex: None,
            kyber_public_key_hex: None,
            last_seen: 1700000000,
            auto_reconnect: true,
        });

        let loaded = PeerStore::load(Some(&safe_path));
        assert_eq!(loaded.len(), 0);
        assert!(!safe_path.exists());
        assert!(!legacy_path.exists());
    }

    #[test]
    fn test_upsert_updates_existing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known_peers.json");
        let mut store = PeerStore::new(Some(&path));

        store.upsert(KnownPeer {
            did: "did:nxf:bob".to_string(),
            name: "Bob".to_string(),
            role: "finance".to_string(),
            peer_id: "12D3KooWBob".to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            encryption_public_key_hex: None,
            verifying_key_hex: None,
            kyber_public_key_hex: None,
            last_seen: 1000,
            auto_reconnect: true,
        });

        // Update with new onion address
        store.upsert(KnownPeer {
            did: "did:nxf:bob".to_string(),
            name: "Bob".to_string(),
            role: "finance".to_string(),
            peer_id: "12D3KooWBob".to_string(),
            onion_address: Some("newonion123".to_string()),
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            encryption_public_key_hex: None,
            verifying_key_hex: None,
            kyber_public_key_hex: None,
            last_seen: 2000,
            auto_reconnect: true,
        });

        assert_eq!(store.len(), 1);
        let bob = store.get("did:nxf:bob").unwrap();
        assert_eq!(bob.onion_address.as_deref(), Some("newonion123"));
        assert_eq!(bob.last_seen, 2000);
    }

    #[test]
    fn test_remove_peer() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known_peers.json");
        let mut store = PeerStore::new(Some(&path));

        store.upsert(KnownPeer {
            did: "did:nxf:temp".to_string(),
            name: "Temp".to_string(),
            role: "agent".to_string(),
            peer_id: "12D3KooWTemp".to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            encryption_public_key_hex: None,
            verifying_key_hex: None,
            kyber_public_key_hex: None,
            last_seen: 1000,
            auto_reconnect: true,
        });

        assert_eq!(store.len(), 1);
        store.remove("did:nxf:temp");
        assert_eq!(store.len(), 0);

        // Verify disk is also updated
        let loaded = PeerStore::load(Some(&path));
        assert_eq!(loaded.len(), 0);
    }

    #[test]
    fn test_auto_reconnect_filter_only_returns_paired_peers() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known_peers.json");
        let mut store = PeerStore::new(Some(&path));

        store.upsert(KnownPeer {
            did: "did:nxf:paired".to_string(),
            name: "Paired".to_string(),
            role: "agent".to_string(),
            peer_id: "12D3KooWPaired".to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            encryption_public_key_hex: None,
            verifying_key_hex: None,
            kyber_public_key_hex: None,
            last_seen: 100,
            auto_reconnect: true,
        });
        store.upsert(KnownPeer {
            did: "did:nxf:manual".to_string(),
            name: "Manual".to_string(),
            role: "agent".to_string(),
            peer_id: "12D3KooWManual".to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: None,
            onion_port: 9090,
            encryption_public_key_hex: None,
            verifying_key_hex: None,
            kyber_public_key_hex: None,
            last_seen: 101,
            auto_reconnect: false,
        });

        let paired = store.auto_reconnect_peers();
        assert_eq!(paired.len(), 1);
        assert_eq!(paired[0].did, "did:nxf:paired");
    }

    #[test]
    fn test_safe_store_roundtrip_uses_encrypted_blob() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known_peers_safe.json");
        let persist_key = [42u8; 32];
        let mut store = PeerStore::with_persist_key(Some(&path), Some(persist_key));

        store.upsert(KnownPeer {
            did: "did:nxf:safe".to_string(),
            name: "Safe".to_string(),
            role: "agent".to_string(),
            peer_id: "12D3KooWSafe".to_string(),
            onion_address: None,
            tcp_address: None,
            iroh_endpoint_addr: Some(
                crate::network::discovery::iroh::sample_relay_only_iroh_endpoint_addr_json(5),
            ),
            onion_port: 9090,
            encryption_public_key_hex: None,
            verifying_key_hex: None,
            kyber_public_key_hex: None,
            last_seen: 1700000001,
            auto_reconnect: true,
        });

        let on_disk = std::fs::read(&path).unwrap();
        assert!(
            !std::str::from_utf8(&on_disk)
                .unwrap_or_default()
                .contains("did:nxf:safe"),
            "safe peer store should not leak plaintext DIDs to disk"
        );

        let loaded = PeerStore::load_with_persist_key(Some(&path), Some(persist_key));
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.get("did:nxf:safe").unwrap().name, "Safe");
    }

    #[test]
    fn test_safe_store_loads_legacy_plaintext_json() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known_peers_safe.json");
        let legacy = serde_json::to_vec_pretty(&StoredPeers {
            peers: HashMap::from([(
                "did:nxf:legacy".to_string(),
                KnownPeer {
                    did: "did:nxf:legacy".to_string(),
                    name: "Legacy".to_string(),
                    role: "agent".to_string(),
                    peer_id: "12D3KooWLegacy".to_string(),
                    onion_address: None,
                    tcp_address: None,
                    iroh_endpoint_addr: None,
                    onion_port: 9090,
                    encryption_public_key_hex: None,
                    verifying_key_hex: None,
                    kyber_public_key_hex: None,
                    last_seen: 1,
                    auto_reconnect: true,
                },
            )]),
        })
        .unwrap();
        std::fs::write(&path, legacy).unwrap();

        let loaded = PeerStore::load_with_persist_key(Some(&path), Some([11u8; 32]));
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.get("did:nxf:legacy").unwrap().name, "Legacy");
    }

    #[test]
    fn test_upsert_sanitizes_iroh_and_drops_fallback_routes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known_peers_safe.json");
        let mut store = PeerStore::with_persist_key(Some(&path), Some([22u8; 32]));
        let endpoint_id = iroh::SecretKey::from_bytes(&[21u8; 32]).public();
        let endpoint_addr = iroh::EndpointAddr::from_parts(
            endpoint_id,
            [
                iroh::TransportAddr::Ip(std::net::SocketAddr::from(([127, 0, 0, 1], 7777))),
                iroh::TransportAddr::Relay(
                    "https://relay.example.test"
                        .parse::<iroh::RelayUrl>()
                        .unwrap(),
                ),
            ],
        );
        let endpoint_json = serde_json::to_string(&endpoint_addr).unwrap();

        store.upsert(KnownPeer {
            did: "did:nxf:relay-only".to_string(),
            name: "Relay Only".to_string(),
            role: "agent".to_string(),
            peer_id: "12D3KooWRelay".to_string(),
            onion_address: Some(
                "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx".to_string(),
            ),
            tcp_address: Some("/ip4/127.0.0.1/tcp/9000".to_string()),
            iroh_endpoint_addr: Some(endpoint_json),
            onion_port: 9090,
            encryption_public_key_hex: None,
            verifying_key_hex: None,
            kyber_public_key_hex: None,
            last_seen: 1,
            auto_reconnect: true,
        });

        let stored = store.get("did:nxf:relay-only").unwrap();
        assert!(stored.onion_address.is_none());
        assert!(stored.tcp_address.is_none());
        let parsed = serde_json::from_str::<iroh::EndpointAddr>(
            stored.iroh_endpoint_addr.as_deref().unwrap(),
        )
        .unwrap();
        assert_eq!(parsed.ip_addrs().count(), 0);
        assert_eq!(parsed.relay_urls().count(), 1);
    }

    #[test]
    fn test_private_transport_scrub_drops_legacy_tcp_routes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known_peers_safe.json");
        let mut store = PeerStore::with_persist_key(Some(&path), Some([31u8; 32]));

        store.upsert(KnownPeer {
            did: "did:nxf:tcp-only".to_string(),
            name: "Tcp Only".to_string(),
            role: "agent".to_string(),
            peer_id: "12D3KooWTcpOnly".to_string(),
            onion_address: None,
            tcp_address: Some("/ip4/198.51.100.10/tcp/9000".to_string()),
            iroh_endpoint_addr: None,
            onion_port: 9090,
            encryption_public_key_hex: None,
            verifying_key_hex: None,
            kyber_public_key_hex: None,
            last_seen: 1,
            auto_reconnect: true,
        });

        assert_eq!(store.scrub_for_private_transport_mode(), 1);
        let stored = store.get("did:nxf:tcp-only").unwrap();
        assert!(stored.tcp_address.is_none());
        assert!(stored.iroh_endpoint_addr.is_none());
    }

    #[test]
    fn test_load_sanitizes_legacy_ip_bearing_reconnect_route() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("known_peers_safe.json");
        let endpoint_id = iroh::SecretKey::from_bytes(&[23u8; 32]).public();
        let endpoint_addr = iroh::EndpointAddr::from_parts(
            endpoint_id,
            [
                iroh::TransportAddr::Ip(std::net::SocketAddr::from(([127, 0, 0, 1], 8888))),
                iroh::TransportAddr::Relay(
                    "https://relay.example.test"
                        .parse::<iroh::RelayUrl>()
                        .unwrap(),
                ),
            ],
        );
        let endpoint_json = serde_json::to_string(&endpoint_addr).unwrap();
        let legacy = serde_json::to_vec_pretty(&StoredPeers {
            peers: HashMap::from([(
                "did:nxf:legacy-relay".to_string(),
                KnownPeer {
                    did: "did:nxf:legacy-relay".to_string(),
                    name: "Legacy Relay".to_string(),
                    role: "agent".to_string(),
                    peer_id: "12D3KooWLegacyRelay".to_string(),
                    onion_address: None,
                    tcp_address: Some("/ip4/127.0.0.1/tcp/9000".to_string()),
                    iroh_endpoint_addr: Some(endpoint_json),
                    onion_port: 9090,
                    encryption_public_key_hex: None,
                    verifying_key_hex: None,
                    kyber_public_key_hex: None,
                    last_seen: 1,
                    auto_reconnect: true,
                },
            )]),
        })
        .unwrap();
        std::fs::write(&path, legacy).unwrap();

        let loaded = PeerStore::load_with_persist_key(Some(&path), Some([24u8; 32]));
        let stored = loaded.get("did:nxf:legacy-relay").unwrap();
        assert!(stored.tcp_address.is_none());
        let parsed = serde_json::from_str::<iroh::EndpointAddr>(
            stored.iroh_endpoint_addr.as_deref().unwrap(),
        )
        .unwrap();
        assert_eq!(parsed.ip_addrs().count(), 0);
        assert_eq!(parsed.relay_urls().count(), 1);
    }
}
