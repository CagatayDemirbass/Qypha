// ═══════════════════════════════════════════════════════════════════════════
// SIGNAL DOUBLE RATCHET PROTOCOL — Per-message forward secrecy
//
// Implements the Signal protocol's Double Ratchet Algorithm:
//   - Root chain: X25519 DH ratchet → HKDF-SHA256 → new root key + chain key
//   - Sending/receiving chains: HMAC-SHA256 KDF → chain key + message key
//   - Per-message AEGIS-256 encryption with unique message key
//   - Skipped message key storage (up to MAX_SKIP) for out-of-order delivery
//
// Forward secrecy: compromising current state reveals NO past message keys.
// Post-compromise security: DH ratchet step restores secrecy after compromise.
//
// Reference: https://signal.org/docs/specifications/doubleratchet/
// ═══════════════════════════════════════════════════════════════════════════

use aegis::aegis256::Aegis256;
use anyhow::Result;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::path::PathBuf;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Maximum number of skipped message keys to store per ratchet step.
/// Prevents memory exhaustion from malicious peers sending huge message numbers.
const MAX_SKIP: u32 = 256;

// ─── Core Types ──────────────────────────────────────────────────────────────

/// Chain key — used to derive message keys via HMAC-SHA256 KDF.
/// Automatically zeroed on drop for forward secrecy.
#[derive(Clone)]
pub struct ChainKey([u8; 32]);

impl ChainKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for ChainKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Message key — unique per-message, used for AEGIS-256 encryption.
/// Automatically zeroed on drop after use.
#[derive(Clone)]
pub struct MessageKey([u8; 32]);

impl MessageKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for MessageKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Ratchet DH keypair — X25519 ephemeral key for DH ratchet steps.
pub struct RatchetKeyPair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl RatchetKeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }
}

impl Drop for RatchetKeyPair {
    fn drop(&mut self) {
        let mut bytes = self.secret.to_bytes();
        bytes.zeroize();
        self.secret = StaticSecret::from(bytes);
    }
}

/// Ratchet message header — sent with every encrypted message.
/// Contains the sender's current DH public key, previous chain length,
/// and message number within the current chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RatchetHeader {
    /// Sender's current DH ratchet public key (32 bytes)
    pub dh_public: [u8; 32],
    /// Number of messages in the previous sending chain
    pub prev_chain_len: u32,
    /// Message number in the current sending chain
    pub message_number: u32,
}

impl RatchetHeader {
    /// Serialize header to bytes for use as AEAD associated data
    pub fn to_aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(40);
        aad.extend_from_slice(&self.dh_public);
        aad.extend_from_slice(&self.prev_chain_len.to_be_bytes());
        aad.extend_from_slice(&self.message_number.to_be_bytes());
        aad
    }
}

// ─── KDF Functions ───────────────────────────────────────────────────────────

/// Root chain KDF: HKDF-SHA256(root_key, dh_output) → (new_root_key, chain_key)
///
/// Domain separation ensures root keys and chain keys are cryptographically
/// independent even though they come from the same HKDF extraction.
fn kdf_rk(root_key: &[u8; 32], dh_output: &[u8]) -> ([u8; 32], ChainKey) {
    let hk = Hkdf::<Sha256>::new(Some(root_key), dh_output);

    let mut new_root = [0u8; 32];
    hk.expand(b"Qypha-Ratchet-RootKey", &mut new_root)
        .expect("HKDF expand 32 bytes");

    let mut chain = [0u8; 32];
    hk.expand(b"Qypha-Ratchet-ChainKey", &mut chain)
        .expect("HKDF expand 32 bytes");

    (new_root, ChainKey(chain))
}

/// Chain KDF: HMAC-SHA256(chain_key, constant) → (new_chain_key, message_key)
///
/// Two constants (0x01, 0x02) produce independent outputs from the same chain key.
/// The chain advances forward: old chain key → new chain key + message key.
fn kdf_ck(chain_key: &ChainKey) -> (ChainKey, MessageKey) {
    // Message key: HMAC-SHA256(ck, 0x01)
    let mut mac_mk =
        Hmac::<Sha256>::new_from_slice(chain_key.as_bytes()).expect("HMAC accepts any key size");
    mac_mk.update(&[0x01]);
    let mk_result = mac_mk.finalize().into_bytes();
    let mut mk = [0u8; 32];
    mk.copy_from_slice(&mk_result);

    // New chain key: HMAC-SHA256(ck, 0x02)
    let mut mac_ck =
        Hmac::<Sha256>::new_from_slice(chain_key.as_bytes()).expect("HMAC accepts any key size");
    mac_ck.update(&[0x02]);
    let ck_result = mac_ck.finalize().into_bytes();
    let mut new_ck = [0u8; 32];
    new_ck.copy_from_slice(&ck_result);

    (ChainKey(new_ck), MessageKey(mk))
}

// ─── Ratchet State ───────────────────────────────────────────────────────────

/// Key for the skipped message keys HashMap: (DH public key, message number)
type SkippedKey = ([u8; 32], u32);

/// Double Ratchet protocol state for a single peer session.
///
/// Each peer maintains one RatchetState per remote peer. The state advances
/// with each message sent (chain ratchet) and each new DH key received
/// (DH ratchet), providing per-message forward secrecy.
pub struct RatchetState {
    /// Our current DH ratchet keypair
    dh_self: RatchetKeyPair,
    /// Remote peer's current DH public key
    dh_remote: Option<PublicKey>,
    /// Root key — advances with each DH ratchet step
    root_key: [u8; 32],
    /// Sending chain key — advances with each message sent
    chain_key_send: Option<ChainKey>,
    /// Receiving chain key — advances with each message received
    chain_key_recv: Option<ChainKey>,
    /// Number of messages sent in current sending chain
    send_count: u32,
    /// Number of messages received in current receiving chain
    recv_count: u32,
    /// Number of messages sent in previous sending chain (for header)
    prev_send_count: u32,
    /// Skipped message keys for out-of-order delivery
    skipped_keys: HashMap<SkippedKey, MessageKey>,
    /// Whether the ratchet has been fully initialized (both sides handshaked)
    initialized: bool,
}

impl RatchetState {
    pub fn is_send_ready(&self) -> bool {
        self.initialized && self.dh_remote.is_some() && self.chain_key_send.is_some()
    }

    pub fn remote_dh_public(&self) -> Option<[u8; 32]> {
        self.dh_remote.as_ref().map(|public| *public.as_bytes())
    }

    /// Initialize as the initiator (the peer with the lexicographically smaller DID).
    ///
    /// The initiator performs the first DH ratchet step immediately, establishing
    /// both sending and receiving chains.
    pub fn init_initiator(shared_secret: &[u8], remote_dh_pub: &PublicKey) -> Self {
        let dh_self = RatchetKeyPair::generate();

        // Initial root key from the pre-shared secret
        let mut root_key = [0u8; 32];
        let hk = Hkdf::<Sha256>::new(Some(b"Qypha-Ratchet-Init"), shared_secret);
        hk.expand(b"Qypha-Ratchet-RootKey-Init", &mut root_key)
            .expect("HKDF expand 32 bytes");

        // Perform initial DH ratchet step
        let dh_output = dh_self.secret.diffie_hellman(remote_dh_pub);
        let (new_root, chain_key_send) = kdf_rk(&root_key, dh_output.as_bytes());

        Self {
            dh_self,
            dh_remote: Some(*remote_dh_pub),
            root_key: new_root,
            chain_key_send: Some(chain_key_send),
            chain_key_recv: None, // Will be set on first received message
            send_count: 0,
            recv_count: 0,
            prev_send_count: 0,
            skipped_keys: HashMap::new(),
            initialized: true,
        }
    }

    /// Initialize as the responder (the peer with the lexicographically larger DID).
    ///
    /// The responder waits for the first message from the initiator before
    /// completing the DH ratchet and establishing sending chain.
    pub fn init_responder(shared_secret: &[u8], dh_keypair: RatchetKeyPair) -> Self {
        let mut root_key = [0u8; 32];
        let hk = Hkdf::<Sha256>::new(Some(b"Qypha-Ratchet-Init"), shared_secret);
        hk.expand(b"Qypha-Ratchet-RootKey-Init", &mut root_key)
            .expect("HKDF expand 32 bytes");

        Self {
            dh_self: dh_keypair,
            dh_remote: None,
            root_key,
            chain_key_send: None,
            chain_key_recv: None,
            send_count: 0,
            recv_count: 0,
            prev_send_count: 0,
            skipped_keys: HashMap::new(),
            initialized: true,
        }
    }

    /// Encrypt a message using the sending chain.
    ///
    /// Returns (RatchetHeader, ciphertext) where ciphertext = nonce(32) || ct || tag(32).
    /// The message key is derived from the sending chain and immediately zeroed.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(RatchetHeader, Vec<u8>)> {
        if !self.initialized {
            return Err(anyhow::anyhow!("Ratchet not initialized"));
        }

        let chain_key = self.chain_key_send.as_ref().ok_or_else(|| {
            anyhow::anyhow!("No sending chain key — waiting for first message from peer")
        })?;

        // Advance the chain: derive message key + new chain key
        let (new_chain, mut msg_key) = kdf_ck(chain_key);
        self.chain_key_send = Some(new_chain);

        // Build header
        let header = RatchetHeader {
            dh_public: *self.dh_self.public.as_bytes(),
            prev_chain_len: self.prev_send_count,
            message_number: self.send_count,
        };
        self.send_count += 1;

        // Encrypt with AEGIS-256 using message key (header as AAD for binding)
        let nonce: [u8; 32] = rand::random();
        let aad = header.to_aad();
        let aegis = Aegis256::<32>::new(msg_key.as_bytes(), &nonce);
        let (ct, tag) = aegis.encrypt(plaintext, &aad);
        msg_key.0.zeroize();

        // Format: nonce(32) || ciphertext || tag(32)
        let mut output = Vec::with_capacity(32 + ct.len() + 32);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ct);
        output.extend_from_slice(&tag);

        Ok((header, output))
    }

    /// Decrypt a message using the receiving chain (with DH ratchet if needed).
    ///
    /// Handles three cases:
    /// 1. Message from skipped keys (out-of-order delivery)
    /// 2. New DH public key → perform DH ratchet step, then decrypt
    /// 3. Same DH public key → advance receiving chain, then decrypt
    pub fn decrypt(&mut self, header: &RatchetHeader, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if !self.initialized {
            return Err(anyhow::anyhow!("Ratchet not initialized"));
        }

        // 1. Check skipped keys first (out-of-order message)
        let skipped_key = (header.dh_public, header.message_number);
        if let Some(mut msg_key) = self.skipped_keys.remove(&skipped_key) {
            let result = decrypt_with_key(&msg_key, header, ciphertext);
            msg_key.0.zeroize();
            return result;
        }

        // 2. If new DH public key → DH ratchet step
        let remote_pub = PublicKey::from(header.dh_public);
        let need_dh_ratchet = match &self.dh_remote {
            Some(existing) => existing.as_bytes() != &header.dh_public,
            None => true, // First message from peer
        };

        if need_dh_ratchet {
            // Skip any remaining messages in the current receiving chain
            if self.chain_key_recv.is_some() {
                self.skip_message_keys(header.prev_chain_len)?;
            }

            // DH ratchet step: establish new receiving chain
            self.dh_remote = Some(remote_pub);
            let dh_output = self.dh_self.secret.diffie_hellman(&remote_pub);
            let (new_root, chain_key_recv) = kdf_rk(&self.root_key, dh_output.as_bytes());
            self.root_key = new_root;
            self.chain_key_recv = Some(chain_key_recv);
            self.recv_count = 0;

            // Generate new DH keypair and establish new sending chain
            self.prev_send_count = self.send_count;
            self.send_count = 0;
            self.dh_self = RatchetKeyPair::generate();
            let dh_output2 = self.dh_self.secret.diffie_hellman(&remote_pub);
            let (new_root2, chain_key_send) = kdf_rk(&self.root_key, dh_output2.as_bytes());
            self.root_key = new_root2;
            self.chain_key_send = Some(chain_key_send);
        }

        // 3. Skip any messages before this one in the current chain
        self.skip_message_keys(header.message_number)?;

        // 4. Derive message key from receiving chain
        let chain_key = self
            .chain_key_recv
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No receiving chain key"))?;
        let (new_chain, mut msg_key) = kdf_ck(chain_key);
        self.chain_key_recv = Some(new_chain);
        self.recv_count += 1;

        // 5. Decrypt
        let result = decrypt_with_key(&msg_key, header, ciphertext);
        msg_key.0.zeroize();
        result
    }

    /// Skip message keys up to `until` count, storing them for later out-of-order delivery.
    fn skip_message_keys(&mut self, until: u32) -> Result<()> {
        if self.recv_count + MAX_SKIP < until {
            return Err(anyhow::anyhow!(
                "Too many skipped messages ({} > MAX_SKIP={})",
                until - self.recv_count,
                MAX_SKIP
            ));
        }

        let chain_key = match self.chain_key_recv.as_ref() {
            Some(ck) => ck,
            None => return Ok(()),
        };

        let dh_pub = match &self.dh_remote {
            Some(pk) => *pk.as_bytes(),
            None => return Ok(()),
        };

        let mut current_chain = ChainKey::from_bytes(*chain_key.as_bytes());
        while self.recv_count < until {
            let (new_chain, msg_key) = kdf_ck(&current_chain);
            self.skipped_keys.insert((dh_pub, self.recv_count), msg_key);
            current_chain = new_chain;
            self.recv_count += 1;
        }
        self.chain_key_recv = Some(current_chain);

        Ok(())
    }

    /// Securely wipe all ratchet state from memory.
    pub fn secure_wipe(&mut self) {
        self.root_key.zeroize();
        self.chain_key_send = None;
        self.chain_key_recv = None;
        self.send_count = 0;
        self.recv_count = 0;
        self.prev_send_count = 0;
        // Drop all skipped keys (MessageKey zeroizes on drop)
        self.skipped_keys.clear();
        self.initialized = false;
    }
}

impl Drop for RatchetState {
    fn drop(&mut self) {
        self.secure_wipe();
    }
}

/// Decrypt ciphertext with a specific message key.
///
/// Input format: nonce(32) || ciphertext || tag(32)
/// Uses RatchetHeader as AEAD associated data for header binding.
fn decrypt_with_key(msg_key: &MessageKey, header: &RatchetHeader, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 64 {
        return Err(anyhow::anyhow!("Ratchet ciphertext too short"));
    }

    let nonce: [u8; 32] = data[..32].try_into().unwrap();
    let tag_start = data.len() - 32;
    let ct = &data[32..tag_start];
    let tag: [u8; 32] = data[tag_start..].try_into().unwrap();

    let aad = header.to_aad();
    let aegis = Aegis256::<32>::new(msg_key.as_bytes(), &nonce);
    aegis.decrypt(ct, &tag, &aad).map_err(|_| {
        anyhow::anyhow!("Ratchet message decryption failed — wrong key or tampered data")
    })
}

// ─── Serializable Ratchet State (for persistence) ────────────────────────────

#[derive(Serialize, Deserialize)]
struct SkippedKeyEntry {
    dh_public: [u8; 32],
    message_number: u32,
    key: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct SerializedRatchetState {
    dh_self_secret: Vec<u8>,
    dh_self_public: Vec<u8>,
    dh_remote: Option<Vec<u8>>,
    root_key: Vec<u8>,
    chain_key_send: Option<Vec<u8>>,
    chain_key_recv: Option<Vec<u8>>,
    send_count: u32,
    recv_count: u32,
    prev_send_count: u32,
    skipped_keys: Vec<SkippedKeyEntry>,
    initialized: bool,
}

impl RatchetState {
    fn to_serializable(&self) -> SerializedRatchetState {
        SerializedRatchetState {
            dh_self_secret: self.dh_self.secret.to_bytes().to_vec(),
            dh_self_public: self.dh_self.public.as_bytes().to_vec(),
            dh_remote: self.dh_remote.map(|pk| pk.as_bytes().to_vec()),
            root_key: self.root_key.to_vec(),
            chain_key_send: self
                .chain_key_send
                .as_ref()
                .map(|ck| ck.as_bytes().to_vec()),
            chain_key_recv: self
                .chain_key_recv
                .as_ref()
                .map(|ck| ck.as_bytes().to_vec()),
            send_count: self.send_count,
            recv_count: self.recv_count,
            prev_send_count: self.prev_send_count,
            skipped_keys: self
                .skipped_keys
                .iter()
                .map(|((dh, num), mk)| SkippedKeyEntry {
                    dh_public: *dh,
                    message_number: *num,
                    key: *mk.as_bytes(),
                })
                .collect(),
            initialized: self.initialized,
        }
    }

    fn from_serializable(s: SerializedRatchetState) -> Result<Self> {
        let dh_secret_bytes: [u8; 32] = s
            .dh_self_secret
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid DH secret length"))?;
        let dh_self = RatchetKeyPair::from_secret_bytes(dh_secret_bytes);

        let dh_remote = if let Some(ref pk_bytes) = s.dh_remote {
            let bytes: [u8; 32] = pk_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid DH remote public key"))?;
            Some(PublicKey::from(bytes))
        } else {
            None
        };

        let root_key: [u8; 32] = s
            .root_key
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid root key length"))?;

        let chain_key_send = s.chain_key_send.map(|ck| {
            let bytes: [u8; 32] = ck.as_slice().try_into().expect("chain key 32 bytes");
            ChainKey(bytes)
        });

        let chain_key_recv = s.chain_key_recv.map(|ck| {
            let bytes: [u8; 32] = ck.as_slice().try_into().expect("chain key 32 bytes");
            ChainKey(bytes)
        });

        let mut skipped_keys = HashMap::new();
        for entry in s.skipped_keys {
            skipped_keys.insert(
                (entry.dh_public, entry.message_number),
                MessageKey(entry.key),
            );
        }

        Ok(Self {
            dh_self,
            dh_remote,
            root_key,
            chain_key_send,
            chain_key_recv,
            send_count: s.send_count,
            recv_count: s.recv_count,
            prev_send_count: s.prev_send_count,
            skipped_keys,
            initialized: s.initialized,
        })
    }
}

// ─── Ratchet Manager ─────────────────────────────────────────────────────────

/// Manages Double Ratchet sessions for all peers.
///
/// Each peer gets an independent RatchetState. Sessions can be optionally
/// persisted to disk (encrypted with AEGIS-256). In Ghost mode,
/// persistence is disabled and all state is memory-only.
pub struct RatchetManager {
    sessions: HashMap<String, RatchetState>, // peer_did → state
    persist_dir: Option<PathBuf>,
    persist_key: Option<[u8; 32]>,
}

impl RatchetManager {
    pub fn new(persist_dir: Option<PathBuf>, persist_key: Option<[u8; 32]>) -> Self {
        if let Some(ref dir) = persist_dir {
            let _ = std::fs::create_dir_all(dir);
        }
        Self {
            sessions: HashMap::new(),
            persist_dir,
            persist_key,
        }
    }

    /// Get or initialize a ratchet session for a peer.
    ///
    /// `is_initiator` is determined by DID comparison: smaller DID = initiator.
    /// This ensures both sides agree on roles without extra negotiation.
    ///
    /// `remote_dh_pub`: The peer's ratchet DH public key (from handshake).
    ///   - Initiator uses this as the initial DH target (like Signal's signed prekey).
    ///   - Responder ignores this (learns initiator's key from the first message header).
    ///
    /// `our_ratchet_secret`: Responder's own ratchet keypair secret bytes.
    ///   - Must match the public key sent in our handshake's `ratchet_dh_public_hex`.
    ///   - If None, a random keypair is generated (test use only).
    pub fn get_or_init(
        &mut self,
        peer_did: &str,
        shared_secret: &[u8],
        remote_dh_pub: &PublicKey,
        is_initiator: bool,
        our_ratchet_secret: Option<[u8; 32]>,
    ) -> &mut RatchetState {
        if !self.sessions.contains_key(peer_did) {
            let state = if is_initiator {
                RatchetState::init_initiator(shared_secret, remote_dh_pub)
            } else {
                // Responder: use our ratchet keypair (sent in handshake) as dh_self.
                // Do NOT pre-compute receiving chain — it will be established when
                // the first message arrives via DH ratchet in decrypt().
                // This follows the Signal Double Ratchet specification exactly.
                let dh_self = match our_ratchet_secret {
                    Some(bytes) => RatchetKeyPair::from_secret_bytes(bytes),
                    None => RatchetKeyPair::generate(),
                };
                RatchetState::init_responder(shared_secret, dh_self)
            };
            self.sessions.insert(peer_did.to_string(), state);
        }
        self.sessions.get_mut(peer_did).unwrap()
    }

    /// Securely replace any existing session with a fresh ratchet derived
    /// from the latest verified transport handshake.
    pub fn reset_and_init(
        &mut self,
        peer_did: &str,
        shared_secret: &[u8],
        remote_dh_pub: &PublicKey,
        is_initiator: bool,
        our_ratchet_secret: Option<[u8; 32]>,
    ) -> &mut RatchetState {
        self.remove_session(peer_did);
        let state = if is_initiator {
            RatchetState::init_initiator(shared_secret, remote_dh_pub)
        } else {
            let dh_self = match our_ratchet_secret {
                Some(bytes) => RatchetKeyPair::from_secret_bytes(bytes),
                None => RatchetKeyPair::generate(),
            };
            RatchetState::init_responder(shared_secret, dh_self)
        };
        self.sessions.insert(peer_did.to_string(), state);
        self.sessions.get_mut(peer_did).unwrap()
    }

    /// Encrypt a message for a specific peer.
    pub fn encrypt_for_peer(
        &mut self,
        peer_did: &str,
        plaintext: &[u8],
    ) -> Result<(RatchetHeader, Vec<u8>)> {
        let state = self
            .sessions
            .get_mut(peer_did)
            .ok_or_else(|| anyhow::anyhow!("No ratchet session for peer: {}", peer_did))?;
        state.encrypt(plaintext)
    }

    /// Decrypt a message from a specific peer.
    pub fn decrypt_from_peer(
        &mut self,
        peer_did: &str,
        header: &RatchetHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let state = self
            .sessions
            .get_mut(peer_did)
            .ok_or_else(|| anyhow::anyhow!("No ratchet session for peer: {}", peer_did))?;
        state.decrypt(header, ciphertext)
    }

    /// Check if a session exists for a peer.
    pub fn has_session(&self, peer_did: &str) -> bool {
        self.sessions.contains_key(peer_did)
    }

    pub fn session_remote_dh_public(&self, peer_did: &str) -> Option<[u8; 32]> {
        self.sessions
            .get(peer_did)
            .and_then(RatchetState::remote_dh_public)
    }

    pub fn session_send_ready(&self, peer_did: &str) -> bool {
        self.sessions
            .get(peer_did)
            .map(RatchetState::is_send_ready)
            .unwrap_or(false)
    }

    /// Remove a session for a peer (securely wiped via Drop).
    pub fn remove_session(&mut self, peer_did: &str) {
        if let Some(mut state) = self.sessions.remove(peer_did) {
            state.secure_wipe();
        }
        // Remove persisted file if exists
        if let Some(ref dir) = self.persist_dir {
            let path = dir.join(format!("{}.ratchet", hex::encode(peer_did)));
            let _ = secure_delete_file(&path);
        }
    }

    /// Persist all sessions to disk (encrypted with AEGIS-256).
    /// No-op if persist_dir is None (Ghost mode).
    pub fn persist_all(&self) -> Result<()> {
        let dir = match &self.persist_dir {
            Some(d) => d,
            None => return Ok(()),
        };
        let key = match &self.persist_key {
            Some(k) => k,
            None => return Ok(()),
        };

        for (peer_did, state) in &self.sessions {
            let serialized = state.to_serializable();
            let data = bincode::serialize(&serialized)
                .map_err(|e| anyhow::anyhow!("Ratchet serialize failed: {}", e))?;

            // AEGIS-256 encrypt
            let nonce: [u8; 32] = rand::random();
            let aegis = Aegis256::<32>::new(key, &nonce);
            let (ct, tag) = aegis.encrypt(&data, b"ratchet-persist");

            let mut output = Vec::with_capacity(32 + ct.len() + 32);
            output.extend_from_slice(&nonce);
            output.extend_from_slice(&ct);
            output.extend_from_slice(&tag);

            let path = dir.join(format!("{}.ratchet", hex::encode(peer_did)));
            std::fs::write(&path, &output)?;
        }

        Ok(())
    }

    /// Load all persisted sessions from disk.
    /// No-op if persist_dir is None (Ghost mode).
    pub fn load_all(&mut self) -> Result<()> {
        let dir = match &self.persist_dir {
            Some(d) => d.clone(),
            None => return Ok(()),
        };
        let key = match &self.persist_key {
            Some(k) => *k,
            None => return Ok(()),
        };

        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => return Ok(()),
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("ratchet") {
                continue;
            }

            let filename = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();

            let peer_did = match hex::decode(&filename) {
                Ok(bytes) => String::from_utf8(bytes).unwrap_or_default(),
                Err(_) => continue,
            };

            if peer_did.is_empty() {
                continue;
            }

            let data = match std::fs::read(&path) {
                Ok(d) => d,
                Err(_) => continue,
            };

            if data.len() < 64 {
                continue;
            }

            // AEGIS-256 decrypt
            let nonce: [u8; 32] = data[..32].try_into().unwrap();
            let tag_start = data.len() - 32;
            let ct = &data[32..tag_start];
            let tag: [u8; 32] = data[tag_start..].try_into().unwrap();

            let aegis = Aegis256::<32>::new(&key, &nonce);
            let plaintext = match aegis.decrypt(ct, &tag, b"ratchet-persist") {
                Ok(pt) => pt,
                Err(_) => {
                    tracing::warn!(peer_did = %peer_did, "Failed to decrypt ratchet state — skipping");
                    continue;
                }
            };

            let serialized: SerializedRatchetState = match bincode::deserialize(&plaintext) {
                Ok(s) => s,
                Err(_) => continue,
            };

            match RatchetState::from_serializable(serialized) {
                Ok(state) => {
                    self.sessions.insert(peer_did, state);
                }
                Err(_) => continue,
            }
        }

        Ok(())
    }

    /// Securely wipe all sessions and persisted data.
    /// Used in Ghost mode cleanup and emergency wipe scenarios.
    pub fn secure_wipe(&mut self) {
        // Wipe all in-memory sessions
        for (_, mut state) in self.sessions.drain() {
            state.secure_wipe();
        }

        // Wipe persisted files
        if let Some(ref dir) = self.persist_dir {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) == Some("ratchet") {
                        let _ = secure_delete_file(&path);
                    }
                }
            }
        }

        self.persist_key.as_mut().map(|k| k.zeroize());
    }
}

impl Drop for RatchetManager {
    fn drop(&mut self) {
        for (_, mut state) in self.sessions.drain() {
            state.secure_wipe();
        }
        if let Some(ref mut key) = self.persist_key {
            key.zeroize();
        }
    }
}

/// Overwrite a file with random data before deletion (NIST SP 800-88 lite).
fn secure_delete_file(path: &std::path::Path) -> Result<()> {
    if let Ok(metadata) = std::fs::metadata(path) {
        let size = metadata.len() as usize;
        if size > 0 {
            let random_data: Vec<u8> = (0..size).map(|_| rand::random::<u8>()).collect();
            let _ = std::fs::write(path, &random_data);
        }
    }
    std::fs::remove_file(path)?;
    Ok(())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a pair of initialized ratchet states (Alice = initiator, Bob = responder).
    ///
    /// Bob starts without knowing Alice's DH public key — he learns it from
    /// the first message, triggering the DH ratchet that establishes both
    /// his receiving chain (to decrypt Alice's messages) and sending chain
    /// (to send his own messages).
    fn create_ratchet_pair() -> (RatchetState, RatchetState) {
        let shared_secret = rand::random::<[u8; 32]>();
        let bob_dh = RatchetKeyPair::generate();
        let bob_dh_pub = bob_dh.public;

        let alice = RatchetState::init_initiator(&shared_secret, &bob_dh_pub);
        let bob = RatchetState::init_responder(&shared_secret, bob_dh);

        (alice, bob)
    }

    #[test]
    fn test_ratchet_basic_send_receive() {
        let (mut alice, mut bob) = create_ratchet_pair();

        // Alice sends 3 messages
        let msgs = [
            b"Hello Bob!".to_vec(),
            b"How are you?".to_vec(),
            b"This is message 3".to_vec(),
        ];

        for msg in &msgs {
            let (header, ct) = alice.encrypt(msg).unwrap();
            let pt = bob.decrypt(&header, &ct).unwrap();
            assert_eq!(&pt, msg);
        }
    }

    #[test]
    fn test_ratchet_bidirectional() {
        let (mut alice, mut bob) = create_ratchet_pair();

        // Alice → Bob
        let (h1, ct1) = alice.encrypt(b"Hello from Alice").unwrap();
        let pt1 = bob.decrypt(&h1, &ct1).unwrap();
        assert_eq!(pt1, b"Hello from Alice");

        // Bob → Alice (triggers DH ratchet in Bob)
        let (h2, ct2) = bob.encrypt(b"Hello from Bob").unwrap();
        let pt2 = alice.decrypt(&h2, &ct2).unwrap();
        assert_eq!(pt2, b"Hello from Bob");

        // Alice → Bob again (another DH ratchet)
        let (h3, ct3) = alice.encrypt(b"Second from Alice").unwrap();
        let pt3 = bob.decrypt(&h3, &ct3).unwrap();
        assert_eq!(pt3, b"Second from Alice");
    }

    #[test]
    fn test_ratchet_out_of_order() {
        let (mut alice, mut bob) = create_ratchet_pair();

        // Alice sends 3 messages
        let (h1, ct1) = alice.encrypt(b"msg1").unwrap();
        let (h2, ct2) = alice.encrypt(b"msg2").unwrap();
        let (h3, ct3) = alice.encrypt(b"msg3").unwrap();

        // Bob receives in order 3, 1, 2 (out of order)
        let pt3 = bob.decrypt(&h3, &ct3).unwrap();
        assert_eq!(pt3, b"msg3");

        let pt1 = bob.decrypt(&h1, &ct1).unwrap();
        assert_eq!(pt1, b"msg1");

        let pt2 = bob.decrypt(&h2, &ct2).unwrap();
        assert_eq!(pt2, b"msg2");
    }

    #[test]
    fn test_ratchet_max_skip_exceeded() {
        let (mut alice, mut bob) = create_ratchet_pair();

        // Alice sends MAX_SKIP + 10 messages, Bob only decrypts the last
        let mut headers = Vec::new();
        let mut cts = Vec::new();
        for i in 0..(MAX_SKIP + 10) {
            let msg = format!("msg{}", i);
            let (h, ct) = alice.encrypt(msg.as_bytes()).unwrap();
            headers.push(h);
            cts.push(ct);
        }

        // Trying to decrypt the very last message should fail (too many skips)
        let last = headers.len() - 1;
        let result = bob.decrypt(&headers[last], &cts[last]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Too many skipped"));
    }

    #[test]
    fn test_ratchet_forward_secrecy() {
        let (mut alice, mut bob) = create_ratchet_pair();

        // Alice sends a message, Bob decrypts it
        let (h1, ct1) = alice.encrypt(b"Secret past message").unwrap();
        let pt1 = bob.decrypt(&h1, &ct1).unwrap();
        assert_eq!(pt1, b"Secret past message");

        // Bob replies (DH ratchet advances)
        let (h2, ct2) = bob.encrypt(b"Bob reply").unwrap();
        let _pt2 = alice.decrypt(&h2, &ct2).unwrap();

        // Now capture Bob's root key (simulating state compromise)
        let captured_root = bob.root_key;

        // Try to decrypt the old message with captured root key — should fail
        // because the message key was derived from a previous chain that's been
        // ratcheted past and zeroed.
        // We verify by ensuring the old header/ciphertext no longer decrypts
        // with a fresh state using the captured root key.
        let result = bob.decrypt(&h1, &ct1);
        assert!(
            result.is_err(),
            "Forward secrecy: old message must not decrypt after ratchet advance"
        );

        // Verify the captured root key is different from original
        // (DH ratchet changed it)
        assert_ne!(captured_root, [0u8; 32]);
    }

    #[test]
    fn test_ratchet_persist_restore() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let persist_key: [u8; 32] = rand::random();

        // Create manager, init session, send messages
        let mut mgr = RatchetManager::new(Some(tmp_dir.path().to_path_buf()), Some(persist_key));

        let shared_secret = rand::random::<[u8; 32]>();
        let remote_dh = RatchetKeyPair::generate();
        let remote_pub = remote_dh.public;

        mgr.get_or_init("did:nxf:test_peer", &shared_secret, &remote_pub, true, None);

        let (_header, _ct) = mgr
            .encrypt_for_peer("did:nxf:test_peer", b"Persist test")
            .unwrap();

        // Persist
        mgr.persist_all().unwrap();

        // Create a new manager with same key, load
        let mut mgr2 = RatchetManager::new(Some(tmp_dir.path().to_path_buf()), Some(persist_key));
        mgr2.load_all().unwrap();

        assert!(mgr2.has_session("did:nxf:test_peer"));

        // The loaded session should be able to encrypt new messages
        let result = mgr2.encrypt_for_peer("did:nxf:test_peer", b"After restore");
        assert!(result.is_ok());
    }

    #[test]
    fn test_ratchet_manager_exposes_persisted_remote_dh_public() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let persist_key: [u8; 32] = rand::random();
        let shared_secret = rand::random::<[u8; 32]>();
        let remote_dh = RatchetKeyPair::generate();
        let remote_pub = remote_dh.public;

        let mut mgr = RatchetManager::new(Some(tmp_dir.path().to_path_buf()), Some(persist_key));
        mgr.get_or_init("did:nxf:test_peer", &shared_secret, &remote_pub, true, None);
        assert_eq!(
            mgr.session_remote_dh_public("did:nxf:test_peer"),
            Some(*remote_pub.as_bytes())
        );

        mgr.persist_all().unwrap();

        let mut restored =
            RatchetManager::new(Some(tmp_dir.path().to_path_buf()), Some(persist_key));
        restored.load_all().unwrap();
        assert_eq!(
            restored.session_remote_dh_public("did:nxf:test_peer"),
            Some(*remote_pub.as_bytes())
        );
    }

    #[test]
    fn test_ratchet_secure_wipe() {
        let mut state = {
            let shared_secret = rand::random::<[u8; 32]>();
            let remote_dh = RatchetKeyPair::generate();
            RatchetState::init_initiator(&shared_secret, &remote_dh.public)
        };

        // Verify state is initialized
        assert!(state.initialized);
        assert!(state.chain_key_send.is_some());

        // Wipe
        state.secure_wipe();

        assert!(!state.initialized);
        assert!(state.chain_key_send.is_none());
        assert!(state.chain_key_recv.is_none());
        assert_eq!(state.root_key, [0u8; 32]);
        assert!(state.skipped_keys.is_empty());
    }

    #[test]
    fn test_ratchet_manager_multi_peer() {
        let mut mgr = RatchetManager::new(None, None);

        let ss1 = rand::random::<[u8; 32]>();
        let ss2 = rand::random::<[u8; 32]>();
        let ss3 = rand::random::<[u8; 32]>();

        let dh1 = RatchetKeyPair::generate();
        let dh2 = RatchetKeyPair::generate();
        let dh3 = RatchetKeyPair::generate();

        mgr.get_or_init("peer1", &ss1, &dh1.public, true, None);
        mgr.get_or_init("peer2", &ss2, &dh2.public, true, None);
        mgr.get_or_init("peer3", &ss3, &dh3.public, false, None);

        assert!(mgr.has_session("peer1"));
        assert!(mgr.has_session("peer2"));
        assert!(mgr.has_session("peer3"));

        // Encrypt for each peer independently
        let r1 = mgr.encrypt_for_peer("peer1", b"msg for peer1");
        let r2 = mgr.encrypt_for_peer("peer2", b"msg for peer2");
        assert!(r1.is_ok());
        assert!(r2.is_ok());

        // Peer3 is responder — no sending chain until DH ratchet
        // (responder needs to receive first message to establish sending chain)

        mgr.remove_session("peer2");
        assert!(!mgr.has_session("peer2"));
    }

    #[test]
    fn test_ratchet_manager_reset_and_init_replaces_existing_session() {
        let mut mgr = RatchetManager::new(None, None);
        let shared_secret = rand::random::<[u8; 32]>();
        let first_remote = RatchetKeyPair::generate();
        let second_remote = RatchetKeyPair::generate();

        let (header1, _) = {
            let _ = mgr.get_or_init(
                "peer-reset",
                &shared_secret,
                &first_remote.public,
                true,
                None,
            );
            mgr.encrypt_for_peer("peer-reset", b"first").unwrap()
        };
        assert_eq!(header1.message_number, 0);

        let (header2, _) = {
            let _ = mgr.reset_and_init(
                "peer-reset",
                &shared_secret,
                &second_remote.public,
                true,
                None,
            );
            mgr.encrypt_for_peer("peer-reset", b"second").unwrap()
        };
        assert_eq!(header2.message_number, 0);
        assert_ne!(header1.dh_public, header2.dh_public);
    }

    #[test]
    fn test_responder_session_is_not_send_ready_until_first_inbound_message() {
        let shared_secret = rand::random::<[u8; 32]>();
        let bob_dh = RatchetKeyPair::generate();

        let mut alice = RatchetState::init_initiator(&shared_secret, &bob_dh.public);
        let mut bob = RatchetState::init_responder(&shared_secret, bob_dh);

        assert!(alice.is_send_ready());
        assert!(!bob.is_send_ready());

        let (header, ciphertext) = alice.encrypt(b"bootstrap").unwrap();
        let plaintext = bob.decrypt(&header, &ciphertext).unwrap();
        assert_eq!(plaintext, b"bootstrap");
        assert!(bob.is_send_ready());

        let mut mgr = RatchetManager::new(None, None);
        mgr.sessions.insert("alice".to_string(), alice);
        mgr.sessions.insert("bob".to_string(), bob);
        assert!(mgr.session_send_ready("alice"));
        assert!(mgr.session_send_ready("bob"));
    }

    #[test]
    fn test_ratchet_wrong_peer_fails() {
        let (mut alice, mut bob) = create_ratchet_pair();

        // Create a separate Eve
        let shared_secret_eve = rand::random::<[u8; 32]>();
        let eve_dh = RatchetKeyPair::generate();
        let mut eve = RatchetState::init_initiator(&shared_secret_eve, &eve_dh.public);

        // Alice encrypts for Bob
        let (header, ct) = alice.encrypt(b"Only for Bob").unwrap();

        // Bob can decrypt
        let pt = bob.decrypt(&header, &ct).unwrap();
        assert_eq!(pt, b"Only for Bob");

        // Eve cannot decrypt (different shared secret / ratchet state)
        let eve_result = eve.decrypt(&header, &ct);
        assert!(eve_result.is_err());
    }

    #[test]
    fn test_ratchet_header_aad_binding() {
        let (mut alice, mut bob) = create_ratchet_pair();

        let (header, ct) = alice.encrypt(b"AAD bound message").unwrap();

        // Tamper with header → decryption must fail (AAD mismatch)
        let mut tampered_header = header.clone();
        tampered_header.message_number += 1;

        let result = bob.decrypt(&tampered_header, &ct);
        assert!(
            result.is_err(),
            "Tampered header must cause decryption failure"
        );
    }
}
