pub mod at_rest;
pub mod double_ratchet;
pub mod encryption;
pub mod identity;
pub mod key_rotation;
pub mod keystore;
pub mod merkle;
pub mod rate_limiter;
pub mod replay_guard;
pub mod request_nonce;
pub mod shamir;
pub mod signing;

pub use double_ratchet::{RatchetHeader, RatchetManager, RatchetState};
pub use encryption::{
    decrypt_artifact, decrypt_message, encrypt_artifact, encrypt_message, hybrid_decrypt_artifact,
    hybrid_decrypt_message, hybrid_encrypt_artifact, hybrid_encrypt_message, EncryptedEnvelope,
};
pub use identity::AgentKeyPair;
pub use request_nonce::next_request_nonce;
pub use signing::{sign_data, verify_signature};
