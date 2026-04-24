use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use rand::random;
use sha2::{Digest, Sha256};

use super::protocol::{MailboxBootstrapScopeKind, MailboxBootstrapToken, MailboxCapability};

const MAX_MAILBOX_BOOTSTRAP_SCOPE_ID_LEN: usize = 256;
const MAX_MAILBOX_BOOTSTRAP_NAMESPACE_LEN: usize = 256;
const MAX_MAILBOX_BOOTSTRAP_CAPABILITY_ID_LEN: usize = 128;
const MAX_MAILBOX_BOOTSTRAP_CLOCK_SKEW_SECS: u64 = 5 * 60;
const MAX_MAILBOX_BOOTSTRAP_POW_NONCE_HEX_LEN: usize = 64;
const MAX_MAILBOX_BOOTSTRAP_POW_DIFFICULTY_BITS: u8 = 24;
pub const DEFAULT_MAILBOX_BOOTSTRAP_TOKEN_POW_BITS: u8 = 12;

fn write_canonical_str(buf: &mut Vec<u8>, value: &str) {
    buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
    buf.extend_from_slice(value.as_bytes());
}

fn signing_data(token: &MailboxBootstrapToken) -> Vec<u8> {
    let mut data = Vec::with_capacity(512);
    data.extend_from_slice(b"Qypha-MailboxBootstrapToken-v1:");
    data.push(token.version);
    data.push(match token.scope_kind {
        MailboxBootstrapScopeKind::Invite => 0x01,
        MailboxBootstrapScopeKind::EpochRotation => 0x02,
        MailboxBootstrapScopeKind::ChunkTransfer => 0x03,
    });
    write_canonical_str(&mut data, &token.scope_id);
    write_canonical_str(&mut data, &token.namespace);
    write_canonical_str(&mut data, &token.capability_id);
    write_canonical_str(&mut data, &token.access_key_sha256);
    write_canonical_str(&mut data, &token.auth_token_sha256);
    data.extend_from_slice(&token.issued_at.to_le_bytes());
    data.extend_from_slice(&token.expires_at.to_le_bytes());
    write_canonical_str(&mut data, &token.issuer_verifying_key_hex);
    data.push(token.pow_difficulty_bits);
    write_canonical_str(&mut data, &token.pow_nonce_hex);
    data
}

fn mailbox_secret_digest(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

fn validate_bootstrap_token_shape(
    token: &MailboxBootstrapToken,
    require_signature: bool,
) -> Result<()> {
    if token.version != 1 {
        bail!(
            "Mailbox bootstrap token version {} is unsupported",
            token.version
        );
    }
    if token.scope_id.trim().is_empty() {
        bail!("Mailbox bootstrap token scope id must not be empty");
    }
    if token.scope_id.len() > MAX_MAILBOX_BOOTSTRAP_SCOPE_ID_LEN {
        bail!(
            "Mailbox bootstrap token scope id exceeds {} bytes",
            MAX_MAILBOX_BOOTSTRAP_SCOPE_ID_LEN
        );
    }
    if token.namespace.trim().is_empty() {
        bail!("Mailbox bootstrap token namespace must not be empty");
    }
    if token.namespace.len() > MAX_MAILBOX_BOOTSTRAP_NAMESPACE_LEN {
        bail!(
            "Mailbox bootstrap token namespace exceeds {} bytes",
            MAX_MAILBOX_BOOTSTRAP_NAMESPACE_LEN
        );
    }
    if token.capability_id.trim().is_empty() {
        bail!("Mailbox bootstrap token capability id must not be empty");
    }
    if token.capability_id.len() > MAX_MAILBOX_BOOTSTRAP_CAPABILITY_ID_LEN {
        bail!(
            "Mailbox bootstrap token capability id exceeds {} bytes",
            MAX_MAILBOX_BOOTSTRAP_CAPABILITY_ID_LEN
        );
    }
    if token.access_key_sha256.len() != 64
        || !token
            .access_key_sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    {
        bail!("Mailbox bootstrap token access digest is invalid");
    }
    if token.auth_token_sha256.len() != 64
        || !token
            .auth_token_sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    {
        bail!("Mailbox bootstrap token auth digest is invalid");
    }
    if token.issuer_verifying_key_hex.len() != 64
        || !token
            .issuer_verifying_key_hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    {
        bail!("Mailbox bootstrap token verifying key is invalid");
    }
    if require_signature && token.signature_b64.trim().is_empty() {
        bail!("Mailbox bootstrap token signature must not be empty");
    }
    if token.pow_difficulty_bits > MAX_MAILBOX_BOOTSTRAP_POW_DIFFICULTY_BITS {
        bail!(
            "Mailbox bootstrap token PoW difficulty exceeds {} bits",
            MAX_MAILBOX_BOOTSTRAP_POW_DIFFICULTY_BITS
        );
    }
    if token.pow_nonce_hex.len() > MAX_MAILBOX_BOOTSTRAP_POW_NONCE_HEX_LEN {
        bail!(
            "Mailbox bootstrap token PoW nonce exceeds {} hex chars",
            MAX_MAILBOX_BOOTSTRAP_POW_NONCE_HEX_LEN
        );
    }
    if token.pow_difficulty_bits > 0 {
        if token.pow_nonce_hex.trim().is_empty() {
            bail!("Mailbox bootstrap token PoW nonce must not be empty");
        }
        if !token.pow_nonce_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("Mailbox bootstrap token PoW nonce is invalid");
        }
    } else if !token.pow_nonce_hex.is_empty()
        && !token.pow_nonce_hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        bail!("Mailbox bootstrap token PoW nonce is invalid");
    }
    if token.expires_at <= token.issued_at {
        bail!("Mailbox bootstrap token expiry must be after issuance");
    }
    Ok(())
}

fn leading_zero_bits(bytes: &[u8]) -> u8 {
    let mut count = 0u8;
    for byte in bytes {
        let zeros = byte.leading_zeros() as u8;
        count = count.saturating_add(zeros);
        if zeros != 8 {
            break;
        }
    }
    count
}

fn pow_score_bits(token: &MailboxBootstrapToken) -> u8 {
    let digest = Sha256::digest(signing_data(token));
    leading_zero_bits(&digest)
}

fn solve_pow(token: &mut MailboxBootstrapToken) -> Result<()> {
    if token.pow_difficulty_bits == 0 {
        token.pow_nonce_hex.clear();
        return Ok(());
    }
    let seed = random::<u64>();
    for counter in 0u64.. {
        token.pow_nonce_hex = format!("{:016x}", seed.wrapping_add(counter));
        if pow_score_bits(token) >= token.pow_difficulty_bits {
            return Ok(());
        }
    }
    bail!("Failed to solve mailbox bootstrap PoW")
}

pub fn mailbox_bootstrap_pow_satisfies(token: &MailboxBootstrapToken, min_bits: u8) -> bool {
    pow_score_bits(token) >= min_bits
}

pub fn issue_mailbox_bootstrap_token_with_difficulty(
    signing_key: &ed25519_dalek::SigningKey,
    scope_kind: MailboxBootstrapScopeKind,
    scope_id: &str,
    namespace: &str,
    capability: &MailboxCapability,
    expires_at: u64,
    pow_difficulty_bits: u8,
) -> Result<MailboxBootstrapToken> {
    if pow_difficulty_bits > MAX_MAILBOX_BOOTSTRAP_POW_DIFFICULTY_BITS {
        bail!(
            "Requested mailbox bootstrap PoW difficulty exceeds {} bits",
            MAX_MAILBOX_BOOTSTRAP_POW_DIFFICULTY_BITS
        );
    }
    if capability.capability_id.trim().is_empty() {
        bail!("Mailbox bootstrap token requires a capability id");
    }
    if capability.access_key_b64.trim().is_empty() {
        bail!("Mailbox bootstrap token requires an access key");
    }
    if capability.auth_token_b64.trim().is_empty() {
        bail!("Mailbox bootstrap token requires an auth token");
    }
    let issued_at = chrono::Utc::now().timestamp().max(0) as u64;
    let mut token = MailboxBootstrapToken {
        version: 1,
        scope_kind,
        scope_id: scope_id.trim().to_string(),
        namespace: namespace.to_string(),
        capability_id: capability.capability_id.clone(),
        access_key_sha256: mailbox_secret_digest(&capability.access_key_b64),
        auth_token_sha256: mailbox_secret_digest(&capability.auth_token_b64),
        issued_at,
        expires_at,
        issuer_verifying_key_hex: hex::encode(signing_key.verifying_key().as_bytes()),
        pow_difficulty_bits,
        pow_nonce_hex: String::new(),
        signature_b64: String::new(),
    };
    solve_pow(&mut token)?;
    validate_bootstrap_token_shape(&token, false)?;
    let signature = signing_key.sign(&signing_data(&token));
    token.signature_b64 = BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes());
    Ok(token)
}

pub fn issue_mailbox_bootstrap_token(
    signing_key: &ed25519_dalek::SigningKey,
    scope_kind: MailboxBootstrapScopeKind,
    scope_id: &str,
    namespace: &str,
    capability: &MailboxCapability,
    expires_at: u64,
) -> Result<MailboxBootstrapToken> {
    issue_mailbox_bootstrap_token_with_difficulty(
        signing_key,
        scope_kind,
        scope_id,
        namespace,
        capability,
        expires_at,
        DEFAULT_MAILBOX_BOOTSTRAP_TOKEN_POW_BITS,
    )
}

pub fn verify_mailbox_bootstrap_token(
    token: &MailboxBootstrapToken,
    expected_scope_kind: Option<MailboxBootstrapScopeKind>,
    namespace: &str,
    capability: &MailboxCapability,
    enforce_expiry: bool,
) -> Result<()> {
    validate_bootstrap_token_shape(token, true)?;
    if let Some(expected_scope_kind) = expected_scope_kind {
        if token.scope_kind != expected_scope_kind {
            bail!(
                "Mailbox bootstrap token scope mismatch: expected {:?}, got {:?}",
                expected_scope_kind,
                token.scope_kind
            );
        }
    }
    if token.namespace != namespace {
        bail!("Mailbox bootstrap token namespace mismatch");
    }
    if token.capability_id != capability.capability_id {
        bail!("Mailbox bootstrap token capability mismatch");
    }
    if token.access_key_sha256 != mailbox_secret_digest(&capability.access_key_b64) {
        bail!("Mailbox bootstrap token access digest mismatch");
    }
    if token.auth_token_sha256 != mailbox_secret_digest(&capability.auth_token_b64) {
        bail!("Mailbox bootstrap token auth digest mismatch");
    }

    let verifying_key_bytes = hex::decode(&token.issuer_verifying_key_hex)
        .context("Mailbox bootstrap token verifying key is not valid hex")?;
    let verifying_key_bytes: [u8; 32] = verifying_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Mailbox bootstrap token verifying key must be 32 bytes"))?;
    let verifying_key =
        VerifyingKey::from_bytes(&verifying_key_bytes).context("Invalid mailbox bootstrap key")?;

    let signature_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(token.signature_b64.as_bytes())
        .context("Mailbox bootstrap token signature is not valid base64")?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| anyhow::anyhow!("Mailbox bootstrap token signature is malformed"))?;
    verifying_key
        .verify_strict(&signing_data(token), &signature)
        .map_err(|_| anyhow::anyhow!("Mailbox bootstrap token signature verification failed"))?;

    let now = chrono::Utc::now().timestamp().max(0) as u64;
    if token.issued_at > now.saturating_add(MAX_MAILBOX_BOOTSTRAP_CLOCK_SKEW_SECS) {
        bail!("Mailbox bootstrap token issuance time is in the future");
    }
    if enforce_expiry && now > token.expires_at {
        bail!("Mailbox bootstrap token has expired");
    }
    if token.pow_difficulty_bits > 0
        && !mailbox_bootstrap_pow_satisfies(token, token.pow_difficulty_bits)
    {
        bail!("Mailbox bootstrap token PoW verification failed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_capability() -> MailboxCapability {
        MailboxCapability {
            capability_id: "cap_bootstrap".to_string(),
            access_key_b64: BASE64_URL_SAFE_NO_PAD.encode([7u8; 32]),
            auth_token_b64: BASE64_URL_SAFE_NO_PAD.encode([9u8; 32]),
            bootstrap_token: None,
        }
    }

    #[test]
    fn issued_token_verifies_against_capability() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let capability = sample_capability();
        let token = issue_mailbox_bootstrap_token(
            &signing_key,
            MailboxBootstrapScopeKind::Invite,
            "invite_123",
            "mailbox:ops:epoch:1:slot:test",
            &capability,
            chrono::Utc::now().timestamp().max(0) as u64 + 3_600,
        )
        .unwrap();

        verify_mailbox_bootstrap_token(
            &token,
            Some(MailboxBootstrapScopeKind::Invite),
            "mailbox:ops:epoch:1:slot:test",
            &capability,
            true,
        )
        .unwrap();
        assert!(token.pow_difficulty_bits >= DEFAULT_MAILBOX_BOOTSTRAP_TOKEN_POW_BITS);
        assert!(mailbox_bootstrap_pow_satisfies(
            &token,
            token.pow_difficulty_bits
        ));
    }

    #[test]
    fn verify_rejects_capability_mismatch() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let capability = sample_capability();
        let token = issue_mailbox_bootstrap_token(
            &signing_key,
            MailboxBootstrapScopeKind::Invite,
            "invite_456",
            "mailbox:ops:epoch:2:slot:test",
            &capability,
            chrono::Utc::now().timestamp().max(0) as u64 + 3_600,
        )
        .unwrap();
        let mut tampered = capability.clone();
        tampered.capability_id = "cap_other".to_string();

        let error = verify_mailbox_bootstrap_token(
            &token,
            Some(MailboxBootstrapScopeKind::Invite),
            "mailbox:ops:epoch:2:slot:test",
            &tampered,
            true,
        )
        .unwrap_err();
        assert!(error.to_string().contains("capability mismatch"));
    }

    #[test]
    fn verify_rejects_invalid_pow_nonce() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let capability = sample_capability();
        let mut token = issue_mailbox_bootstrap_token_with_difficulty(
            &signing_key,
            MailboxBootstrapScopeKind::Invite,
            "invite_pow",
            "mailbox:ops:epoch:3:slot:test",
            &capability,
            chrono::Utc::now().timestamp().max(0) as u64 + 3_600,
            8,
        )
        .unwrap();
        token.pow_nonce_hex = "deadbeef".to_string();

        let error = verify_mailbox_bootstrap_token(
            &token,
            Some(MailboxBootstrapScopeKind::Invite),
            "mailbox:ops:epoch:3:slot:test",
            &capability,
            true,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("signature verification failed")
                || error.to_string().contains("PoW verification failed")
        );
    }
}
