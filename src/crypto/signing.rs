use anyhow::Result;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Sign arbitrary data with the agent's Ed25519 private key
pub fn sign_data(signing_key: &SigningKey, data: &[u8]) -> Vec<u8> {
    let signature: Signature = signing_key.sign(data);
    signature.to_bytes().to_vec()
}

/// Verify a signature against the sender's public key
pub fn verify_signature(
    verifying_key: &VerifyingKey,
    data: &[u8],
    signature_bytes: &[u8],
) -> Result<bool> {
    let sig_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid signature length"))?;
    let signature = Signature::from_bytes(&sig_array);

    Ok(verifying_key.verify(data, &signature).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_sign_and_verify() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let data = b"Hello Qypha agent network!";
        let signature = sign_data(&signing_key, data);

        assert!(verify_signature(&verifying_key, data, &signature).unwrap());
    }

    #[test]
    fn test_tampered_data_fails() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let data = b"Original message";
        let signature = sign_data(&signing_key, data);

        let tampered = b"Tampered message";
        assert!(!verify_signature(&verifying_key, tampered, &signature).unwrap());
    }

    #[test]
    fn test_wrong_key_fails() {
        let signing_key1 = SigningKey::generate(&mut OsRng);
        let signing_key2 = SigningKey::generate(&mut OsRng);
        let wrong_verifier = signing_key2.verifying_key();

        let data = b"Test data";
        let signature = sign_data(&signing_key1, data);

        assert!(!verify_signature(&wrong_verifier, data, &signature).unwrap());
    }
}
