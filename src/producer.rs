use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use crate::{Envelope, canonical};

#[derive(Debug, Error)]
pub enum ProducerError {
    #[error("failed to access producer key material: {0}")]
    Io(#[from] std::io::Error),
    #[error("private key file permissions are too broad; require no group/other permission bits")]
    InsecurePrivateKeyPermissions,
    #[error("private key is not valid base64url without padding")]
    InvalidPrivateKeyEncoding,
    #[error("private key must decode to exactly 32 bytes")]
    InvalidPrivateKeyLength,
    #[error("event already contains a signature")]
    SignatureAlreadyPresent,
    #[error("failed to canonicalize event")]
    Canonicalization,
}

pub fn generate_private_key(path: &Path) -> Result<String, ProducerError> {
    let mut seed = [0_u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut seed)?;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options.open(path)?;
    file.write_all(URL_SAFE_NO_PAD.encode(seed).as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;

    Ok(public_key(&SigningKey::from_bytes(&seed)))
}

pub fn load_private_key(path: &Path) -> Result<SigningKey, ProducerError> {
    #[cfg(unix)]
    {
        let mode = fs::metadata(path)?.mode();
        if mode & 0o077 != 0 {
            return Err(ProducerError::InsecurePrivateKeyPermissions);
        }
    }

    let encoded = fs::read_to_string(path)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded.trim())
        .map_err(|_| ProducerError::InvalidPrivateKeyEncoding)?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ProducerError::InvalidPrivateKeyLength)?;
    Ok(SigningKey::from_bytes(&seed))
}

pub fn public_key(signing_key: &SigningKey) -> String {
    URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes())
}

pub fn sign_envelope(
    mut envelope: Envelope,
    signing_key: &SigningKey,
) -> Result<Envelope, ProducerError> {
    if !envelope.signature.is_empty() {
        return Err(ProducerError::SignatureAlreadyPresent);
    }

    let bytes =
        canonical::unsigned_bytes(&envelope).map_err(|_| ProducerError::Canonicalization)?;
    envelope.signature = URL_SAFE_NO_PAD.encode(signing_key.sign(&bytes).to_bytes());
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Verifier;
    use serde_json::json;

    use super::*;
    use crate::envelope::{EVENT_SPEC_V1, PROBE_REQUESTED_V1};

    fn unsigned_envelope() -> Envelope {
        Envelope {
            spec: EVENT_SPEC_V1.to_owned(),
            id: "evt_sign_test".to_owned(),
            issuer: "p_test".to_owned(),
            key_id: "k1".to_owned(),
            kind: PROBE_REQUESTED_V1.to_owned(),
            target: "t_test".to_owned(),
            issued_at: "2026-08-30T18:20:00Z".to_owned(),
            expires_at: "2026-08-30T18:30:00Z".to_owned(),
            correlation_id: "cor_sign_test".to_owned(),
            causation_id: None,
            payload: json!({ "nonce": "public-safe-nonce" }),
            signature: String::new(),
        }
    }

    #[test]
    fn signs_canonical_unsigned_envelope() {
        let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
        let signed = sign_envelope(unsigned_envelope(), &signing_key).unwrap();
        let signature_bytes = URL_SAFE_NO_PAD.decode(&signed.signature).unwrap();
        let signature_bytes: [u8; 64] = signature_bytes.try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
        let message = canonical::unsigned_bytes(&signed).unwrap();

        signing_key
            .verifying_key()
            .verify(&message, &signature)
            .unwrap();
        assert_eq!(public_key(&signing_key).len(), 43);
    }

    #[test]
    fn refuses_to_replace_existing_signature() {
        let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
        let mut envelope = unsigned_envelope();
        envelope.signature = "already-present".to_owned();

        assert!(matches!(
            sign_envelope(envelope, &signing_key),
            Err(ProducerError::SignatureAlreadyPresent)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn generated_private_key_is_mode_0600_and_reloadable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("producer.seed");
        let public = generate_private_key(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;

        assert_eq!(mode, 0o600);
        assert_eq!(public_key(&load_private_key(&path).unwrap()), public);
    }
}
