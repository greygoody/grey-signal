use std::{collections::BTreeMap, fs, path::Path};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    canonical,
    envelope::{
        EVENT_SPEC_V1, Envelope, PROBE_COMPLETED_V1, PROBE_REQUESTED_V1, ProbeCompletedPayload,
        ProbeRequestedPayload,
    },
};

const MAX_ENVELOPE_BYTES: usize = 8 * 1024;
const MAX_ID_LEN: usize = 96;
const MAX_CLOCK_SKEW_SECONDS: i64 = 60;
const MAX_EVENT_AGE_SECONDS: i64 = 15 * 60;
const MAX_TTL_SECONDS: i64 = 15 * 60;

#[derive(Debug, Clone)]
pub struct AdmissionMetadata {
    pub policy_commit: String,
    pub workflow_run_id: String,
    pub workflow_run_attempt: u64,
    pub admitted_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRecord {
    pub record: String,
    pub admission: AdmissionEvidence,
    pub event_digest: String,
    pub event: Envelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionEvidence {
    pub policy_commit: String,
    pub workflow_run_id: String,
    pub workflow_run_attempt: u64,
    pub admitted_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerRegistry {
    issuer: String,
    keys: BTreeMap<String, String>,
    grants: Vec<Grant>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    kind: String,
    targets: Vec<String>,
}

#[derive(Debug, Error)]
pub enum AdmissionError {
    #[error("envelope exceeds {MAX_ENVELOPE_BYTES} bytes")]
    EnvelopeTooLarge,
    #[error("invalid event JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("unsupported event spec")]
    UnsupportedSpec,
    #[error("invalid identifier in field {0}")]
    InvalidIdentifier(&'static str),
    #[error("unsupported event kind")]
    UnsupportedKind,
    #[error("invalid payload for event kind: {0}")]
    InvalidPayload(String),
    #[error("invalid RFC3339 timestamp in field {0}")]
    InvalidTimestamp(&'static str),
    #[error("event issued too far in the future")]
    IssuedInFuture,
    #[error("event is older than the admission window")]
    EventTooOld,
    #[error("event expiry must be after issue time")]
    InvalidExpiryOrder,
    #[error("event TTL exceeds the admission limit")]
    ExcessiveTtl,
    #[error("event has expired")]
    Expired,
    #[error("producer registry is unavailable")]
    RegistryUnavailable,
    #[error("producer registry is invalid")]
    RegistryInvalid,
    #[error("producer registry issuer does not match event issuer")]
    RegistryIssuerMismatch,
    #[error("unknown producer key")]
    UnknownKey,
    #[error("issuer is not authorized for event kind and target")]
    Unauthorized,
    #[error("invalid producer public key")]
    InvalidPublicKey,
    #[error("invalid event signature encoding")]
    InvalidSignatureEncoding,
    #[error("event signature verification failed")]
    InvalidSignature,
    #[error("failed to canonicalize event")]
    Canonicalization,
}

pub fn admit(
    raw: &[u8],
    registry_dir: &Path,
    now: OffsetDateTime,
    metadata: AdmissionMetadata,
) -> Result<AdmissionRecord, AdmissionError> {
    if raw.len() > MAX_ENVELOPE_BYTES {
        return Err(AdmissionError::EnvelopeTooLarge);
    }

    let envelope: Envelope = serde_json::from_slice(raw)?;
    validate_envelope(&envelope, now)?;
    let registry = load_registry(registry_dir, &envelope.issuer)?;

    if registry.issuer != envelope.issuer {
        return Err(AdmissionError::RegistryIssuerMismatch);
    }

    let authorized = registry.grants.iter().any(|grant| {
        grant.kind == envelope.kind
            && grant
                .targets
                .iter()
                .any(|target| target == &envelope.target)
    });
    if !authorized {
        return Err(AdmissionError::Unauthorized);
    }

    let key_encoded = registry
        .keys
        .get(&envelope.key_id)
        .ok_or(AdmissionError::UnknownKey)?;
    let verifying_key = decode_public_key(key_encoded)?;
    let signature = decode_signature(&envelope.signature)?;
    let signed_bytes =
        canonical::unsigned_bytes(&envelope).map_err(|_| AdmissionError::Canonicalization)?;

    verifying_key
        .verify_strict(&signed_bytes, &signature)
        .map_err(|_| AdmissionError::InvalidSignature)?;

    let full_event =
        canonical::full_event_bytes(&envelope).map_err(|_| AdmissionError::Canonicalization)?;
    let event_digest = format!("sha256:{}", hex::encode(Sha256::digest(full_event)));

    Ok(AdmissionRecord {
        record: "grey-signal/admission/v1".to_owned(),
        admission: AdmissionEvidence {
            policy_commit: metadata.policy_commit,
            workflow_run_id: metadata.workflow_run_id,
            workflow_run_attempt: metadata.workflow_run_attempt,
            admitted_at: metadata
                .admitted_at
                .format(&Rfc3339)
                .map_err(|_| AdmissionError::Canonicalization)?,
        },
        event_digest,
        event: envelope,
    })
}

fn validate_envelope(envelope: &Envelope, now: OffsetDateTime) -> Result<(), AdmissionError> {
    if envelope.spec != EVENT_SPEC_V1 {
        return Err(AdmissionError::UnsupportedSpec);
    }

    for (field, value) in [
        ("id", envelope.id.as_str()),
        ("issuer", envelope.issuer.as_str()),
        ("key_id", envelope.key_id.as_str()),
        ("target", envelope.target.as_str()),
        ("correlation_id", envelope.correlation_id.as_str()),
    ] {
        if !valid_identifier(value) {
            return Err(AdmissionError::InvalidIdentifier(field));
        }
    }
    if let Some(causation_id) = &envelope.causation_id
        && !valid_identifier(causation_id)
    {
        return Err(AdmissionError::InvalidIdentifier("causation_id"));
    }

    validate_payload(envelope, now)?;

    let issued_at = parse_timestamp(&envelope.issued_at, "issued_at")?;
    let expires_at = parse_timestamp(&envelope.expires_at, "expires_at")?;

    if issued_at > now + Duration::seconds(MAX_CLOCK_SKEW_SECONDS) {
        return Err(AdmissionError::IssuedInFuture);
    }
    if issued_at < now - Duration::seconds(MAX_EVENT_AGE_SECONDS) {
        return Err(AdmissionError::EventTooOld);
    }
    if expires_at <= issued_at {
        return Err(AdmissionError::InvalidExpiryOrder);
    }
    if expires_at - issued_at > Duration::seconds(MAX_TTL_SECONDS) {
        return Err(AdmissionError::ExcessiveTtl);
    }
    if now > expires_at {
        return Err(AdmissionError::Expired);
    }

    Ok(())
}

fn validate_payload(envelope: &Envelope, now: OffsetDateTime) -> Result<(), AdmissionError> {
    match envelope.kind.as_str() {
        PROBE_REQUESTED_V1 => {
            let payload: ProbeRequestedPayload =
                serde_json::from_value(envelope.payload.clone())
                    .map_err(|error| AdmissionError::InvalidPayload(error.to_string()))?;
            if payload.nonce.is_empty() || payload.nonce.len() > 256 {
                return Err(AdmissionError::InvalidPayload(
                    "nonce must contain 1..=256 bytes".to_owned(),
                ));
            }
        }
        PROBE_COMPLETED_V1 => {
            let payload: ProbeCompletedPayload =
                serde_json::from_value(envelope.payload.clone())
                    .map_err(|error| AdmissionError::InvalidPayload(error.to_string()))?;
            if !valid_identifier(&payload.request_id) {
                return Err(AdmissionError::InvalidPayload(
                    "request_id is not a valid identifier".to_owned(),
                ));
            }
            if payload.nonce_digest.len() != 71 || !payload.nonce_digest.starts_with("sha256:") {
                return Err(AdmissionError::InvalidPayload(
                    "nonce_digest must be sha256:<64 lowercase hex characters>".to_owned(),
                ));
            }
            if !payload.nonce_digest[7..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                return Err(AdmissionError::InvalidPayload(
                    "nonce_digest must be lowercase hexadecimal".to_owned(),
                ));
            }
            if payload.consumer_version.is_empty() || payload.consumer_version.len() > 96 {
                return Err(AdmissionError::InvalidPayload(
                    "consumer_version must contain 1..=96 bytes".to_owned(),
                ));
            }
            let observed_at = parse_timestamp(&payload.observed_at, "payload.observed_at")?;
            if observed_at > now + Duration::seconds(MAX_CLOCK_SKEW_SECONDS) {
                return Err(AdmissionError::InvalidPayload(
                    "observed_at is too far in the future".to_owned(),
                ));
            }
        }
        _ => return Err(AdmissionError::UnsupportedKind),
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

fn parse_timestamp(value: &str, field: &'static str) -> Result<OffsetDateTime, AdmissionError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| AdmissionError::InvalidTimestamp(field))
}

fn load_registry(registry_dir: &Path, issuer: &str) -> Result<ProducerRegistry, AdmissionError> {
    let path = registry_dir.join(format!("{issuer}.json"));
    let bytes = fs::read(path).map_err(|_| AdmissionError::RegistryUnavailable)?;
    serde_json::from_slice(&bytes).map_err(|_| AdmissionError::RegistryInvalid)
}

fn decode_public_key(encoded: &str) -> Result<VerifyingKey, AdmissionError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| AdmissionError::InvalidPublicKey)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AdmissionError::InvalidPublicKey)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| AdmissionError::InvalidPublicKey)
}

fn decode_signature(encoded: &str) -> Result<Signature, AdmissionError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| AdmissionError::InvalidSignatureEncoding)?;
    let bytes: [u8; 64] = bytes
        .try_into()
        .map_err(|_| AdmissionError::InvalidSignatureEncoding)?;
    Ok(Signature::from_bytes(&bytes))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use tempfile::TempDir;
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};

    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::parse("2026-08-30T17:50:00Z", &Rfc3339).unwrap()
    }

    fn registry(signing_key: &SigningKey, target: &str) -> TempDir {
        let dir = tempfile::tempdir().unwrap();
        let public_key = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes());
        let registry = json!({
            "issuer": "p_test",
            "keys": { "k1": public_key },
            "grants": [
                { "kind": PROBE_REQUESTED_V1, "targets": [target] },
                { "kind": PROBE_COMPLETED_V1, "targets": [target] }
            ]
        });
        fs::write(
            dir.path().join("p_test.json"),
            serde_json::to_vec_pretty(&registry).unwrap(),
        )
        .unwrap();
        dir
    }

    fn signed_request(signing_key: &SigningKey, target: &str) -> Envelope {
        let mut envelope = Envelope {
            spec: EVENT_SPEC_V1.to_owned(),
            id: "evt_test_1".to_owned(),
            issuer: "p_test".to_owned(),
            key_id: "k1".to_owned(),
            kind: PROBE_REQUESTED_V1.to_owned(),
            target: target.to_owned(),
            issued_at: "2026-08-30T17:49:00Z".to_owned(),
            expires_at: "2026-08-30T17:55:00Z".to_owned(),
            correlation_id: "cor_test_1".to_owned(),
            causation_id: None,
            payload: json!({ "nonce": "opaque-nonce" }),
            signature: String::new(),
        };
        let bytes = canonical::unsigned_bytes(&envelope).unwrap();
        envelope.signature = URL_SAFE_NO_PAD.encode(signing_key.sign(&bytes).to_bytes());
        envelope
    }

    fn metadata() -> AdmissionMetadata {
        AdmissionMetadata {
            policy_commit: "abc123".to_owned(),
            workflow_run_id: "42".to_owned(),
            workflow_run_attempt: 1,
            admitted_at: now(),
        }
    }

    #[test]
    fn admits_valid_signed_request() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let registry = registry(&signing_key, "t_test");
        let envelope = signed_request(&signing_key, "t_test");
        let raw = serde_json::to_vec(&envelope).unwrap();

        let record = admit(&raw, registry.path(), now(), metadata()).unwrap();

        assert_eq!(record.event.id, "evt_test_1");
        assert!(record.event_digest.starts_with("sha256:"));
        assert_eq!(record.admission.policy_commit, "abc123");
    }

    #[test]
    fn rejects_tampered_payload() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let registry = registry(&signing_key, "t_test");
        let mut envelope = signed_request(&signing_key, "t_test");
        envelope.payload = json!({ "nonce": "tampered" });
        let raw = serde_json::to_vec(&envelope).unwrap();

        assert!(matches!(
            admit(&raw, registry.path(), now(), metadata()),
            Err(AdmissionError::InvalidSignature)
        ));
    }

    #[test]
    fn rejects_unauthorized_target() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let registry = registry(&signing_key, "t_allowed");
        let envelope = signed_request(&signing_key, "t_denied");
        let raw = serde_json::to_vec(&envelope).unwrap();

        assert!(matches!(
            admit(&raw, registry.path(), now(), metadata()),
            Err(AdmissionError::Unauthorized)
        ));
    }

    #[test]
    fn rejects_expired_event() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let registry = registry(&signing_key, "t_test");
        let mut envelope = signed_request(&signing_key, "t_test");
        envelope.issued_at = "2026-08-30T17:30:00Z".to_owned();
        envelope.expires_at = "2026-08-30T17:35:00Z".to_owned();
        let bytes = canonical::unsigned_bytes(&envelope).unwrap();
        envelope.signature = URL_SAFE_NO_PAD.encode(signing_key.sign(&bytes).to_bytes());
        let raw = serde_json::to_vec(&envelope).unwrap();

        assert!(matches!(
            admit(&raw, registry.path(), now(), metadata()),
            Err(AdmissionError::EventTooOld)
        ));
    }

    #[test]
    fn rejects_unknown_envelope_fields() {
        let raw = br#"{
            "spec":"grey-signal/event/v1",
            "id":"evt_1","issuer":"p_1","key_id":"k1",
            "kind":"probe.requested.v1","target":"t_1",
            "issued_at":"2026-08-30T17:49:00Z","expires_at":"2026-08-30T17:55:00Z",
            "correlation_id":"cor_1","causation_id":null,
            "payload":{"nonce":"x"},"signature":"x","surprise":true
        }"#;

        assert!(serde_json::from_slice::<Envelope>(raw).is_err());
    }

    #[test]
    fn rejects_unknown_payload_fields() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let registry = registry(&signing_key, "t_test");
        let mut envelope = signed_request(&signing_key, "t_test");
        envelope.payload = json!({ "nonce": "x", "command": "do-not-run-this" });
        let bytes = canonical::unsigned_bytes(&envelope).unwrap();
        envelope.signature = URL_SAFE_NO_PAD.encode(signing_key.sign(&bytes).to_bytes());
        let raw = serde_json::to_vec(&envelope).unwrap();

        assert!(matches!(
            admit(&raw, registry.path(), now(), metadata()),
            Err(AdmissionError::InvalidPayload(_))
        ));
    }

    #[test]
    fn rejects_oversized_envelope_before_parsing() {
        let raw = vec![b' '; MAX_ENVELOPE_BYTES + 1];
        let dir = tempfile::tempdir().unwrap();

        assert!(matches!(
            admit(&raw, dir.path(), now(), metadata()),
            Err(AdmissionError::EnvelopeTooLarge)
        ));
    }
}
