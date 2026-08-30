use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const EVENT_SPEC_V1: &str = "grey-signal/event/v1";
pub const PROBE_REQUESTED_V1: &str = "probe.requested.v1";
pub const PROBE_COMPLETED_V1: &str = "probe.completed.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub spec: String,
    pub id: String,
    pub issuer: String,
    pub key_id: String,
    pub kind: String,
    pub target: String,
    pub issued_at: String,
    pub expires_at: String,
    pub correlation_id: String,
    pub causation_id: Option<String>,
    pub payload: Value,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeRequestedPayload {
    pub nonce: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeCompletedPayload {
    pub request_id: String,
    pub nonce_digest: String,
    pub consumer_version: String,
    pub observed_at: String,
}
