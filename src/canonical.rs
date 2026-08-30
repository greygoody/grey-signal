use std::collections::BTreeMap;

use serde_json::Value;

use crate::Envelope;

pub fn unsigned_bytes(envelope: &Envelope) -> Result<Vec<u8>, serde_json::Error> {
    let mut value = serde_json::to_value(envelope)?;
    if let Value::Object(ref mut object) = value {
        object.remove("signature");
    }
    serde_json::to_vec(&sort_value(value))
}

pub fn full_event_bytes(envelope: &Envelope) -> Result<Vec<u8>, serde_json::Error> {
    let value = serde_json::to_value(envelope)?;
    serde_json::to_vec(&sort_value(value))
}

fn sort_value(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let sorted: BTreeMap<String, Value> = object
                .into_iter()
                .map(|(key, value)| (key, sort_value(value)))
                .collect();
            serde_json::to_value(sorted).expect("BTreeMap<String, Value> is serializable")
        }
        Value::Array(values) => Value::Array(values.into_iter().map(sort_value).collect()),
        other => other,
    }
}
