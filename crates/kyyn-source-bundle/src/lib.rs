//! JSON-bundle evidence helpers shared by first-party source components.

use serde::Serialize;
use sha2::Digest as _;

pub fn canonical_record_sha256(record: &impl Serialize) -> Result<String, serde_json::Error> {
    let canonical = serde_json::to_vec(record)?;
    Ok(format!("{:x}", sha2::Sha256::digest(canonical)))
}

/// Normalize a provider identity field into the lowercase `id` locator key
/// Kyyn searches recursively inside JSON bundles.
pub fn ensure_locator_id(
    record: &mut serde_json::Value,
    id_field: &str,
    fallback: impl Into<String>,
) -> Result<String, String> {
    let id = record
        .get(id_field)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| fallback.into());
    let object = record
        .as_object_mut()
        .ok_or_else(|| "bundle record is not a JSON object".to_string())?;
    object.insert("id".into(), serde_json::Value::String(id.clone()));
    Ok(id)
}

pub fn located_record_sha256(
    bundle: &[u8],
    locator: &str,
) -> Result<Option<String>, serde_json::Error> {
    let bundle: serde_json::Value = serde_json::from_slice(bundle)?;
    find_record(&bundle, locator)
        .map(canonical_record_sha256)
        .transpose()
}

fn find_record<'a>(value: &'a serde_json::Value, locator: &str) -> Option<&'a serde_json::Value> {
    match value {
        serde_json::Value::Array(values) => {
            values.iter().find_map(|value| find_record(value, locator))
        }
        serde_json::Value::Object(fields) => {
            if fields.get("id").and_then(serde_json::Value::as_str) == Some(locator) {
                return Some(value);
            }
            fields
                .values()
                .find_map(|value| find_record(value, locator))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{canonical_record_sha256, ensure_locator_id, located_record_sha256};
    use serde_json::json;

    #[test]
    fn flat_salesforce_bundle_round_trips_the_engine_locator_hash() {
        let mut record = json!({
            "attributes": {"type": "Opportunity"},
            "Id": "006-test",
            "Name": "Migration",
            "StageName": "Closed Won"
        });
        assert_eq!(
            ensure_locator_id(&mut record, "Id", "row-0").unwrap(),
            "006-test"
        );
        let bundle = serde_json::to_vec_pretty(&vec![record.clone()]).unwrap();
        assert_eq!(
            located_record_sha256(&bundle, "006-test").unwrap(),
            Some(canonical_record_sha256(&record).unwrap())
        );
    }

    #[test]
    fn nested_graph_chat_bundle_round_trips_the_engine_locator_hash() {
        let message = json!({
            "id": "message-2",
            "createdDateTime": "2026-07-25T12:00:00Z",
            "from": "Ada",
            "body": "ship it"
        });
        let bundle = serde_json::to_vec_pretty(&vec![json!({
            "id": "chat-1",
            "topic": "Source migration",
            "messages": [{"id": "message-1", "body": "hello"}, message.clone()]
        })])
        .unwrap();
        assert_eq!(
            located_record_sha256(&bundle, "message-2").unwrap(),
            Some(canonical_record_sha256(&message).unwrap())
        );
        assert_eq!(located_record_sha256(&bundle, "missing").unwrap(), None);
    }
}
