use candid::{CandidType, Deserialize, Int, Nat};

/// The ICRC-3 `Value` tree Internet Identity signs attribute bundles as.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Value {
    Nat(Nat),
    Int(Int),
    Blob(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(String, Value)>),
}

/// `None` when the bytes are not a Candid-encoded `Value`.
pub(crate) fn decode(bytes: &[u8]) -> Option<Value> {
    candid::decode_one(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::attributes::{as_identity_attributes, Attributes};
    use serde_json::Value as Json;

    fn vectors() -> Json {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../test-vectors/icrc3-test-vectors.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).expect("test vectors")).unwrap()
    }

    #[test]
    fn decodes_every_vector_as_a_map_with_the_implicit_fields() {
        let vectors = vectors();
        let origin = vectors["origin"].as_str().unwrap();
        let cases = vectors["vectors"].as_array().unwrap();
        assert_eq!(cases.len(), 10);

        for case in cases {
            let label = case["label"].as_str().unwrap();
            let bytes = hex::decode(case["message_hex"].as_str().unwrap()).unwrap();
            let value = decode(&bytes).unwrap_or_else(|| panic!("{label}: not a Value"));
            let attributes = Attributes::from_value(value).expect(label);

            assert_eq!(attributes.text("implicit:origin"), Some(origin), "{label}");
            assert!(
                attributes.nat("implicit:issued_at_timestamp_ns").is_some(),
                "{label}"
            );
            assert!(attributes.blob("implicit:nonce").is_some(), "{label}");
        }
    }

    #[test]
    fn resolves_the_vectors_name_and_verified_email_keys() {
        let vectors = vectors();
        let name = vectors["name"].as_str().unwrap();

        for case in vectors["vectors"].as_array().unwrap() {
            let label = case["label"].as_str().unwrap();
            let bytes = hex::decode(case["message_hex"].as_str().unwrap()).unwrap();
            let attributes = Attributes::from_value(decode(&bytes).unwrap()).unwrap();
            let resolved = as_identity_attributes(&attributes, &[]).expect(label);

            // The vectors carry `email`, never `verified_email`, so no email
            // resolves; a name resolves whenever the bundle carries one.
            assert_eq!(resolved.email, None, "{label}");
            assert_eq!(resolved.sso, None, "{label}");
            let has_name =
                attributes.has("name") || attributes.has("openid:https://accounts.google.com:name");
            assert_eq!(
                resolved.name.as_deref(),
                has_name.then_some(name),
                "{label}"
            );
        }
    }

    #[test]
    fn rejects_bytes_that_are_not_a_value() {
        assert_eq!(decode(b"not candid"), None);
        assert_eq!(decode(&candid::encode_one("text").unwrap()), None);
    }
}
