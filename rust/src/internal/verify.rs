use crate::internal::attributes::{as_identity_attributes, Attributes};
use crate::internal::challenges::Challenges;
use crate::internal::value;
use crate::types::{Error, IdentityAttributes};
use candid::Nat;

/// How old a bundle may be, from `implicit:issued_at_timestamp_ns`.
pub(crate) const MAX_AGE_NS: u64 = 5 * 60 * 1_000_000_000;

/// The canister's configuration, read from its environment variables.
pub(crate) struct Config<'a> {
    pub(crate) frontend_origins: Option<&'a str>,
    pub(crate) trusted_sso_domains: Option<&'a str>,
}

/// A comma-separated list with empty entries dropped. Entries are not trimmed:
/// an operator's typo should fail to match, not be silently corrected.
fn parse_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
        .collect()
}

/// Checks a bundle from a trusted signer, in order: it is attached, it decodes
/// to a map, `frontend_origins` is set and holds `implicit:origin`, the bundle
/// is fresh, its nonce is one this canister issued, and its name and email
/// come from one kind of source. `bundle` is `None` when the call carries none.
pub(crate) fn verify(
    bundle: Option<&[u8]>,
    config: &Config,
    now: u64,
    challenges: &mut Challenges,
) -> Result<IdentityAttributes, Error> {
    let bundle = bundle.ok_or(Error::NoAttributes)?;
    let attributes = value::decode(bundle)
        .and_then(Attributes::from_value)
        .ok_or(Error::MalformedCandid)?;

    let frontend_origins = config
        .frontend_origins
        .map(parse_list)
        .filter(|origins| !origins.is_empty())
        .ok_or(Error::FrontendOriginsNotConfigured)?;

    let origin = attributes
        .text("implicit:origin")
        .ok_or_else(|| Error::MissingField("implicit:origin".into()))?;
    if !frontend_origins.iter().any(|o| o == origin) {
        return Err(Error::FrontendOriginMismatch {
            expected: frontend_origins,
            got: origin.to_string(),
        });
    }

    let issued_at = attributes
        .nat("implicit:issued_at_timestamp_ns")
        .ok_or_else(|| Error::MissingField("implicit:issued_at_timestamp_ns".into()))?;
    let now = Nat::from(now);
    if &now >= issued_at {
        let age = now.clone() - issued_at.clone();
        if age > MAX_AGE_NS {
            return Err(Error::Stale { age_ns: age });
        }
    }

    let nonce = attributes
        .blob("implicit:nonce")
        .ok_or_else(|| Error::MissingField("implicit:nonce".into()))?;
    let now = u64::try_from(now.0).unwrap_or(u64::MAX);
    if !challenges.consume(nonce, now) {
        return Err(Error::UnknownNonce);
    }

    let trusted_sso_domains = config
        .trusted_sso_domains
        .map(parse_list)
        .unwrap_or_default();
    as_identity_attributes(&attributes, &trusted_sso_domains)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::value::Value;

    const NOW: u64 = 1_800_000_000_000_000_000;
    const ORIGIN: &str = "https://app.example.com";
    const NONCE: &[u8] = &[7; 32];

    const CONFIGURED: Config = Config {
        frontend_origins: Some("https://other.example.com,https://app.example.com"),
        trusted_sso_domains: None,
    };

    fn entries() -> Vec<(String, Value)> {
        vec![
            ("implicit:origin".into(), Value::Text(ORIGIN.into())),
            (
                "implicit:issued_at_timestamp_ns".into(),
                Value::Nat(Nat::from(NOW)),
            ),
            ("implicit:nonce".into(), Value::Blob(NONCE.to_vec())),
            ("name".into(), Value::Text("Alice".into())),
            (
                "verified_email".into(),
                Value::Text("alice@example.com".into()),
            ),
        ]
    }

    fn encode(entries: Vec<(String, Value)>) -> Vec<u8> {
        candid::encode_one(Value::Map(entries)).unwrap()
    }

    fn without(key: &str) -> Vec<u8> {
        encode(entries().into_iter().filter(|(k, _)| k != key).collect())
    }

    fn with(key: &str, value: Value) -> Vec<u8> {
        encode(
            entries()
                .into_iter()
                .map(|(k, v)| if k == key { (k, value.clone()) } else { (k, v) })
                .collect(),
        )
    }

    fn issued() -> Challenges {
        let mut challenges = Challenges::default();
        challenges.issue(NONCE.to_vec(), NOW);
        challenges
    }

    fn run(bundle: &[u8], config: &Config, now: u64) -> Result<IdentityAttributes, Error> {
        verify(Some(bundle), config, now, &mut issued())
    }

    #[test]
    fn a_valid_bundle_resolves_and_consumes_its_nonce() {
        let mut challenges = issued();
        let bundle = encode(entries());
        assert_eq!(
            verify(Some(&bundle), &CONFIGURED, NOW, &mut challenges),
            Ok(IdentityAttributes {
                name: Some("Alice".into()),
                email: Some("alice@example.com".into()),
                sso: None,
            })
        );
        assert_eq!(
            verify(Some(&bundle), &CONFIGURED, NOW, &mut challenges),
            Err(Error::UnknownNonce)
        );
    }

    #[test]
    fn no_bundle() {
        assert_eq!(
            verify(None, &CONFIGURED, NOW, &mut issued()),
            Err(Error::NoAttributes)
        );
    }

    #[test]
    fn a_bundle_that_is_not_a_map() {
        assert_eq!(
            run(b"garbage", &CONFIGURED, NOW),
            Err(Error::MalformedCandid)
        );
        let text = candid::encode_one(Value::Text("x".into())).unwrap();
        assert_eq!(run(&text, &CONFIGURED, NOW), Err(Error::MalformedCandid));
    }

    #[test]
    fn frontend_origins_unset_or_empty() {
        for frontend_origins in [None, Some(""), Some(",,")] {
            let config = Config {
                frontend_origins,
                trusted_sso_domains: None,
            };
            assert_eq!(
                run(&encode(entries()), &config, NOW),
                Err(Error::FrontendOriginsNotConfigured)
            );
        }
    }

    #[test]
    fn an_origin_outside_frontend_origins() {
        assert_eq!(
            run(
                &with("implicit:origin", Value::Text("https://evil.com".into())),
                &CONFIGURED,
                NOW
            ),
            Err(Error::FrontendOriginMismatch {
                expected: vec!["https://other.example.com".into(), ORIGIN.into()],
                got: "https://evil.com".into(),
            })
        );
        let padded = Config {
            frontend_origins: Some(" https://app.example.com"),
            trusted_sso_domains: None,
        };
        assert!(matches!(
            run(&encode(entries()), &padded, NOW),
            Err(Error::FrontendOriginMismatch { .. })
        ));
    }

    #[test]
    fn missing_implicit_fields() {
        for key in [
            "implicit:origin",
            "implicit:issued_at_timestamp_ns",
            "implicit:nonce",
        ] {
            assert_eq!(
                run(&without(key), &CONFIGURED, NOW),
                Err(Error::MissingField(key.into())),
                "{key}"
            );
        }
    }

    #[test]
    fn a_stale_bundle() {
        assert!(run(&encode(entries()), &CONFIGURED, NOW + MAX_AGE_NS).is_ok());
        assert_eq!(
            run(&encode(entries()), &CONFIGURED, NOW + MAX_AGE_NS + 1),
            Err(Error::Stale {
                age_ns: Nat::from(MAX_AGE_NS + 1)
            })
        );
    }

    #[test]
    fn a_bundle_from_the_future_is_not_stale() {
        let ahead = with(
            "implicit:issued_at_timestamp_ns",
            Value::Nat(Nat::from(NOW + 1_000)),
        );
        assert!(run(&ahead, &CONFIGURED, NOW).is_ok());
    }

    #[test]
    fn a_nonce_this_canister_never_issued() {
        assert_eq!(
            run(
                &with("implicit:nonce", Value::Blob(vec![1; 32])),
                &CONFIGURED,
                NOW
            ),
            Err(Error::UnknownNonce)
        );
    }

    #[test]
    fn trusted_sso_domains_come_from_the_config() {
        let sso = encode(
            entries()
                .into_iter()
                .filter(|(k, _)| k.starts_with("implicit:"))
                .chain([(
                    "sso:acme.com:email".into(),
                    Value::Text("a@acme.com".into()),
                )])
                .collect(),
        );
        assert_eq!(
            run(&sso, &CONFIGURED, NOW),
            Err(Error::UntrustedSsoSource {
                domain: "acme.com".into()
            })
        );
        let config = Config {
            frontend_origins: CONFIGURED.frontend_origins,
            trusted_sso_domains: Some("dfinity.org,acme.com"),
        };
        assert_eq!(
            run(&sso, &config, NOW),
            Ok(IdentityAttributes {
                name: None,
                email: Some("a@acme.com".into()),
                sso: Some("acme.com".into()),
            })
        );
    }
}
