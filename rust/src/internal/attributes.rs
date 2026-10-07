use crate::internal::value::Value;
use crate::types::{Error, IdentityAttributes};
use candid::Nat;

/// A decoded bundle: the entries of its top-level map.
pub(crate) struct Attributes(Vec<(String, Value)>);

impl Attributes {
    /// `None` unless `value` is a map.
    pub(crate) fn from_value(value: Value) -> Option<Self> {
        match value {
            Value::Map(entries) => Some(Self(entries)),
            _ => None,
        }
    }

    pub(crate) fn has(&self, key: &str) -> bool {
        self.0.iter().any(|(k, _)| k == key)
    }

    pub(crate) fn text(&self, key: &str) -> Option<&str> {
        self.0.iter().find_map(|(k, v)| match v {
            Value::Text(text) if k == key => Some(text.as_str()),
            _ => None,
        })
    }

    pub(crate) fn nat(&self, key: &str) -> Option<&Nat> {
        self.0.iter().find_map(|(k, v)| match v {
            Value::Nat(nat) if k == key => Some(nat),
            _ => None,
        })
    }

    pub(crate) fn blob(&self, key: &str) -> Option<&[u8]> {
        self.0.iter().find_map(|(k, v)| match v {
            Value::Blob(blob) if k == key => Some(blob.as_slice()),
            _ => None,
        })
    }
}

/// The unscoped prefix, then one per OpenID provider. `{tid}` is a literal
/// part of the Microsoft key, not a placeholder for a tenant id.
const NON_SSO_PREFIXES: [&str; 4] = [
    "",
    "openid:https://accounts.google.com:",
    "openid:https://appleid.apple.com:",
    "openid:https://login.microsoftonline.com/{tid}/v2.0:",
];

/// `(domain, suffix)` for a key shaped exactly `sso:<domain>:<suffix>`.
fn parse_sso_key(key: &str) -> Option<(&str, &str)> {
    let mut parts = key.split(':');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("sso"), Some(domain), Some(suffix), None) => Some((domain, suffix)),
        _ => None,
    }
}

fn resolve_non_sso_field(
    attributes: &Attributes,
    field: &str,
    suffix: &str,
) -> Result<Option<String>, Error> {
    let mut value = None;
    let mut sources = Vec::new();
    for prefix in NON_SSO_PREFIXES {
        let key = format!("{prefix}{suffix}");
        if let Some(text) = attributes.text(&key) {
            value = Some(text.to_string());
            sources.push(key);
        }
    }
    if sources.len() > 1 {
        return Err(Error::AmbiguousAttribute {
            field: field.to_string(),
            sources,
        });
    }
    Ok(value)
}

fn non_sso_name_or_email_keys(attributes: &Attributes) -> Vec<String> {
    NON_SSO_PREFIXES
        .iter()
        .flat_map(|prefix| ["name", "verified_email"].map(|suffix| format!("{prefix}{suffix}")))
        .filter(|key| attributes.has(key))
        .collect()
}

struct SsoSource {
    domain: String,
    key: String,
    value: String,
}

/// Resolves `{ name, email, sso }` from a bundle. An empty
/// `trusted_sso_domains` refuses every `sso:` key.
pub(crate) fn as_identity_attributes(
    attributes: &Attributes,
    trusted_sso_domains: &[String],
) -> Result<IdentityAttributes, Error> {
    let mut untrusted_domain = None;
    let mut sso_names = Vec::new();
    let mut sso_emails = Vec::new();

    for (key, value) in &attributes.0 {
        let (Some((domain, suffix)), Value::Text(value)) = (parse_sso_key(key), value) else {
            continue;
        };
        if !trusted_sso_domains.iter().any(|d| d == domain) {
            untrusted_domain.get_or_insert_with(|| domain.to_string());
            continue;
        }
        let source = SsoSource {
            domain: domain.to_string(),
            key: key.clone(),
            value: value.clone(),
        };
        match suffix {
            "name" => sso_names.push(source),
            "email" => sso_emails.push(source),
            _ => {}
        }
    }

    if let Some(domain) = untrusted_domain {
        return Err(Error::UntrustedSsoSource { domain });
    }

    if sso_names.is_empty() && sso_emails.is_empty() {
        return Ok(IdentityAttributes {
            name: resolve_non_sso_field(attributes, "name", "name")?,
            email: resolve_non_sso_field(attributes, "email", "verified_email")?,
            sso: None,
        });
    }

    // An SSO bundle never also carries another source: one identity provider
    // must not be able to shadow another.
    let other_keys = non_sso_name_or_email_keys(attributes);
    if !other_keys.is_empty() {
        return Err(Error::MixedSsoSources {
            sso_keys: sso_names
                .iter()
                .chain(&sso_emails)
                .map(|s| s.key.clone())
                .collect(),
            other_keys,
        });
    }

    // Name and email from two organizations would splice two providers' claims.
    let mut domain: Option<&str> = None;
    let mut domain_sources = Vec::new();
    for source in sso_names.iter().chain(&sso_emails) {
        domain_sources.push(source.key.clone());
        match domain {
            None => domain = Some(&source.domain),
            Some(first) if first != source.domain => {
                return Err(Error::AmbiguousAttribute {
                    field: "sso".to_string(),
                    sources: domain_sources,
                });
            }
            Some(_) => {}
        }
    }

    for (field, sources) in [("name", &sso_names), ("email", &sso_emails)] {
        if sources.len() > 1 {
            return Err(Error::AmbiguousAttribute {
                field: field.to_string(),
                sources: sources.iter().map(|s| s.key.clone()).collect(),
            });
        }
    }

    Ok(IdentityAttributes {
        name: sso_names.first().map(|s| s.value.clone()),
        email: sso_emails.first().map(|s| s.value.clone()),
        sso: domain.map(str::to_string),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(entries: &[(&str, &str)]) -> Attributes {
        Attributes(
            entries
                .iter()
                .map(|(k, v)| (k.to_string(), Value::Text(v.to_string())))
                .collect(),
        )
    }

    fn trusted(domains: &[&str]) -> Vec<String> {
        domains.iter().map(|d| d.to_string()).collect()
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    fn ok(
        name: Option<&str>,
        email: Option<&str>,
        sso: Option<&str>,
    ) -> Result<IdentityAttributes, Error> {
        Ok(IdentityAttributes {
            name: name.map(str::to_string),
            email: email.map(str::to_string),
            sso: sso.map(str::to_string),
        })
    }

    #[test]
    fn unscoped_name_and_verified_email_ignore_the_unverified_email() {
        let attributes = bundle(&[
            ("name", "Alice"),
            ("email", "alice@example.com"),
            ("verified_email", "alice@verified.com"),
        ]);
        assert_eq!(
            as_identity_attributes(&attributes, &[]),
            ok(Some("Alice"), Some("alice@verified.com"), None)
        );
    }

    #[test]
    fn one_openid_scope() {
        let attributes = bundle(&[
            ("openid:https://accounts.google.com:name", "Alice G"),
            (
                "openid:https://accounts.google.com:email",
                "alice@gmail.com",
            ),
            (
                "openid:https://accounts.google.com:verified_email",
                "alice@gmail.com",
            ),
        ]);
        assert_eq!(
            as_identity_attributes(&attributes, &[]),
            ok(Some("Alice G"), Some("alice@gmail.com"), None)
        );
    }

    #[test]
    fn no_source_resolves_to_none() {
        let attributes = bundle(&[("email", "alice@example.com")]);
        assert_eq!(
            as_identity_attributes(&attributes, &[]),
            ok(None, None, None)
        );

        let apple = bundle(&[("openid:https://appleid.apple.com:email", "alice@icloud.com")]);
        assert_eq!(as_identity_attributes(&apple, &[]), ok(None, None, None));
    }

    #[test]
    fn a_name_from_two_sources_is_ambiguous() {
        let attributes = bundle(&[
            ("name", "Alice"),
            ("openid:https://accounts.google.com:name", "Alice G"),
            ("verified_email", "alice@verified.com"),
        ]);
        assert_eq!(
            as_identity_attributes(&attributes, &[]),
            Err(Error::AmbiguousAttribute {
                field: "name".into(),
                sources: strings(&["name", "openid:https://accounts.google.com:name"]),
            })
        );
    }

    #[test]
    fn an_email_from_two_providers_is_ambiguous() {
        let attributes = bundle(&[
            (
                "openid:https://accounts.google.com:verified_email",
                "alice@gmail.com",
            ),
            (
                "openid:https://appleid.apple.com:verified_email",
                "alice@icloud.com",
            ),
        ]);
        assert_eq!(
            as_identity_attributes(&attributes, &[]),
            Err(Error::AmbiguousAttribute {
                field: "email".into(),
                sources: strings(&[
                    "openid:https://accounts.google.com:verified_email",
                    "openid:https://appleid.apple.com:verified_email",
                ]),
            })
        );
    }

    #[test]
    fn sso_name_and_email_from_a_trusted_domain() {
        let attributes = bundle(&[
            ("sso:dfinity.org:name", "Alice D"),
            ("sso:dfinity.org:email", "alice@dfinity.org"),
        ]);
        assert_eq!(
            as_identity_attributes(&attributes, &trusted(&["dfinity.org"])),
            ok(
                Some("Alice D"),
                Some("alice@dfinity.org"),
                Some("dfinity.org")
            )
        );
    }

    #[test]
    fn an_sso_email_may_be_on_any_domain() {
        let attributes = bundle(&[
            ("sso:dfinity.org:name", "Bob"),
            ("sso:dfinity.org:email", "bob@externalcontractor.com"),
        ]);
        assert_eq!(
            as_identity_attributes(&attributes, &trusted(&["dfinity.org"])),
            ok(
                Some("Bob"),
                Some("bob@externalcontractor.com"),
                Some("dfinity.org")
            )
        );
    }

    #[test]
    fn an_untrusted_sso_domain_refuses_the_bundle() {
        let attributes = bundle(&[
            ("sso:evil.com:name", "Mallory"),
            ("sso:evil.com:email", "m@evil.com"),
        ]);
        assert_eq!(
            as_identity_attributes(&attributes, &trusted(&["dfinity.org"])),
            Err(Error::UntrustedSsoSource {
                domain: "evil.com".into()
            })
        );
    }

    #[test]
    fn no_trusted_domain_refuses_every_sso_key() {
        let attributes = bundle(&[("sso:dfinity.org:name", "Alice")]);
        assert_eq!(
            as_identity_attributes(&attributes, &[]),
            Err(Error::UntrustedSsoSource {
                domain: "dfinity.org".into()
            })
        );
    }

    #[test]
    fn sso_with_an_unscoped_key_is_mixed() {
        let attributes = bundle(&[
            ("sso:dfinity.org:name", "Alice"),
            ("verified_email", "alice@elsewhere.com"),
        ]);
        assert_eq!(
            as_identity_attributes(&attributes, &trusted(&["dfinity.org"])),
            Err(Error::MixedSsoSources {
                sso_keys: strings(&["sso:dfinity.org:name"]),
                other_keys: strings(&["verified_email"]),
            })
        );
    }

    #[test]
    fn sso_with_an_openid_key_is_mixed() {
        let attributes = bundle(&[
            ("sso:dfinity.org:name", "Alice"),
            (
                "openid:https://accounts.google.com:verified_email",
                "alice@gmail.com",
            ),
        ]);
        assert_eq!(
            as_identity_attributes(&attributes, &trusted(&["dfinity.org"])),
            Err(Error::MixedSsoSources {
                sso_keys: strings(&["sso:dfinity.org:name"]),
                other_keys: strings(&["openid:https://accounts.google.com:verified_email"]),
            })
        );
    }

    #[test]
    fn two_sso_domains_are_ambiguous() {
        let attributes = bundle(&[
            ("sso:dfinity.org:name", "Alice"),
            ("sso:acme.com:email", "alice@acme.com"),
        ]);
        assert_eq!(
            as_identity_attributes(&attributes, &trusted(&["dfinity.org", "acme.com"])),
            Err(Error::AmbiguousAttribute {
                field: "sso".into(),
                sources: strings(&["sso:dfinity.org:name", "sso:acme.com:email"]),
            })
        );
    }

    #[test]
    fn two_sso_names_for_one_domain_are_ambiguous() {
        let attributes = bundle(&[
            ("sso:dfinity.org:name", "Alice"),
            ("sso:dfinity.org:name", "Bob"),
        ]);
        assert_eq!(
            as_identity_attributes(&attributes, &trusted(&["dfinity.org"])),
            Err(Error::AmbiguousAttribute {
                field: "name".into(),
                sources: strings(&["sso:dfinity.org:name", "sso:dfinity.org:name"]),
            })
        );
    }

    #[test]
    fn an_sso_name_alone_leaves_the_email_empty() {
        let attributes = bundle(&[("sso:dfinity.org:name", "Alice")]);
        assert_eq!(
            as_identity_attributes(&attributes, &trusted(&["dfinity.org"])),
            ok(Some("Alice"), None, Some("dfinity.org"))
        );
    }

    #[test]
    fn a_key_that_is_not_exactly_three_parts_is_not_sso() {
        assert_eq!(
            parse_sso_key("sso:dfinity.org:name"),
            Some(("dfinity.org", "name"))
        );
        assert_eq!(parse_sso_key("sso:dfinity.org"), None);
        assert_eq!(parse_sso_key("sso:a:b:c"), None);
        assert_eq!(parse_sso_key("openid:dfinity.org:name"), None);
    }
}
