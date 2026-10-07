use candid::{CandidType, Deserialize, Nat};

/// What `on_verified` receives for a verified bundle.
///
/// `name` and `email` each come from at most one key in the bundle. `sso` is
/// the trusted SSO domain when they came from `sso:<domain>:*` keys, and
/// `None` otherwise.
///
/// For unscoped and OpenID sources, `email` comes only from a
/// `verified_email` key; the unverified `email` key never lands here. For an
/// SSO source it comes from `sso:<domain>:email`, which the organization's
/// identity provider asserts, and its own domain may be anything.
#[derive(CandidType, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct IdentityAttributes {
    pub name: Option<String>,
    pub email: Option<String>,
    pub sso: Option<String>,
}

/// Why `_internet_identity_sign_in_finish` refused a bundle. The Candid type
/// is the Motoko package's, so one frontend works with either backend.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// No bundle is attached to the call: the frontend did not wrap its
    /// identity in an `AttributesIdentity`.
    NoAttributes,
    /// The bundle is not a Candid-encoded ICRC-3 `Value::Map`.
    MalformedCandid,
    /// A required implicit field is missing.
    MissingField(String),
    /// The `frontend_origins` environment variable is unset or empty.
    FrontendOriginsNotConfigured,
    /// `implicit:origin` is not one of `frontend_origins`.
    FrontendOriginMismatch { expected: Vec<String>, got: String },
    /// `implicit:issued_at_timestamp_ns` is older than five minutes. The
    /// frontend fetches a fresh nonce and tries again.
    Stale {
        #[serde(rename = "ageNs")]
        age_ns: Nat,
    },
    /// The nonce was not issued by this canister, was already consumed, or
    /// expired.
    UnknownNonce,
    /// `name`, `email`, or `sso` (SSO keys from two domains) comes from more
    /// than one key.
    AmbiguousAttribute { field: String, sources: Vec<String> },
    /// The bundle has an `sso:<domain>:*` key for a domain not listed in
    /// `trusted_sso_domains`. The whole bundle is refused.
    UntrustedSsoSource { domain: String },
    /// The bundle mixes `sso:` keys with unscoped or OpenID keys for name or
    /// email.
    MixedSsoSources {
        #[serde(rename = "ssoKeys")]
        sso_keys: Vec<String>,
        #[serde(rename = "otherKeys")]
        other_keys: Vec<String>,
    },
}

/// What `_internet_identity_sign_in_finish` returns: Candid
/// `variant { ok; err : Error }`, like the Motoko package's `Result`.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum SignInResult {
    #[serde(rename = "ok")]
    Ok,
    #[serde(rename = "err")]
    Err(Error),
}
