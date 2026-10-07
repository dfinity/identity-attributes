# identity-attributes

Verify Internet Identity attribute bundles (a user's name, email, and SSO
domain) in a Rust canister. [../motoko](../motoko) is the same library in
Motoko, and both answer the frontend with the same Candid types.

## Install

```toml
[dependencies]
candid = "0.10"
ic-cdk = "0.20"
identity-attributes = "0.1"
```

Set the canister's environment variables in `icp.yaml`:

```yaml
canisters:
  - name: backend
    settings:
      environment_variables:
        trusted_attribute_signers: "rdmx6-jaaaa-aaaaa-aaadq-cai"  # II backend principal (required)
        frontend_origins:          "https://your-app.icp0.io"     # allowed origins, comma-separated (required)
        trusted_sso_domains:       "dfinity.org"                  # comma-separated, optional (omit to reject all sso:* keys)
```

## Backend

`endpoints!` adds the two sign-in methods the frontend calls, and runs your
function with the caller and their verified attributes. What it does with them
is yours to decide; this one keeps a profile per principal:

```rust
use candid::Principal;
use ic_cdk::query;
use identity_attributes::IdentityAttributes;
use std::cell::RefCell;
use std::collections::BTreeMap;

thread_local! {
    // On the heap to keep the example short: an upgrade clears it.
    static PROFILES: RefCell<BTreeMap<Principal, IdentityAttributes>> =
        const { RefCell::new(BTreeMap::new()) };
}

identity_attributes::endpoints!(|caller: Principal, attributes: IdentityAttributes| {
    PROFILES.with_borrow_mut(|profiles| profiles.insert(caller, attributes));
});

#[query]
fn get_profile(user_id: Principal) -> Option<IdentityAttributes> {
    PROFILES.with_borrow(|profiles| profiles.get(&user_id).cloned())
}

ic_cdk::export_candid!();
```

[examples/profile](examples/profile) is this canister, with its generated
`profile.did`.

## Frontend

The same as for the Motoko package: fetch a nonce from
`_internet_identity_sign_in_start`, request the attributes with it, and call
`_internet_identity_sign_in_finish` through an `AttributesIdentity`. See
[the Motoko README](../motoko/README.md#frontend).

## API

```rust
identity_attributes::endpoints!(on_verified);  // on_verified: FnOnce(Principal, IdentityAttributes)

// Added to your canister:
// _internet_identity_sign_in_start  : () -> (blob)
// _internet_identity_sign_in_finish : () -> (variant { ok; err : Error })

pub struct IdentityAttributes {
    pub name: Option<String>,
    pub email: Option<String>,
    pub sso: Option<String>,
}

pub enum Error {
    NoAttributes,
    MalformedCandid,
    MissingField(String),
    FrontendOriginsNotConfigured,
    FrontendOriginMismatch { expected: Vec<String>, got: String },
    Stale { age_ns: Nat },                                    // Candid: ageNs
    UnknownNonce,
    AmbiguousAttribute { field: String, sources: Vec<String> },
    UntrustedSsoSource { domain: String },
    MixedSsoSources { sso_keys: Vec<String>, other_keys: Vec<String> }, // Candid: ssoKeys, otherKeys
}
```

`sign_in_start()` and `sign_in_finish(on_verified)` are the functions behind
the two methods, for a canister that defines them itself.

Resolution rules:

- Each field resolves from at most one key. Two candidates return `AmbiguousAttribute`.
- A bundle's name and email come either from `sso:` keys or from unscoped and OpenID keys, never both: a mixed bundle is rejected with `MixedSsoSources`.
- An untrusted `sso:<domain>:*` key rejects the whole bundle with `UntrustedSsoSource`.
- Non-SSO email comes from `verified_email`. SSO email comes from `sso:<domain>:email`.

A call carrying a bundle traps when `trusted_attribute_signers` is unset or
does not list the bundle's signer.

Nonces are kept on the heap, so an upgrade clears them: a sign-in in flight
then fails with `UnknownNonce` and starts again. A nonce expires after five
minutes, and at most 4096 are held, the oldest evicted first.

## License

Apache-2.0.
