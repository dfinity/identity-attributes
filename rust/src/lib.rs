//! Verify Internet Identity attribute bundles in a Rust canister.
//!
//! [`endpoints!`] adds the two methods the frontend calls, and runs your
//! function with the caller and their verified `{ name, email, sso }`:
//!
//! ```ignore
//! use candid::Principal;
//! use identity_attributes::IdentityAttributes;
//!
//! identity_attributes::endpoints!(|caller: Principal, attributes: IdentityAttributes| {
//!     // store `attributes` for `caller` however the app needs
//! });
//! ```
//!
//! Configured by environment variables: `trusted_attribute_signers` and
//! `frontend_origins` (both required, comma-separated), and optionally
//! `trusted_sso_domains`.

mod internal;
mod types;

use candid::Principal;
use ic_cdk::api::{
    env_var_name_exists, env_var_value, msg_caller, msg_caller_info_data, msg_caller_info_signer,
    time,
};
use ic_cdk::call::Call;
use internal::challenges::Challenges;
use internal::verify::{self, Config};
use std::cell::RefCell;
pub use types::{Error, IdentityAttributes, SignInResult};

thread_local! {
    /// Kept on the heap, so an upgrade clears it. A sign-in in flight then
    /// fails with `UnknownNonce` and starts again; a nonce lives five minutes,
    /// so nothing older was redeemable anyway.
    static CHALLENGES: RefCell<Challenges> = RefCell::new(Challenges::default());
}

/// Adds `_internet_identity_sign_in_start` and `_internet_identity_sign_in_finish`
/// to the canister. `on_verified` is called with the caller and their
/// [`IdentityAttributes`] for every bundle that passes verification.
#[macro_export]
macro_rules! endpoints {
    ($on_verified:expr) => {
        // Imported rather than named in the signature, and `ic_cdk` left
        // unqualified, because `ic_cdk::export_candid!` re-parses these
        // signatures and does not accept the leading `::` of `$crate`.
        use $crate::SignInResult as IiSignInResult;

        #[ic_cdk::update]
        async fn _internet_identity_sign_in_start() -> Vec<u8> {
            $crate::sign_in_start().await
        }

        #[ic_cdk::update]
        fn _internet_identity_sign_in_finish() -> IiSignInResult {
            $crate::sign_in_finish($on_verified)
        }
    };
}

/// Issues a single-use nonce for the frontend to put in its attribute
/// request. Called anonymously, before sign-in. Traps when the management
/// canister cannot supply randomness.
pub async fn sign_in_start() -> Vec<u8> {
    let nonce = Call::unbounded_wait(Principal::management_canister(), "raw_rand")
        .await
        .ok()
        .and_then(|reply| reply.candid::<Vec<u8>>().ok())
        .unwrap_or_else(|| ic_cdk::trap("raw_rand failed"));
    CHALLENGES.with_borrow_mut(|challenges| challenges.issue(nonce.clone(), time()));
    nonce
}

/// Verifies the bundle attached to this call and, when it passes, calls
/// `on_verified` with the caller and their attributes.
///
/// Traps when the call carries a bundle and `trusted_attribute_signers` is
/// unset, or does not list its signer.
pub fn sign_in_finish(on_verified: impl FnOnce(Principal, IdentityAttributes)) -> SignInResult {
    let bundle = trusted_bundle();
    let frontend_origins = env_var("frontend_origins");
    let trusted_sso_domains = env_var("trusted_sso_domains");
    let config = Config {
        frontend_origins: frontend_origins.as_deref(),
        trusted_sso_domains: trusted_sso_domains.as_deref(),
    };
    let verified = CHALLENGES.with_borrow_mut(|challenges| {
        verify::verify(bundle.as_deref(), &config, time(), challenges)
    });
    match verified {
        Ok(attributes) => {
            on_verified(msg_caller(), attributes);
            SignInResult::Ok
        }
        Err(error) => SignInResult::Err(error),
    }
}

/// The bundle attached to this call, or `None` when there is none.
fn trusted_bundle() -> Option<Vec<u8>> {
    let signer = msg_caller_info_signer()?;
    let trusted = env_var("trusted_attribute_signers").unwrap_or_else(|| {
        ic_cdk::trap("trusted_attribute_signers environment variable is not set")
    });
    let listed = trusted.split(',').any(|entry| {
        Principal::from_text(entry).unwrap_or_else(|_| {
            ic_cdk::trap(format!(
                "trusted_attribute_signers: invalid principal {entry}"
            ))
        }) == signer
    });
    if !listed {
        ic_cdk::trap("untrusted attribute signer");
    }
    Some(msg_caller_info_data())
}

fn env_var(name: &str) -> Option<String> {
    env_var_name_exists(name).then(|| env_var_value(name))
}
