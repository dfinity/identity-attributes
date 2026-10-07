//! A canister that keeps each user's verified name and email.

use candid::Principal;
use ic_cdk::api::msg_caller;
use ic_cdk::query;
use identity_attributes::IdentityAttributes;
use std::cell::RefCell;
use std::collections::BTreeMap;

thread_local! {
    static PROFILES: RefCell<BTreeMap<Principal, IdentityAttributes>> =
        const { RefCell::new(BTreeMap::new()) };
}

identity_attributes::endpoints!(|caller: Principal, attributes: IdentityAttributes| {
    PROFILES.with_borrow_mut(|profiles| profiles.insert(caller, attributes));
});

#[query]
fn get_profile() -> Option<IdentityAttributes> {
    PROFILES.with_borrow(|profiles| profiles.get(&msg_caller()).cloned())
}

ic_cdk::export_candid!();

#[cfg(test)]
mod tests {
    /// Writes `profile.did` beside the crate, so the interface in the repo is
    /// the one the code exports rather than one somebody hand-edited.
    #[test]
    fn candid_is_up_to_date() {
        let exported = super::__export_service();
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("profile.did");

        if std::env::var("BLESS").is_ok() {
            std::fs::write(&path, &exported).expect("writing profile.did");
        }

        let committed = std::fs::read_to_string(&path).expect("profile.did should exist");
        assert_eq!(
            committed.trim(),
            exported.trim(),
            "profile.did is stale — rerun with BLESS=1"
        );
    }
}
