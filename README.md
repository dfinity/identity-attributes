# identity-attributes

Verify Internet Identity attribute bundles (a user's name, email, and SSO
domain) in your canister. The library adds the two methods the frontend calls
during sign-in, checks the bundle, and hands you the verified attributes.

Motoko:

```motoko
include IdentityAttributes({
  onVerified = func(caller, attrs) {
    profiles.add(caller, attrs)
  };
});
```

Rust:

```rust
#[identity_attributes]
fn consume_attributes(caller: Principal, attributes: IdentityAttributes) {
    PROFILES.with_borrow_mut(|profiles| profiles.insert(caller, attributes));
}
```

- **[motoko/](motoko/README.md)**: the Mops package, for a Motoko canister.
- **[rust/](rust/README.md)**: the crate, for a Rust canister.

Both read the same environment variables, run the same checks, and answer the
frontend with the same Candid types, so one frontend works with either. See
[CONTRIBUTING.md](CONTRIBUTING.md) and [Releasing.md](Releasing.md).

## License

Apache-2.0.
