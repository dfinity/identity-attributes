# Releasing

The two packages version and publish independently, each from its own tag:
`motoko-vX.Y.Z` publishes `motoko/` to [mops.one](https://mops.one), and
`rust-vX.Y.Z` publishes `rust/` to [crates.io](https://crates.io).

The Rust package is two crates released together at one version:
`identity-attributes` and `identity-attributes-macros`, which holds the
`#[identity_attributes]` attribute and is published first. The code the
attribute generates calls into `identity-attributes`, so it depends on the
macros by exact version.

1. Bump `version` in `motoko/mops.toml`, or for Rust in `rust/Cargo.toml`,
   `rust/macros/Cargo.toml`, and the `=X.Y.Z` macros requirement in
   `rust/Cargo.toml`.
2. Update the version in that package's install snippet in its `README.md`.
3. In that package's `Changelog.md`, rename `## Next` to `## X.Y.Z` and add a
   fresh empty `## Next` at the top.
4. Open a PR with those changes; merge once green.
5. From `main`, tag the merge commit:

   ```
   git tag motoko-vX.Y.Z   # or rust-vX.Y.Z
   git push origin motoko-vX.Y.Z   # or rust-vX.Y.Z
   ```

6. Check the publish workflow run to confirm it succeeded.

The Mops workflow needs the secret `MOPS_IDENTITY_PEM`, a publisher identity
exported with `mops user export`, scoped to the `release` environment under
**Settings → Environments**. That environment accepts the `motoko-v*.*.*` and
`rust-v*.*.*` tags.

The crates.io workflow stores no token: it uses
[trusted publishing](https://crates.io/docs/trusted-publishing), so each run
gets a short-lived token for the crates that trust it. Each crate needs a
trusted publisher on crates.io (the crate's **Settings → Trusted Publishing**):
owner `dfinity`, repository `identity-attributes`, workflow `publish-crate.yml`,
environment `release`. A trusted publisher can only be added to a crate that
exists, so the first release of each crate is published by hand with
`cargo publish --locked`, `identity-attributes-macros` first.
