# Releasing

The two packages version and publish independently, each from its own tag:
`motoko-vX.Y.Z` publishes `motoko/` to [mops.one](https://mops.one), and
`rust-vX.Y.Z` publishes `rust/` to [crates.io](https://crates.io).

1. Bump `version` in `motoko/mops.toml` or `rust/Cargo.toml`.
2. Update the version in that package's install snippet in its `README.md`.
3. In that package's `Changelog.md`, rename `## Next` to `## X.Y.Z` and add a
   fresh empty `## Next` at the top.
4. Open a PR with those changes; merge once green.
5. From `main`, tag the merge commit:

   ```
   git tag motoko-vX.Y.Z   # or rust-vX.Y.Z
   git push origin motoko-vX.Y.Z
   ```

6. Check the publish workflow run to confirm it succeeded.

The Mops workflow needs the repository secret `MOPS_IDENTITY_PEM`, a publisher
identity exported with `mops user export`. The crates.io workflow needs
`CARGO_REGISTRY_TOKEN`. Both are scoped to the `release` environment, under
**Settings → Environments**.
