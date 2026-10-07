# Contributing to identity-attributes

Thank you for your interest in contributing ❤️

## Contributing code changes

If you want to contribute a feature or bug fix, please **reach out to us first** so we can discuss feasibility and implementation strategies. You can reach out to us:

* on the [forum](https://forum.dfinity.org/c/internet-identity/32), or
* during our monthly community calls — see [Identity & Authentication WG](https://forum.dfinity.org/t/working-group-identity-authentication/11902).

Make sure to read the [LICENSE](LICENSE) first.

External contributions are accepted under the DFINITY [CLA](https://github.com/dfinity/cla/blob/main/CLA.md). The org-wide CLA workflow will guide you through signing on your first PR.

## Development

```
cd motoko
mops install
mops test
npm install && npm run format:check

cd ../rust
cargo test --workspace
cargo clippy --all-targets -- -D warnings
cargo build --release --target wasm32-unknown-unknown -p profile-example
```

The two libraries are meant to stay in step: a change to how either behaves
belongs in both, with the same test on each side. Both answer the frontend
with the same Candid types; `rust/examples/profile/profile.did` is generated
(`BLESS=1 cargo test -p profile-example`), so a change to the Rust types shows
up there.

For the release process, see [Releasing.md](Releasing.md).

## Bug reports

We really appreciate bug reports through [GitHub Issues](https://github.com/dfinity/identity-attributes/issues/new).
