# Cryptoki Rust Wrapper

The `cryptoki` crate provides an idiomatic interface to the PKCS #11 API.
The `cryptoki-sys` crate provides the direct FFI bindings.

Check the `cryptoki` [README file](cryptoki/README.md) to get started!

# Community

Come and ask questions or talk with the Parsec Community in our Slack channel or biweekly meetings.
See the [Community](https://github.com/parallaxsecond/community) repository for more information on how to join.

# Contributing

Please check the [**Contribution
Guidelines**](https://parallaxsecond.github.io/parsec-book/contributing/index.html) to know more
about the contribution process.

# History

This repository is based on [this original PR on rust-pkcs11](https://github.com/mheese/rust-pkcs11/pull/43).
Read the PR discussion for more information.

# Releasing steps

Here are the steps needed for maintainers to release those two crates.

* all on-going issues and pull requests have been finalized
* go to the `main` branch and pull the latest
* do a dry-run to ensure everything can be published in the current state `cargo publish --dry-run`
* bump the two crates' version number in their `Cargo.toml`
* `cargo build` to update `Cargo.lock`
* commit the changes (see [this](https://github.com/parallaxsecond/rust-cryptoki/commit/82c7415d9ed63cd9a315062397c457e9c67e6f12) for example)
* tag the commit with the new version tags `cryptoki-sys-x.y.z` and `cryptoki-x.y.z`
* push the commit and the tags to `main`
* `cargo publish`
* update `CHANGELOG.md` with [`github-changelog-generator`](https://github.com/github-changelog-generator/github-changelog-generator) (you will need to [create a GitHub token](https://github.com/github-changelog-generator/github-changelog-generator?tab=readme-ov-file#github-token))
* make a PR with the updated changelog and inform the community about the new version!

# License

The software is provided under Apache-2.0. Contributions to this project are accepted under the same license.

*Copyright 2021 Contributors to the Parsec project.*
