#!/usr/bin/env bash

# Copyright 2021 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# Continuous Integration test script

set -euxf -o pipefail

pushd cryptoki-sys
cargo build --features generate-bindings
popd

# check formatting before going through all the builds
if cargo fmt --version; then
	cargo fmt --all -- --check
fi
if cargo clippy --version; then
	cargo clippy --all-targets -- -D clippy::all -D clippy::cargo
fi

cargo build

cargo build --all-features

cargo build --target "$TARGET"

cargo test
