#!/usr/bin/env bash

# Copyright 2021 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# Continuous Integration test script

set -euf -o pipefail

RUST_BACKTRACE=1 cargo build

RUST_BACKTRACE=1 cargo build --target arm-unknown-linux-gnueabi
RUST_BACKTRACE=1 cargo build --target armv7-unknown-linux-gnueabi
RUST_BACKTRACE=1 cargo build --target armv7-unknown-linux-gnueabihf
RUST_BACKTRACE=1 cargo build --target aarch64-unknown-linux-gnu
RUST_BACKTRACE=1 cargo build --target i686-unknown-linux-gnu
RUST_BACKTRACE=1 cargo build --target powerpc64-unknown-linux-gnu
RUST_BACKTRACE=1 cargo build --target powerpc64le-unknown-linux-gnu
RUST_BACKTRACE=1 cargo build --target x86_64-pc-windows-msvc
RUST_BACKTRACE=1 cargo build --target x86_64-apple-darwin

pushd cryptoki-sys
RUST_BACKTRACE=1 cargo build --features generate-bindings
popd

if cargo fmt -h; then
	cargo fmt --all -- --check
fi
if cargo clippy -h; then
	cargo clippy --all-targets -- -D clippy::all -D clippy::cargo
fi

RUST_BACKTRACE=1 cargo test
