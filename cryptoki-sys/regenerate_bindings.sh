#!/usr/bin/env bash

# Copyright 2022 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

set -xeuf -o pipefail

targets="aarch64-unknown-linux-gnu arm-unknown-linux-gnueabi i686-unknown-linux-gnu powerpc64-unknown-linux-gnu x86_64-unknown-linux-gnu x86_64-apple-darwin aarch64-apple-darwin x86_64-unknown-freebsd"
TARGET_INSTALLED=

for target in $targets; do

    # Check if the target is already installed
    if ! rustup target list | grep -q "$target (installed)"; then
        rustup target install "$target"
        TARGET_INSTALLED="$target"
    fi

    cargo build --target "$target" --features generate-bindings
    find ../target/"$target"/ -name "pkcs11_bindings.rs" | xargs -I '{}' cp '{}' src/bindings/"$target".rs

    if [ "$TARGET_INSTALLED" == "$target" ]; then
        rustup target remove "$target"
    fi
done
