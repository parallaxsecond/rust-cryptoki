#!/usr/bin/env bash

# Copyright 2022 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

set -xeuf -o pipefail

# x86_64-unknown-darwin is included as a stable toolchain but does not
# include `rust-std` as a component (see https://doc.rust-lang.org/nightly/rustc/platform-support.html)
targets=( aarch64-unknown-linux-gnu arm-unknown-linux-gnueabi i686-unknown-linux-gnu powerpc64-unknown-linux-gnu x86_64-unknown-linux-gnu )

grepcwe() { grep -c "$@" || test $? = 1; }

for target in "${targets[@]}"
do
	PREVIOUSLY_INSTALLED=`rustup target list | grepcwe "$target (installed)"`

    if [ "$PREVIOUSLY_INSTALLED" == "0" ]; then
        rustup target install $target
    fi

    cargo build --target $target --features generate-bindings
    find ../target/$target/ -name pkcs11_bindings.rs | xargs -I '{}' cp '{}' src/bindings/$target.rs

    if [ "$PREVIOUSLY_INSTALLED" == "0" ]; then
        rustup target remove $target
    fi
done