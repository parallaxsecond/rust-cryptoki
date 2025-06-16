#!/usr/bin/env bash

# Copyright 2021 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# Continuous Integration test script

set -euxf -o pipefail

pushd cryptoki-sys
cargo build --features generate-bindings
popd

cargo test --target "$TARGET"
