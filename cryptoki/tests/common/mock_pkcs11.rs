// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Bindings for the mock PKCS#11 library test API.
#![allow(dead_code)]

use cryptoki::context::Pkcs11;
use libloading::Library;
use std::env;

/// Returns the mock PKCS#11 library, or None if not configured.
/// These tests require the mock library to simulate token removal.
pub fn get_mock_library() -> Option<Pkcs11> {
    let path = env::var("TEST_PKCS11_MODULE").ok()?;
    if !path.contains("mockpkcs11") {
        return None;
    }
    Some(Pkcs11::new(path).unwrap())
}

pub struct MockPkcs11 {
    _lib: Library,
    simulate_token_removal: unsafe extern "C" fn(),
    simulate_token_insertion: unsafe extern "C" fn(),
    reset: unsafe extern "C" fn(),
}

impl MockPkcs11 {
    pub fn new() -> Option<Self> {
        let lib_path = env::var("TEST_PKCS11_MODULE").ok()?;

        // Only use mock API if we're using the mock library
        if !lib_path.contains("mockpkcs11") {
            return None;
        }

        unsafe {
            let lib = Library::new(&lib_path).ok()?;
            let simulate_token_removal = *lib.get(b"mock_simulate_token_removal").ok()?;
            let simulate_token_insertion = *lib.get(b"mock_simulate_token_insertion").ok()?;
            let reset = *lib.get(b"mock_reset").ok()?;

            Some(MockPkcs11 {
                _lib: lib,
                simulate_token_removal,
                simulate_token_insertion,
                reset,
            })
        }
    }

    pub fn simulate_token_removal(&self) {
        unsafe {
            (self.simulate_token_removal)();
        }
    }

    pub fn reset(&self) {
        unsafe {
            (self.reset)();
        }
    }
}
