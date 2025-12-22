// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Tests for Drop error handling in Session.
//!
//! These tests use a mock PKCS#11 library that can simulate token removal,
//! allowing us to verify that Drop implementations handle errors gracefully
//! without logging warnings when close() was called explicitly.

use libloading::Library;
use log::{Level, LevelFilter, Metadata, Record};
use serial_test::serial;
use std::env;
use std::sync::Mutex;

mod common;

// ============================================================================
// Bindings for the mock library test API
// ============================================================================

struct MockPkcs11 {
    _lib: Library,
    simulate_token_removal: unsafe extern "C" fn(),
    #[allow(dead_code)]
    simulate_token_insertion: unsafe extern "C" fn(),
    reset: unsafe extern "C" fn(),
}

impl MockPkcs11 {
    fn new() -> Option<Self> {
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

    fn simulate_token_removal(&self) {
        unsafe {
            (self.simulate_token_removal)();
        }
    }

    fn reset(&self) {
        unsafe {
            (self.reset)();
        }
    }
}

// ============================================================================
// Log capture infrastructure
// ============================================================================

static LOG_MESSAGES: Mutex<Vec<(Level, String)>> = Mutex::new(Vec::new());
static LOGGER: TestLogger = TestLogger;

struct TestLogger;

impl log::Log for TestLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            if let Ok(mut logs) = LOG_MESSAGES.lock() {
                logs.push((record.level(), format!("{}", record.args())));
            }
        }
    }

    fn flush(&self) {}
}

fn init_logger() {
    // Ignore error if already initialized
    let _ = log::set_logger(&LOGGER).map(|()| log::set_max_level(LevelFilter::Warn));
}

fn clear_logs() {
    if let Ok(mut logs) = LOG_MESSAGES.lock() {
        logs.clear();
    }
}

fn get_logs() -> Vec<(Level, String)> {
    LOG_MESSAGES
        .lock()
        .map(|logs| logs.clone())
        .unwrap_or_default()
}

fn logs_contain_warning(substring: &str) -> bool {
    get_logs()
        .iter()
        .any(|(l, msg)| *l == Level::Warn && msg.contains(substring))
}

#[allow(dead_code)]
fn print_logs() {
    for (level, msg) in get_logs() {
        println!("  [{:?}] {}", level, msg);
    }
}

// ============================================================================
// Tests
// ============================================================================

/// Test that when close() is called explicitly after token removal,
/// no warning is logged during Drop.
///
/// Scenario:
/// 1. Open a valid session
/// 2. Simulate token removal (via mock API)
/// 3. get_session_info() returns error (handle invalid)
/// 4. close() is called explicitly and error is ignored
/// 5. Drop runs but should NOT log a warning because close() was called
#[test]
#[serial]
fn session_close_after_token_removal_no_warning() {
    init_logger();
    clear_logs();

    let mock = match MockPkcs11::new() {
        Some(m) => m,
        None => {
            println!("Skipping test: not using mock PKCS#11 library");
            return;
        }
    };
    mock.reset();

    // Load the mock library via cryptoki
    let pkcs11 = common::get_pkcs11();

    // 1. Open a valid session
    let slot = pkcs11.get_slots_with_token().unwrap()[0];
    let session = pkcs11.open_ro_session(slot).unwrap();

    // Verify the session is valid
    assert!(
        session.get_session_info().is_ok(),
        "Session should be valid initially"
    );

    // 2. Simulate token removal
    mock.simulate_token_removal();

    // 3. get_session_info() returns error (handle invalid)
    let result = session.get_session_info();
    assert!(
        result.is_err(),
        "get_session_info should fail after token removal"
    );

    // 4. Close the session explicitly and IGNORE the error
    // (this is the pattern users would use when handling token removal gracefully)
    let close_result = session.close();
    assert!(
        close_result.is_err(),
        "close() should return error after token removal"
    );

    // 5. Drop has been called, but since close() set closed=true,
    //    it should not log a warning

    // 6. Verify that NO warning was logged
    println!("Captured logs:");
    print_logs();

    assert!(
        !logs_contain_warning("Failed to close session"),
        "Warning should NOT appear because close() was called explicitly"
    );
}

/// Test that when a session is dropped without explicit close() after token removal,
/// a warning IS logged (this is expected behavior for unexpected errors).
#[test]
#[serial]
fn session_drop_without_close_after_token_removal_logs_warning() {
    init_logger();
    clear_logs();

    let mock = match MockPkcs11::new() {
        Some(m) => m,
        None => {
            println!("Skipping test: not using mock PKCS#11 library");
            return;
        }
    };
    mock.reset();

    let pkcs11 = common::get_pkcs11();

    // Open a valid session
    let slot = pkcs11.get_slots_with_token().unwrap()[0];
    let session = pkcs11.open_ro_session(slot).unwrap();

    // Verify the session is valid
    assert!(session.get_session_info().is_ok());

    // Simulate token removal
    mock.simulate_token_removal();

    // Drop the session WITHOUT calling close()
    // This should trigger the Drop warning
    drop(session);

    // Verify that a warning WAS logged
    println!("Captured logs:");
    print_logs();

    assert!(
        logs_contain_warning("Failed to close session"),
        "Warning SHOULD appear because close() was NOT called explicitly"
    );
}
