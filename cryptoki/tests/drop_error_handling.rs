// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Tests for Drop error handling in Session.
//!
//! These tests use a mock PKCS#11 library that can simulate token removal,
//! allowing us to verify that Drop implementations handle errors gracefully
//! without logging warnings when close() was called explicitly.

mod common;

use common::mock_pkcs11::{get_mock_library, MockPkcs11};
use common::test_logger::{clear_logs, init_logger, logs_contain_warning, print_logs};
use serial_test::serial;

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
fn mock_session_close_after_token_removal_no_warning() {
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
    let pkcs11 = get_mock_library().unwrap();

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
fn mock_session_drop_without_close_after_token_removal_logs_warning() {
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

    let pkcs11 = get_mock_library().unwrap();

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
