// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

mod common;

use crate::common::USER_PIN;
use common::init_pins;
use cryptoki::{session::UserType, types::AuthPin};
use cryptoki_rustcrypto::rng::Rng;
use serial_test::serial;
use signature::rand_core::{CryptoRngCore, RngCore};
use testresult::TestResult;

// This test is meant to ensure we provide [`rand_core::CryptoRngCore`].
// This is the trait consumers will use throughout the RustCrypto ecosystem
// to express interest in a CSPRNG.
#[test]
#[serial]
fn ensure_crypto_rng_core() -> TestResult {
    fn just_making_sure<R: CryptoRngCore>(_r: &mut R) {
        // Hi! just making sure you provide a CSPRNG.
    }
    let (pkcs11, slot) = init_pins();

    // open a session
    let session = pkcs11.open_rw_session(slot)?;

    // log in the session
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let mut rng = Rng::new(session).unwrap();
    just_making_sure(&mut rng);

    Ok(())
}

#[test]
#[serial]
fn generate_random() -> TestResult {
    let (pkcs11, slot) = init_pins();

    // open a session
    let session = pkcs11.open_rw_session(slot)?;

    // log in the session
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let mut rng = Rng::new(session).unwrap();
    rng.next_u32();
    rng.next_u64();

    let mut buf = vec![0; 123];
    rng.fill_bytes(&mut buf);
    rng.try_fill_bytes(&mut buf).unwrap();

    Ok(())
}
