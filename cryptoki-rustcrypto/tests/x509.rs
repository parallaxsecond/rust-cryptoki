// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

mod common;

use crate::common::USER_PIN;
use common::init_pins;
use cryptoki::{object::Attribute, session::UserType, types::AuthPin};
use cryptoki_rustcrypto::x509::CertPkcs11;
use der::Decode;
use serial_test::serial;
use testresult::TestResult;
use x509_cert::Certificate;

const VERISIGN_CERT: &[u8] = include_bytes!("./verisign.der");

#[test]
#[serial]
fn test_x509() -> TestResult {
    let (pkcs11, slot) = init_pins();

    // open a session
    let session = pkcs11.open_rw_session(slot)?;

    // log in the session
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let cert = Certificate::from_der(VERISIGN_CERT).expect("read certificate from der");

    let base_template = vec![Attribute::Label(b"demo-cert".to_vec())];

    cert.pkcs11_store(&session, base_template.clone())
        .expect("Store cert with the PKCS11 provider");

    let new = Certificate::pkcs11_load(&session, base_template)
        .expect("Lookup cert from PKCS11 provider");

    assert_eq!(cert, new);

    Ok(())
}
