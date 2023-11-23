// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

mod common;

use crate::common::USER_PIN;
use common::init_pins;
use cryptoki::{mechanism::Mechanism, object::Attribute, session::UserType, types::AuthPin};
use cryptoki_rustcrypto::rsa::{pkcs1v15, pss};
use serial_test::serial;
use signature::{Keypair, Signer, Verifier};
use testresult::TestResult;

#[test]
#[serial]
fn pkcs1v15_sign_verify() -> TestResult {
    let (pkcs11, slot) = init_pins();

    // open a session
    let session = pkcs11.open_rw_session(slot)?;

    // log in the session
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // get mechanism
    let mechanism = Mechanism::RsaPkcsKeyPairGen;

    let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01];
    let modulus_bits = 1024;

    let label = b"demo-signer";

    // pub key template
    let pub_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Label(label.to_vec()),
        Attribute::PublicExponent(public_exponent),
        Attribute::ModulusBits(modulus_bits.into()),
    ];

    // priv key template
    let priv_key_template = vec![Attribute::Token(true), Attribute::Label(label.to_vec())];

    // generate a key pair
    let (public, private) =
        session.generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)?;

    // data to sign
    let data = [0xFF, 0x55, 0xDD];

    let signer =
        pkcs1v15::Signer::<sha2::Sha256>::new(session, label).expect("Lookup keys from HSM");

    let signature = signer.sign(&data);

    let verifying_key = signer.verifying_key();
    verifying_key.verify(&data, &signature)?;

    let session = signer.into_session();

    // delete keys
    session.destroy_object(public)?;
    session.destroy_object(private)?;

    Ok(())
}

#[test]
#[serial]
fn pss_sign_verify() -> TestResult {
    let (pkcs11, slot) = init_pins();

    // open a session
    let session = pkcs11.open_rw_session(slot)?;

    // log in the session
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // get mechanism
    let mechanism = Mechanism::RsaPkcsKeyPairGen;

    let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01];
    let modulus_bits = 1024;

    let label = b"demo-signer";

    // pub key template
    let pub_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Label(label.to_vec()),
        Attribute::PublicExponent(public_exponent),
        Attribute::ModulusBits(modulus_bits.into()),
    ];

    // priv key template
    let priv_key_template = vec![Attribute::Token(true), Attribute::Label(label.to_vec())];

    // generate a key pair
    let (public, private) =
        session.generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)?;

    // data to sign
    let data = [0xFF, 0x55, 0xDD];

    let signer = pss::Signer::<sha2::Sha256>::new(session, label).expect("Lookup keys from HSM");

    let signature = signer.sign(&data);

    let verifying_key = signer.verifying_key();
    verifying_key.verify(&data, &signature)?;

    let session = signer.into_session();

    // delete keys
    session.destroy_object(public)?;
    session.destroy_object(private)?;

    Ok(())
}
