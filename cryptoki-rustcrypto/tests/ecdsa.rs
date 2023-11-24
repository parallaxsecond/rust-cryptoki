// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

mod common;

use crate::common::USER_PIN;
use common::init_pins;
use cryptoki::{
    mechanism::Mechanism,
    object::{Attribute, KeyType},
    session::UserType,
    types::AuthPin,
};
use cryptoki_rustcrypto::ecdsa;
use der::Encode;
use p256::pkcs8::AssociatedOid;
use serial_test::serial;
use signature::{Keypair, Signer, Verifier};
use testresult::TestResult;

#[test]
#[serial]
fn sign_verify() -> TestResult {
    let (pkcs11, slot) = init_pins();

    // open a session
    let session = pkcs11.open_rw_session(slot)?;

    // log in the session
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // get mechanism
    let mechanism = Mechanism::EccKeyPairGen;

    let secp256r1_oid: Vec<u8> = p256::NistP256::OID.to_der().unwrap();
    println!("oid: {:x?}", secp256r1_oid);

    let label = b"demo-signer";

    // pub key template
    let pub_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::KeyType(KeyType::EC),
        Attribute::Verify(true),
        Attribute::EcParams(secp256r1_oid.clone()),
        Attribute::Label(label.to_vec()),
    ];

    // priv key template
    let priv_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        //Attribute::KeyType(KeyType::EC),
        //Attribute::EcParams(secp256r1_oid),
        //Attribute::Sensitive(true),
        //Attribute::Extractable(false),
        Attribute::Sign(true),
        Attribute::Label(label.to_vec()),
    ];

    // generate a key pair
    let (public, private) =
        session.generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)?;

    // data to sign
    let data = [0xFF, 0x55, 0xDD];

    let signer =
        ecdsa::Signer::<p256::NistP256, _>::new(&session, label).expect("Lookup keys from HSM");

    let signature = signer.sign(&data);

    let verifying_key = signer.verifying_key();
    verifying_key.verify(&data, &signature)?;

    // delete keys
    session.destroy_object(public)?;
    session.destroy_object(private)?;

    Ok(())
}
