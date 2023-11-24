// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

mod common;

use crate::common::USER_PIN;
use common::init_pins;
use cryptoki::{mechanism::Mechanism, object::Attribute, session::UserType, types::AuthPin};
use cryptoki_rustcrypto::rsa::pss;
use der::{pem::LineEnding, EncodePem};
use serial_test::serial;
use signature::Keypair;
use spki::SubjectPublicKeyInfoOwned;
use std::{str::FromStr, time::Duration};
use testresult::TestResult;
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
};

#[test]
#[serial]
fn pss_create_ca() -> TestResult {
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

    let signer = pss::Signer::<sha2::Sha256>::new(session, label).expect("Lookup keys from HSM");

    let serial_number = SerialNumber::from(42u32);
    let validity = Validity::from_now(Duration::new(5, 0)).unwrap();
    let profile = Profile::Root;
    let subject =
        Name::from_str("CN=World domination corporation,O=World domination Inc,C=US").unwrap();
    let pub_key = SubjectPublicKeyInfoOwned::from_key(signer.verifying_key()).unwrap();

    let builder =
        CertificateBuilder::new(profile, serial_number, validity, subject, pub_key, &signer)
            .expect("Create certificate");

    let certificate = builder.build().unwrap();

    let pem = certificate.to_pem(LineEnding::LF).expect("generate pem");
    println!("{}", pem);

    let session = signer.into_session();

    // delete keys
    session.destroy_object(public)?;
    session.destroy_object(private)?;

    Ok(())
}
