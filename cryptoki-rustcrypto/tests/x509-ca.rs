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
use cryptoki_rustcrypto::{ecdsa, rsa::pss};
use der::{pem::LineEnding, Encode, EncodePem};
use p256::pkcs8::AssociatedOid;
use serial_test::serial;
use signature::Keypair;
use spki::SubjectPublicKeyInfoOwned;
use std::{str::FromStr, time::Duration};
use testresult::TestResult;
use x509_cert::{
    builder::{profile::cabf, Builder, CertificateBuilder},
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

    let signer =
        pss::Signer::<sha2::Sha256, _>::new(&session, label).expect("Lookup keys from HSM");

    let serial_number = SerialNumber::from(42u32);
    let validity = Validity::from_now(Duration::new(5, 0)).unwrap();
    let subject =
        Name::from_str("CN=World domination corporation,O=World domination Inc,C=US").unwrap();
    let profile = cabf::Root::new(false, subject).expect("Create root profile");
    let pub_key = SubjectPublicKeyInfoOwned::from_key(&signer.verifying_key()).unwrap();

    let builder = CertificateBuilder::new(profile, serial_number, validity, pub_key)
        .expect("Create certificate");

    let certificate = builder.build(&signer).unwrap();

    let pem = certificate.to_pem(LineEnding::LF).expect("generate pem");
    println!("{}", pem);

    // delete keys
    session.destroy_object(public)?;
    session.destroy_object(private)?;

    Ok(())
}

#[test]
#[serial]
fn ecdsa_create_ca() -> TestResult {
    let (pkcs11, slot) = init_pins();

    // open a session
    let session = pkcs11.open_rw_session(slot)?;

    // log in the session
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // get mechanism
    let mechanism = Mechanism::EccKeyPairGen;

    let secp256r1_oid: Vec<u8> = p256::NistP256::OID.to_der().unwrap();

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
        Attribute::Sign(true),
        Attribute::Label(label.to_vec()),
    ];

    // generate a key pair
    let (public, private) =
        session.generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)?;

    let signer =
        ecdsa::Signer::<p256::NistP256, _>::new(&session, label).expect("Lookup keys from HSM");

    let serial_number = SerialNumber::from(42u32);
    let validity = Validity::from_now(Duration::new(5, 0)).unwrap();
    let subject =
        Name::from_str("CN=World domination corporation,O=World domination Inc,C=US").unwrap();
    let profile = cabf::Root::new(false, subject).expect("create root profile");
    let pub_key = SubjectPublicKeyInfoOwned::from_key(&signer.verifying_key()).unwrap();

    let builder = CertificateBuilder::new(profile, serial_number, validity, pub_key)
        .expect("Create certificate");

    let certificate = builder
        .build::<_, p256::ecdsa::DerSignature>(&signer)
        .unwrap();

    let pem = certificate.to_pem(LineEnding::LF).expect("generate pem");
    println!("{}", pem);

    // delete keys
    session.destroy_object(public)?;
    session.destroy_object(private)?;

    Ok(())
}
