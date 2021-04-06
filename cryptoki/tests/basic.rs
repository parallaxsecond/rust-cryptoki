// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod common;

use common::init_pins;
use cryptoki::types::mechanism::Mechanism;
use cryptoki::types::object::{Attribute, AttributeInfo, AttributeType, KeyType, ObjectClass};
use cryptoki::types::session::UserType;
use cryptoki::types::Flags;
use serial_test::serial;
use std::sync::Arc;
use std::thread;

#[test]
#[serial]
fn sign_verify() {
    let (pkcs11, slot) = init_pins();

    // set flags
    let mut flags = Flags::new();
    let _ = flags.set_rw_session(true).set_serial_session(true);

    // open a session
    let session = pkcs11.open_session_no_callback(slot, flags).unwrap();

    // log in the session
    session.login(UserType::User).unwrap();

    // get mechanism
    let mechanism = Mechanism::RsaPkcsKeyPairGen;

    let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01];
    let modulus_bits = 1024;

    // pub key template
    let pub_key_template = vec![
        Attribute::Token(true.into()),
        Attribute::Private(false.into()),
        Attribute::PublicExponent(public_exponent),
        Attribute::ModulusBits(modulus_bits.into()),
    ];

    // priv key template
    let priv_key_template = vec![Attribute::Token(true.into())];

    // generate a key pair
    let (public, private) = session
        .generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)
        .unwrap();

    // data to sign
    let data = [0xFF, 0x55, 0xDD];

    // sign something with it
    let signature = session.sign(&Mechanism::RsaPkcs, private, &data).unwrap();

    // verify the signature
    session
        .verify(&Mechanism::RsaPkcs, public, &data, &signature)
        .unwrap();

    // delete keys
    session.destroy_object(public).unwrap();
    session.destroy_object(private).unwrap();
}

#[test]
#[serial]
fn encrypt_decrypt() {
    let (pkcs11, slot) = init_pins();

    // set flags
    let mut flags = Flags::new();
    let _ = flags.set_rw_session(true).set_serial_session(true);

    // open a session
    let session = pkcs11.open_session_no_callback(slot, flags).unwrap();

    // log in the session
    session.login(UserType::User).unwrap();

    // get mechanism
    let mechanism = Mechanism::RsaPkcsKeyPairGen;

    let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01];
    let modulus_bits = 1024;

    // pub key template
    let pub_key_template = vec![
        Attribute::Token(true.into()),
        Attribute::Private(false.into()),
        Attribute::PublicExponent(public_exponent),
        Attribute::ModulusBits(modulus_bits.into()),
        Attribute::Encrypt(true.into()),
    ];

    // priv key template
    let priv_key_template = vec![
        Attribute::Token(true.into()),
        Attribute::Decrypt(true.into()),
    ];

    // generate a key pair
    let (public, private) = session
        .generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)
        .unwrap();

    // data to encrypt
    let data = vec![0xFF, 0x55, 0xDD];

    // encrypt something with it
    let encrypted_data = session.encrypt(&Mechanism::RsaPkcs, public, &data).unwrap();

    // decrypt
    let decrypted_data = session
        .decrypt(&Mechanism::RsaPkcs, private, &encrypted_data)
        .unwrap();

    // The decrypted buffer is bigger than the original one.
    assert_eq!(data, decrypted_data);

    // delete keys
    session.destroy_object(public).unwrap();
    session.destroy_object(private).unwrap();
}

#[test]
#[serial]
fn import_export() {
    let (pkcs11, slot) = init_pins();

    // set flags
    let mut flags = Flags::new();
    let _ = flags.set_rw_session(true).set_serial_session(true);

    // open a session
    let session = pkcs11.open_session_no_callback(slot, flags).unwrap();

    // log in the session
    session.login(UserType::User).unwrap();

    let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01];
    let modulus = vec![0xFF; 1024];

    let template = vec![
        Attribute::Token(true.into()),
        Attribute::Private(false.into()),
        Attribute::PublicExponent(public_exponent),
        Attribute::Modulus(modulus.clone()),
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(KeyType::RSA),
        Attribute::Verify(true.into()),
    ];

    {
        // Intentionally forget the object handle to find it later
        let _public_key = session.create_object(&template).unwrap();
    }

    let is_it_the_public_key = session.find_objects(&template).unwrap().remove(0);

    let attribute_info = session
        .get_attribute_info(is_it_the_public_key, &[AttributeType::Modulus])
        .unwrap()
        .remove(0);

    if let AttributeInfo::Available(size) = attribute_info {
        assert_eq!(size, 1024);
    } else {
        panic!("The Modulus attribute was expected to be present.")
    };

    let attr = session
        .get_attributes(is_it_the_public_key, &[AttributeType::Modulus])
        .unwrap()
        .remove(0);

    if let Attribute::Modulus(modulus_cmp) = attr {
        assert_eq!(modulus[..], modulus_cmp[..]);
    } else {
        panic!("Expected the Modulus attribute.");
    }

    // delete key
    session.destroy_object(is_it_the_public_key).unwrap();
}

#[test]
#[serial]
fn login_feast() {
    const SESSIONS: usize = 100;

    let (pkcs11, slot) = init_pins();

    // set flags
    let mut flags = Flags::new();
    let _ = flags.set_rw_session(true).set_serial_session(true);

    let pkcs11 = Arc::from(pkcs11);
    let mut threads = Vec::new();

    for _ in 0..SESSIONS {
        let pkcs11 = pkcs11.clone();
        threads.push(thread::spawn(move || {
            let session = pkcs11.open_session_no_callback(slot, flags).unwrap();
            session.login(UserType::User).unwrap();
            session.login(UserType::User).unwrap();
            session.login(UserType::User).unwrap();
            session.logout().unwrap();
            session.logout().unwrap();
            session.logout().unwrap();
        }));
    }

    for thread in threads {
        thread.join().unwrap();
    }
}
