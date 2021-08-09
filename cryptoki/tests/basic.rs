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
fn derive_key() {
    let (pkcs11, slot) = init_pins();

    // set flags
    let mut flags = Flags::new();
    let _ = flags.set_rw_session(true).set_serial_session(true);

    // open a session
    let session = pkcs11.open_session_no_callback(slot, flags).unwrap();

    // log in the session
    session.login(UserType::User).unwrap();

    // get mechanism
    let mechanism = Mechanism::EccKeyPairGen;

    let secp256r1_oid: Vec<u8> = vec![0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    // pub key template
    let pub_key_template = vec![
        Attribute::Token(true.into()),
        Attribute::Private(false.into()),
        Attribute::Derive(true.into()),
        Attribute::KeyType(KeyType::EC),
        Attribute::Verify(true.into()),
        Attribute::EcParams(secp256r1_oid),
    ];

    // priv key template
    let priv_key_template = vec![
        Attribute::Token(true.into()),
        Attribute::Private(true.into()),
        Attribute::Sensitive(true.into()),
        Attribute::Extractable(false.into()),
        Attribute::Derive(true.into()),
        Attribute::Sign(true.into()),
    ];

    // generate a key pair
    let (public, private) = session
        .generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)
        .unwrap();

    let ec_point_attribute = session
        .get_attributes(public, &[AttributeType::EcPoint])
        .unwrap()
        .remove(0);

    let ec_point = if let Attribute::EcPoint(point) = ec_point_attribute {
        point
    } else {
        panic!("Expected EC point attribute.");
    };

    use cryptoki::types::mechanism::elliptic_curve::*;
    use std::convert::TryInto;

    let params = Ecdh1DeriveParams {
        kdf: EcKdfType::NULL,
        shared_data_len: 0_usize.try_into().unwrap(),
        shared_data: std::ptr::null(),
        public_data_len: (*ec_point).len().try_into().unwrap(),
        public_data: ec_point.as_ptr() as *const std::ffi::c_void,
    };

    let shared_secret = session
        .derive_key(
            &Mechanism::Ecdh1Derive(params),
            private,
            &[
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::GENERIC_SECRET),
                Attribute::Sensitive(false.into()),
                Attribute::Extractable(true.into()),
                Attribute::Token(false.into()),
            ],
        )
        .unwrap();

    let value_attribute = session
        .get_attributes(shared_secret, &[AttributeType::Value])
        .unwrap()
        .remove(0);
    let value = if let Attribute::Value(value) = value_attribute {
        value
    } else {
        panic!("Expected value attribute.");
    };

    assert_eq!(value.len(), 32);

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
fn get_token_info() {
    let (pkcs11, slot) = init_pins();
    let info = pkcs11.get_token_info(slot).unwrap();
    assert_eq!("SoftHSM project", info.get_manufacturer_id());
}

#[test]
#[serial]
fn wrap_and_unwrap_key() {
    let (pkcs11, slot) = init_pins();
    // set flags
    let mut flags = Flags::new();
    let _ = flags.set_rw_session(true).set_serial_session(true);

    // open a session
    let session = pkcs11.open_session_no_callback(slot, flags).unwrap();

    // log in the session
    session.login(UserType::User).unwrap();

    let key_to_be_wrapped_template = vec![
        Attribute::Token(true.into()),
        // the key needs to be extractable to be suitable for being wrapped
        Attribute::Extractable(true.into()),
        Attribute::Encrypt(true.into()),
    ];

    // generate a secret key that will be wrapped
    let key_to_be_wrapped = session
        .generate_key(&Mechanism::Des3KeyGen, &key_to_be_wrapped_template)
        .unwrap();

    // Des3Ecb input length must be a multiple of 8
    // see: PKCS#11 spec Table 10-10, DES-ECB Key And Data Length Constraints
    let encrypted_with_original = session
        .encrypt(
            &Mechanism::Des3Ecb,
            key_to_be_wrapped,
            &[1, 2, 3, 4, 5, 6, 7, 8],
        )
        .unwrap();

    // pub key template
    let pub_key_template = vec![
        Attribute::Token(true.into()),
        Attribute::Private(true.into()),
        Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
        Attribute::ModulusBits(1024.into()),
        // key needs to have "wrap" attribute to wrap other keys
        Attribute::Wrap(true.into()),
    ];

    // priv key template
    let priv_key_template = vec![Attribute::Token(true.into())];

    let (wrapping_key, unwrapping_key) = session
        .generate_key_pair(
            &Mechanism::RsaPkcsKeyPairGen,
            &pub_key_template,
            &priv_key_template,
        )
        .unwrap();

    let wrapped_key = session
        .wrap_key(&Mechanism::RsaPkcs, wrapping_key, key_to_be_wrapped)
        .unwrap();
    assert_eq!(wrapped_key.len(), 128);

    let unwrapped_key = session
        .unwrap_key(
            &Mechanism::RsaPkcs,
            unwrapping_key,
            &wrapped_key,
            &[
                Attribute::Token(true.into()),
                Attribute::Private(true.into()),
                Attribute::Encrypt(true.into()),
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::DES3),
            ],
        )
        .unwrap();

    let encrypted_with_unwrapped = session
        .encrypt(
            &Mechanism::Des3Ecb,
            unwrapped_key,
            &[1, 2, 3, 4, 5, 6, 7, 8],
        )
        .unwrap();
    assert_eq!(encrypted_with_original, encrypted_with_unwrapped);
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
