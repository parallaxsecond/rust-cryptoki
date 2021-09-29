// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod common;

use crate::common::{SO_PIN, USER_PIN};
use common::init_pins;
use cryptoki::types::function::RvError;
use cryptoki::types::mechanism::Mechanism;
use cryptoki::types::object::{Attribute, AttributeInfo, AttributeType, KeyType, ObjectClass};
use cryptoki::types::session::{SessionState, UserType};
use cryptoki::types::SessionFlags;
use cryptoki::Error;
use serial_test::serial;
use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

#[derive(Debug)]
struct ErrorWithStacktrace;

impl<T: std::error::Error> From<T> for ErrorWithStacktrace {
    fn from(p: T) -> Self {
        panic!("Error: {:#?}", p);
    }
}

type Result<T> = std::result::Result<T, ErrorWithStacktrace>;

#[test]
#[serial]
fn sign_verify() -> Result<()> {
    let (pkcs11, slot) = init_pins();

    // set flags
    let mut flags = SessionFlags::new();
    let _ = flags.set_rw_session(true).set_serial_session(true);

    // open a session
    let session = pkcs11.open_session_no_callback(slot, flags)?;

    // log in the session
    session.login(UserType::User, Some(USER_PIN))?;

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
    let (public, private) =
        session.generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)?;

    // data to sign
    let data = [0xFF, 0x55, 0xDD];

    // sign something with it
    let signature = session.sign(&Mechanism::RsaPkcs, private, &data)?;

    // verify the signature
    session.verify(&Mechanism::RsaPkcs, public, &data, &signature)?;

    // delete keys
    session.destroy_object(public)?;
    session.destroy_object(private)?;

    Ok(())
}

#[test]
#[serial]
fn encrypt_decrypt() -> Result<()> {
    let (pkcs11, slot) = init_pins();

    // set flags
    let mut flags = SessionFlags::new();
    let _ = flags.set_rw_session(true).set_serial_session(true);

    // open a session
    let session = pkcs11.open_session_no_callback(slot, flags)?;

    // log in the session
    session.login(UserType::User, Some(USER_PIN))?;

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
    let (public, private) =
        session.generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)?;

    // data to encrypt
    let data = vec![0xFF, 0x55, 0xDD];

    // encrypt something with it
    let encrypted_data = session.encrypt(&Mechanism::RsaPkcs, public, &data)?;

    // decrypt
    let decrypted_data = session.decrypt(&Mechanism::RsaPkcs, private, &encrypted_data)?;

    // The decrypted buffer is bigger than the original one.
    assert_eq!(data, decrypted_data);

    // delete keys
    session.destroy_object(public)?;
    session.destroy_object(private)?;

    Ok(())
}

#[test]
#[serial]
fn derive_key() -> Result<()> {
    let (pkcs11, slot) = init_pins();

    // set flags
    let mut flags = SessionFlags::new();
    let _ = flags.set_rw_session(true).set_serial_session(true);

    // open a session
    let session = pkcs11.open_session_no_callback(slot, flags)?;

    // log in the session
    session.login(UserType::User, Some(USER_PIN))?;

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
    let (public, private) =
        session.generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)?;

    let ec_point_attribute = session
        .get_attributes(public, &[AttributeType::EcPoint])?
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
        shared_data_len: 0_usize.try_into()?,
        shared_data: std::ptr::null(),
        public_data_len: (*ec_point).len().try_into()?,
        public_data: ec_point.as_ptr() as *const std::ffi::c_void,
    };

    let shared_secret = session.derive_key(
        &Mechanism::Ecdh1Derive(params),
        private,
        &[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::Sensitive(false.into()),
            Attribute::Extractable(true.into()),
            Attribute::Token(false.into()),
        ],
    )?;

    let value_attribute = session
        .get_attributes(shared_secret, &[AttributeType::Value])?
        .remove(0);
    let value = if let Attribute::Value(value) = value_attribute {
        value
    } else {
        panic!("Expected value attribute.");
    };

    assert_eq!(value.len(), 32);

    // delete keys
    session.destroy_object(public)?;
    session.destroy_object(private)?;

    Ok(())
}

#[test]
#[serial]
fn import_export() -> Result<()> {
    let (pkcs11, slot) = init_pins();

    // set flags
    let mut flags = SessionFlags::new();
    let _ = flags.set_rw_session(true).set_serial_session(true);

    // open a session
    let session = pkcs11.open_session_no_callback(slot, flags)?;

    // log in the session
    session.login(UserType::User, Some(USER_PIN))?;

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
        let _public_key = session.create_object(&template)?;
    }

    let is_it_the_public_key = session.find_objects(&template)?.remove(0);

    let attribute_info = session
        .get_attribute_info(is_it_the_public_key, &[AttributeType::Modulus])?
        .remove(0);

    if let AttributeInfo::Available(size) = attribute_info {
        assert_eq!(size, 1024);
    } else {
        panic!("The Modulus attribute was expected to be present.")
    };

    let attr = session
        .get_attributes(is_it_the_public_key, &[AttributeType::Modulus])?
        .remove(0);

    if let Attribute::Modulus(modulus_cmp) = attr {
        assert_eq!(modulus[..], modulus_cmp[..]);
    } else {
        panic!("Expected the Modulus attribute.");
    }

    // delete key
    session.destroy_object(is_it_the_public_key)?;

    Ok(())
}

#[test]
#[serial]
fn get_token_info() -> Result<()> {
    let (pkcs11, slot) = init_pins();
    let info = pkcs11.get_token_info(slot)?;
    assert_eq!("SoftHSM project", info.manufacturer_id());

    Ok(())
}

#[test]
#[serial]
fn wrap_and_unwrap_key() {
    let (pkcs11, slot) = init_pins();
    // set flags
    let mut flags = SessionFlags::new();
    let _ = flags.set_rw_session(true).set_serial_session(true);

    // open a session
    let session = pkcs11.open_session_no_callback(slot, flags).unwrap();

    // log in the session
    session.login(UserType::User, Some(USER_PIN)).unwrap();

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
    let mut flags = SessionFlags::new();
    let _ = flags.set_rw_session(true).set_serial_session(true);

    let pkcs11 = Arc::from(pkcs11);
    let mut threads = Vec::new();

    for _ in 0..SESSIONS {
        let pkcs11 = pkcs11.clone();
        threads.push(thread::spawn(move || {
            let session = pkcs11.open_session_no_callback(slot, flags).unwrap();
            match session.login(UserType::User, Some(USER_PIN)) {
                Ok(_) | Err(Error::Pkcs11(RvError::UserAlreadyLoggedIn)) => {}
                Err(e) => panic!("Bad error response: {}", e),
            }
            match session.login(UserType::User, Some(USER_PIN)) {
                Ok(_) | Err(Error::Pkcs11(RvError::UserAlreadyLoggedIn)) => {}
                Err(e) => panic!("Bad error response: {}", e),
            }
            match session.login(UserType::User, Some(USER_PIN)) {
                Ok(_) | Err(Error::Pkcs11(RvError::UserAlreadyLoggedIn)) => {}
                Err(e) => panic!("Bad error response: {}", e),
            }
            match session.logout() {
                Ok(_) | Err(Error::Pkcs11(RvError::UserNotLoggedIn)) => {}
                Err(e) => panic!("Bad error response: {}", e),
            }
            match session.logout() {
                Ok(_) | Err(Error::Pkcs11(RvError::UserNotLoggedIn)) => {}
                Err(e) => panic!("Bad error response: {}", e),
            }
            match session.logout() {
                Ok(_) | Err(Error::Pkcs11(RvError::UserNotLoggedIn)) => {}
                Err(e) => panic!("Bad error response: {}", e),
            }
        }));
    }

    for thread in threads {
        thread.join().unwrap();
    }
}

#[test]
#[serial]
fn get_info_test() -> Result<()> {
    let (pkcs11, _) = init_pins();
    let info = pkcs11.get_library_info()?;

    assert_eq!(info.cryptoki_version().major(), 2);
    assert_eq!(info.cryptoki_version().minor(), 40);
    assert_eq!(info.manufacturer_id(), String::from("SoftHSM"));
    Ok(())
}

#[test]
#[serial]
fn get_slot_info_test() -> Result<()> {
    let (pkcs11, slot) = init_pins();
    let slot_info = pkcs11.get_slot_info(slot)?;
    assert!(slot_info.flags().token_present());
    assert!(!slot_info.flags().hardware_slot());
    assert!(!slot_info.flags().removable_device());
    assert_eq!(slot_info.manufacturer_id(), String::from("SoftHSM project"));
    Ok(())
}

#[test]
#[serial]
fn get_session_info_test() -> Result<()> {
    let (pkcs11, slot) = init_pins();

    let mut flags = SessionFlags::new();

    // Check that OpenSession errors when CKF_SERIAL_SESSION is not set
    if let Err(cryptoki::Error::Pkcs11(rv_error)) = pkcs11.open_session_no_callback(slot, flags) {
        assert_eq!(rv_error, RvError::SessionParallelNotSupported);
    } else {
        panic!("Should error when CKF_SERIAL_SESSION is not set");
    }

    let _ = flags.set_serial_session(true);
    {
        let session = pkcs11.open_session_no_callback(slot, flags)?;
        let session_info = session.get_session_info()?;
        assert_eq!(session_info.flags(), flags);
        assert_eq!(session_info.slot_id(), slot);
        assert_eq!(
            session_info.session_state(),
            SessionState::RO_PUBLIC_SESSION
        );

        session.login(UserType::User, Some(USER_PIN))?;
        let session_info = session.get_session_info()?;
        assert_eq!(session_info.flags(), flags);
        assert_eq!(session_info.slot_id(), slot);
        assert_eq!(
            session_info.session_state(),
            SessionState::RO_USER_FUNCTIONS
        );
        session.logout()?;
        if let Err(cryptoki::Error::Pkcs11(rv_error)) = session.login(UserType::So, Some(SO_PIN)) {
            assert_eq!(rv_error, RvError::SessionReadOnlyExists)
        } else {
            panic!("Should error when attempting to log in as CKU_SO on a read-only session");
        }
    }

    let _ = flags.set_rw_session(true);

    let session = pkcs11.open_session_no_callback(slot, flags)?;
    let session_info = session.get_session_info()?;
    assert_eq!(session_info.flags(), flags);
    assert_eq!(session_info.slot_id(), slot);
    assert_eq!(
        session_info.session_state(),
        SessionState::RW_PUBLIC_SESSION
    );

    session.login(UserType::User, Some(USER_PIN))?;
    let session_info = session.get_session_info()?;
    assert_eq!(session_info.flags(), flags);
    assert_eq!(session_info.slot_id(), slot);
    assert_eq!(
        session_info.session_state(),
        SessionState::RW_USER_FUNCTIONS
    );
    session.logout()?;
    session.login(UserType::So, Some(SO_PIN))?;
    let session_info = session.get_session_info()?;
    assert_eq!(session_info.flags(), flags);
    assert_eq!(session_info.slot_id(), slot);
    assert_eq!(session_info.session_state(), SessionState::RW_SO_FUNCTIONS);

    Ok(())
}

#[test]
#[serial]
fn generate_random_test() -> Result<()> {
    let (pkcs11, slot) = init_pins();

    let mut flags = SessionFlags::new();

    let _ = flags.set_serial_session(true);
    let session = pkcs11.open_session_no_callback(slot, flags)?;

    let poor_seed: [u8; 32] = [0; 32];
    session.seed_random(&poor_seed)?;

    let mut random_data: [u8; 32] = [0; 32];
    session.generate_random_slice(&mut random_data)?;

    // This of course assumes the RBG in the the SoftHSM is not terrible
    assert!(!random_data.iter().all(|&x| x == 0));

    let random_vec = session.generate_random_vec(32)?;
    assert_eq!(random_vec.len(), 32);

    assert!(!random_vec.iter().all(|&x| x == 0));
    Ok(())
}

#[test]
#[serial]
fn set_pin_test() -> Result<()> {
    let new_user_pin = "123456";
    let (pkcs11, slot) = init_pins();

    let mut flags = SessionFlags::new();

    let _ = flags.set_serial_session(true).set_rw_session(true);
    let session = pkcs11.open_session_no_callback(slot, flags)?;

    session.login(UserType::User, Some(USER_PIN))?;
    session.set_pin(USER_PIN, new_user_pin)?;
    session.logout()?;
    session.login(UserType::User, Some(new_user_pin))?;

    Ok(())
}

#[test]
#[serial]
fn get_attribute_info_test() -> Result<()> {
    let (pkcs11, slot) = init_pins();

    let mut flags = SessionFlags::new();
    let _ = flags.set_rw_session(true).set_serial_session(true);

    // open a session
    let session = pkcs11.open_session_no_callback(slot, flags)?;

    // log in the session
    session.login(UserType::User, Some(USER_PIN))?;

    // get mechanism
    let mechanism = Mechanism::RsaPkcsKeyPairGen;

    let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01];
    let modulus_bits = 2048;

    // pub key template
    let pub_key_template = vec![
        Attribute::Token(false.into()),
        Attribute::Private(false.into()),
        Attribute::PublicExponent(public_exponent),
        Attribute::ModulusBits(modulus_bits.into()),
    ];

    // priv key template
    let priv_key_template = vec![
        Attribute::Token(false.into()),
        Attribute::Sensitive(true.into()),
        Attribute::Extractable(false.into()),
    ];

    // generate a key pair
    let (public, private) =
        session.generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)?;

    let pub_attribs = vec![AttributeType::PublicExponent, AttributeType::Modulus];
    let mut priv_attribs = pub_attribs.clone();
    priv_attribs.push(AttributeType::PrivateExponent);

    let attrib_info = session.get_attribute_info(public, &pub_attribs)?;
    let hash = pub_attribs
        .iter()
        .zip(attrib_info.iter())
        .collect::<HashMap<_, _>>();

    if let AttributeInfo::Available(size) = hash[&AttributeType::Modulus] {
        assert_eq!(*size, 2048 / 8);
    } else {
        panic!("Modulus should not return Unavailable for an RSA public key");
    }

    match hash[&AttributeType::PublicExponent] {
        AttributeInfo::Available(_) => {}
        _ => panic!("Public Exponent should not return Unavailable for an RSA public key"),
    }

    let attrib_info = session.get_attribute_info(private, &priv_attribs)?;
    let hash = priv_attribs
        .iter()
        .zip(attrib_info.iter())
        .collect::<HashMap<_, _>>();

    if let AttributeInfo::Available(size) = hash[&AttributeType::Modulus] {
        assert_eq!(*size, 2048 / 8);
    } else {
        panic!("Modulus should not return Unavailable on an RSA private key");
    }

    match hash[&AttributeType::PublicExponent] {
        AttributeInfo::Available(_) => {}
        _ => panic!("PublicExponent should not return Unavailable on an RSA private key"),
    }

    match hash[&AttributeType::PrivateExponent] {
        AttributeInfo::Sensitive => {}
        _ => panic!("Private Exponent of RSA private key should be sensitive"),
    }

    let hash = session.get_attribute_info_map(private, priv_attribs)?;
    if let AttributeInfo::Available(size) = hash[&AttributeType::Modulus] {
        assert_eq!(size, 2048 / 8);
    } else {
        panic!("Modulus should not return Unavailable on an RSA private key");
    }

    match hash[&AttributeType::PublicExponent] {
        AttributeInfo::Available(_) => {}
        _ => panic!("Public Exponent should not return Unavailable for an RSA private key"),
    }

    match hash[&AttributeType::PrivateExponent] {
        AttributeInfo::Sensitive => {}
        _ => panic!("Private Exponent of RSA private key should be sensitive"),
    }

    Ok(())
}
