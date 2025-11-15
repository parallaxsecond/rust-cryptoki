// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod common;

use crate::common::{
    get_firmware_version, get_pkcs11, is_fips, is_kryoptic, is_softhsm, SO_PIN, USER_PIN,
};
use common::init_pins;
use cryptoki::context::{CInitializeFlags, Function};
use cryptoki::error::{Error, RvError};
use cryptoki::mechanism::aead::{GcmMessageParams, GcmParams, GeneratorFunction};
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::kbkdf::{
    DerivedKey, Endianness, KbkdfCounterFormat, KbkdfDkmLengthFormat, KbkdfDkmLengthMethod,
    KbkdfFeedbackParams, KbkdfParams, PrfDataParam, PrfDataParamType,
};
use cryptoki::mechanism::misc::{ExtractParams, KeyDerivationStringData};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource};
use cryptoki::mechanism::{Mechanism, MechanismType, MessageParam};
use cryptoki::object::{
    Attribute, AttributeInfo, AttributeType, KeyType, ObjectClass, ObjectHandle,
};
use cryptoki::session::{SessionState, UserType};
use cryptoki::types::{AuthPin, Ulong};
use serial_test::serial;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::thread;

use cryptoki::mechanism::ekdf::AesCbcDeriveParams;
use testresult::TestResult;

const AES128_BLOCK_SIZE: Ulong = Ulong::new(128 / 8);
const AES256_BLOCK_SIZE: Ulong = Ulong::new(256 / 8);

#[test]
#[serial]
fn sign_verify() -> TestResult {
    let (pkcs11, slot) = init_pins();

    // open a session
    let session = pkcs11.open_rw_session(slot)?;

    // log in the session
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // get mechanism
    let mechanism = Mechanism::RsaPkcsKeyPairGen;

    let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01];
    let modulus_bits = 2048;

    // pub key template
    let pub_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::PublicExponent(public_exponent),
        Attribute::ModulusBits(modulus_bits.into()),
        Attribute::Verify(true),
    ];

    // priv key template
    let priv_key_template = vec![Attribute::Token(true), Attribute::Sign(true)];

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

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn sign_verify_eddsa() -> TestResult {
    let (pkcs11, slot) = init_pins();

    let session = pkcs11.open_rw_session(slot)?;

    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let mechanism = Mechanism::EccEdwardsKeyPairGen;

    let pub_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Verify(true),
        // Ed25519 OID
        // See: https://github.com/opendnssec/SoftHSMv2/blob/ac70dc398b236e4522101930e790008936489e2d/src/lib/test/SignVerifyTests.cpp#L173
        Attribute::EcParams(vec![
            0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x32, 0x35, 0x35, 0x31, 0x39,
        ]),
    ];

    let priv_key_template = vec![Attribute::Token(true), Attribute::Sign(true)];

    let (public, private) =
        session.generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)?;

    let data = [0xFF, 0x55, 0xDD];

    let scheme = EddsaSignatureScheme::Pure;

    let params = EddsaParams::new(scheme);

    let signature = session.sign(&Mechanism::Eddsa(params), private, &data)?;

    session.verify(&Mechanism::Eddsa(params), public, &data, &signature)?;

    session.destroy_object(public)?;
    session.destroy_object(private)?;

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn sign_verify_eddsa_with_ed25519_schemes() -> TestResult {
    let (pkcs11, slot) = init_pins();

    let session = pkcs11.open_rw_session(slot)?;

    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let mechanism = Mechanism::EccEdwardsKeyPairGen;

    let pub_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Verify(true),
        // Ed25519 OID
        // See: https://github.com/opendnssec/SoftHSMv2/blob/ac70dc398b236e4522101930e790008936489e2d/src/lib/test/SignVerifyTests.cpp#L173
        Attribute::EcParams(vec![
            0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x32, 0x35, 0x35, 0x31, 0x39,
        ]),
    ];

    let priv_key_template = vec![Attribute::Token(true), Attribute::Sign(true)];

    let (public, private) =
        session.generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)?;

    let data = [0xFF, 0x55, 0xDD];

    let mut schemes = vec![
        EddsaSignatureScheme::Ed25519,
        EddsaSignatureScheme::Ed25519ph(&[]),
        EddsaSignatureScheme::Ed25519ph(b"context"),
    ];
    if !is_fips(&session) {
        // The Ed25519Ctx variant is not FIPS approved
        // https://github.com/openssl/openssl/issues/27502
        schemes.push(EddsaSignatureScheme::Ed25519ctx(b"context"))
    }

    for scheme in schemes {
        let params = EddsaParams::new(scheme);

        let signature = session.sign(&Mechanism::Eddsa(params), private, &data)?;

        session.verify(&Mechanism::Eddsa(params), public, &data, &signature)?;
    }

    session.destroy_object(public)?;
    session.destroy_object(private)?;

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn sign_verify_eddsa_with_ed448_schemes() -> TestResult {
    let (pkcs11, slot) = init_pins();

    let session = pkcs11.open_rw_session(slot)?;

    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let mechanism = Mechanism::EccEdwardsKeyPairGen;

    let pub_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Verify(true),
        // Ed448 OID
        // See: https://github.com/opendnssec/SoftHSMv2/blob/ac70dc398b236e4522101930e790008936489e2d/src/lib/test/SignVerifyTests.cpp#L173
        Attribute::EcParams(vec![
            0x13, 0x0a, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x34, 0x34, 0x38,
        ]),
    ];

    let priv_key_template = vec![Attribute::Token(true), Attribute::Sign(true)];

    let (public, private) =
        session.generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)?;

    let data = [0xFF, 0x55, 0xDD];

    let schemes = [
        EddsaSignatureScheme::Ed448(b"context"),
        EddsaSignatureScheme::Ed448ph(b"context"),
    ];

    for scheme in schemes {
        let params = EddsaParams::new(scheme);

        let signature = session.sign(&Mechanism::Eddsa(params), private, &data)?;

        session.verify(&Mechanism::Eddsa(params), public, &data, &signature)?;
    }

    session.destroy_object(public)?;
    session.destroy_object(private)?;

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn sign_verify_multipart() -> TestResult {
    let (pkcs11, slot) = init_pins();

    // Open a session and log in
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // Define parameters for keypair
    let public_exponent = vec![0x01, 0x00, 0x01];
    let modulus_bits = 2048;

    let pub_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::PublicExponent(public_exponent),
        Attribute::ModulusBits(modulus_bits.into()),
        Attribute::Verify(true),
    ];
    let priv_key_template = vec![Attribute::Token(true), Attribute::Sign(true)];

    // Generate keypair
    let (pub_key, priv_key) = session.generate_key_pair(
        &Mechanism::RsaPkcsKeyPairGen,
        &pub_key_template,
        &priv_key_template,
    )?;

    // Data to sign
    let data = [0xFF, 0x55, 0xDD, 0x11, 0xBB, 0x33];

    // Sign data in parts (standard RsaPkcs doesn't support this)
    session.sign_init(&Mechanism::Sha256RsaPkcs, priv_key)?;
    for part in data.chunks(3) {
        session.sign_update(part)?;
    }
    let signature = session.sign_final()?;

    // Verify signature in parts (standard RsaPkcs doesn't support this)
    session.verify_init(&Mechanism::Sha256RsaPkcs, pub_key)?;
    for part in data.chunks(3) {
        session.verify_update(part)?;
    }
    session.verify_final(&signature)?;

    // Delete keys
    session.destroy_object(pub_key)?;
    session.destroy_object(priv_key)?;

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn sign_verify_multipart_not_initialized() -> TestResult {
    let (pkcs11, slot) = init_pins();

    // Open a session and log in
    let session = pkcs11.open_ro_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // Data to sign/verify
    let data = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let signature = vec![0x66, 0x55, 0x44, 0x33, 0x22, 0x11];

    // Attempt to update signing without an operation having been initialized
    let result = session.sign_update(&data);

    assert!(result.is_err());
    // The exact error returned is inconsistent between backends, so we only match on the function
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(_, Function::SignUpdate)
    ));

    // Attempt to finalize signing without an operation having been initialized
    let result = session.sign_final();

    assert!(result.is_err());
    // The exact error returned is inconsistent between backends, so we only match on the function
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(_, Function::SignFinal)
    ));

    // Attempt to update verification without an operation having been initialized
    let result = session.verify_update(&data);

    assert!(result.is_err());
    // The exact error returned is inconsistent between backends, so we only match on the function
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(_, Function::VerifyUpdate)
    ));

    // Attempt to finalize verification without an operation having been initialized
    let result = session.verify_final(&signature);

    assert!(result.is_err());
    // The exact error returned is inconsistent between backends, so we only match on the function
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(_, Function::VerifyFinal)
    ));

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn sign_verify_multipart_already_initialized() -> TestResult {
    let (pkcs11, slot) = init_pins();

    // Open a session and log in
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // Define parameters for keypair
    let public_exponent = vec![0x01, 0x00, 0x01];
    let modulus_bits = 2048;

    let pub_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::PublicExponent(public_exponent),
        Attribute::ModulusBits(modulus_bits.into()),
        Attribute::Verify(true),
    ];
    let priv_key_template = vec![Attribute::Token(true), Attribute::Sign(true)];

    // Generate keypair
    let (pub_key, priv_key) = session.generate_key_pair(
        &Mechanism::RsaPkcsKeyPairGen,
        &pub_key_template,
        &priv_key_template,
    )?;

    // Initialize signing operation twice in a row
    session.sign_init(&Mechanism::Sha256RsaPkcs, priv_key)?;
    let result = session.sign_init(&Mechanism::Sha256RsaPkcs, priv_key);

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(RvError::OperationActive, Function::SignInit)
    ));

    // Make sure signing operation is over before trying same with verification.
    // Some backends will reset the ongoing operation after the failed 2nd call to
    // sign_init(), so we should not unwrap the result of this call.
    let _ = session.sign_final();

    // Initialize verification operation twice in a row
    session.verify_init(&Mechanism::Sha256RsaPkcs, pub_key)?;
    let result = session.verify_init(&Mechanism::Sha256RsaPkcs, pub_key);

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(RvError::OperationActive, Function::VerifyInit)
    ));

    // Delete keys
    session.destroy_object(pub_key)?;
    session.destroy_object(priv_key)?;

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn encrypt_decrypt() -> TestResult {
    let (pkcs11, slot) = init_pins();

    // open a session
    let session = pkcs11.open_rw_session(slot)?;

    if is_fips(&session) {
        eprintln!("The RSA PKCS#1 encryption is not allowed in FIPS Mode");
        session.close()?;
        pkcs11.finalize()?;
        return Ok(());
    }

    // log in the session
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // get mechanism
    let mechanism = Mechanism::RsaPkcsKeyPairGen;

    let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01];
    let modulus_bits = 2048;

    // pub key template
    let pub_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::PublicExponent(public_exponent),
        Attribute::ModulusBits(modulus_bits.into()),
        Attribute::Encrypt(true),
    ];

    // priv key template
    let priv_key_template = vec![Attribute::Token(true), Attribute::Decrypt(true)];

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

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn encrypt_decrypt_multipart() -> TestResult {
    let (pkcs11, slot) = init_pins();

    // Open a session and log in
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // Generate key (currently SoftHSM only supports multi-part encrypt/decrypt for symmetric crypto)
    let template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::ValueLen(AES128_BLOCK_SIZE),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
    ];
    let key = session.generate_key(&Mechanism::AesKeyGen, &template)?;

    // Data to encrypt
    let data = vec![
        0xFF, 0x55, 0xDD, 0x11, 0xBB, 0x33, 0x99, 0x77, 0xFF, 0x55, 0xDD, 0x11, 0xBB, 0x33, 0x99,
        0x77, 0xFF, 0x55, 0xDD, 0x11, 0xBB, 0x33, 0x99, 0x77, 0xFF, 0x55, 0xDD, 0x11, 0xBB, 0x33,
        0x99, 0x77, 0xFF, 0x55, 0xDD, 0x11, 0xBB, 0x33, 0x99, 0x77, 0xFF, 0x55, 0xDD, 0x11, 0xBB,
        0x33, 0x99, 0x77,
    ];

    // Encrypt data in parts, using AES-ECB
    session.encrypt_init(&Mechanism::AesEcb, key)?;

    let mut encrypted_data = vec![];
    for part in data.chunks(AES128_BLOCK_SIZE.into()) {
        encrypted_data.extend(session.encrypt_update(part)?);
    }
    encrypted_data.extend(session.encrypt_final()?);

    // Decrypt data in parts
    session.decrypt_init(&Mechanism::AesEcb, key)?;

    let mut decrypted_data = vec![];
    for part in encrypted_data.chunks(AES128_BLOCK_SIZE.into()) {
        decrypted_data.extend(session.decrypt_update(part)?);
    }
    decrypted_data.extend(session.decrypt_final()?);

    assert_eq!(data, decrypted_data);

    // Encrypt data in parts, using AES-GCM
    let mut iv = [0u8, 12];
    session.generate_random_slice(&mut iv)?;
    session.encrypt_init(
        &Mechanism::AesGcm(GcmParams::new(&mut iv, &[], 128.into())?),
        key,
    )?;

    let mut encrypted_data = vec![];
    for part in data.chunks(AES128_BLOCK_SIZE.into()) {
        encrypted_data.extend(session.encrypt_update(part)?);
    }
    encrypted_data.extend(session.encrypt_final()?);

    // Decrypt data in parts
    session.decrypt_init(
        &Mechanism::AesGcm(GcmParams::new(&mut iv, &[], 128.into())?),
        key,
    )?;

    let mut decrypted_data = vec![];
    for part in encrypted_data.chunks(AES128_BLOCK_SIZE.into()) {
        decrypted_data.extend(session.decrypt_update(part)?);
    }

    // Skip the final call when testing against Kryoptic as multi-part GCM is
    // broken: https://github.com/latchset/kryoptic/issues/381. We can still
    // assert that the output is correct as Kryoptic has returned it by this
    // point, but skip authentication.
    if !is_kryoptic() {
        decrypted_data.extend(session.decrypt_final()?);
    }

    assert_eq!(data, decrypted_data);

    // Delete key
    session.destroy_object(key)?;

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn encrypt_decrypt_multipart_not_initialized() -> TestResult {
    let (pkcs11, slot) = init_pins();

    // Open a session and log in
    let session = pkcs11.open_ro_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // Data to encrypt/decrypt
    let data = vec![
        0xFF, 0x55, 0xDD, 0x11, 0xBB, 0x33, 0x99, 0x77, 0xFF, 0x55, 0xDD, 0x11, 0xBB, 0x33, 0x99,
        0x77,
    ];

    // Attempt to update encryption without an operation having been initialized
    let result = session.encrypt_update(&data);

    assert!(result.is_err());
    // The exact error returned is inconsistent between backends, so we only match on the function
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(_, Function::EncryptUpdate)
    ));

    // Attempt to finalize encryption without an operation having been initialized
    let result = session.encrypt_final();

    assert!(result.is_err());
    // The exact error returned is inconsistent between backends, so we only match on the function
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(_, Function::EncryptFinal)
    ));

    // Attempt to update decryption without an operation having been initialized
    let result = session.decrypt_update(&data);

    assert!(result.is_err());
    // The exact error returned is inconsistent between backends, so we only match on the function
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(_, Function::DecryptUpdate)
    ));

    // Attempt to finalize decryption without an operation having been initialized
    let result = session.decrypt_final();

    assert!(result.is_err());
    // The exact error returned is inconsistent between backends, so we only match on the function
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(_, Function::DecryptFinal)
    ));

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn encrypt_decrypt_multipart_already_initialized() -> TestResult {
    let (pkcs11, slot) = init_pins();

    // Open a session and log in
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // Generate key (currently SoftHSM only supports multi-part encrypt/decrypt for symmetric crypto)
    let template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::ValueLen(AES128_BLOCK_SIZE),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
    ];
    let key = session.generate_key(&Mechanism::AesKeyGen, &template)?;

    // Initialize encryption operation twice in a row
    session.encrypt_init(&Mechanism::AesEcb, key)?;
    let result = session.encrypt_init(&Mechanism::AesEcb, key);

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(RvError::OperationActive, Function::EncryptInit)
    ));

    // Make sure encryption operation is over before trying same with decryption.
    // Some backends will reset the ongoing operation after the failed 2nd call to
    // encrypt_init(), so we should not unwrap the result of this call.
    let _ = session.encrypt_final();

    // Initialize encryption operation twice in a row
    session.decrypt_init(&Mechanism::AesEcb, key)?;
    let result = session.decrypt_init(&Mechanism::AesEcb, key);

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(RvError::OperationActive, Function::DecryptInit)
    ));

    // Delete key
    session.destroy_object(key)?;

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn derive_key() -> TestResult {
    let (pkcs11, slot) = init_pins();

    // open a session
    let session = pkcs11.open_rw_session(slot)?;

    // log in the session
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // get mechanism
    let mechanism = Mechanism::EccKeyPairGen;

    let secp256r1_oid: Vec<u8> = vec![0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    // pub key template
    let pub_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Derive(true),
        Attribute::KeyType(KeyType::EC),
        Attribute::Verify(true),
        Attribute::EcParams(secp256r1_oid),
    ];

    // priv key template
    let priv_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Derive(true),
        Attribute::Sign(true),
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

    use cryptoki::mechanism::elliptic_curve::*;

    let params = Ecdh1DeriveParams::new(EcKdf::null(), &ec_point);

    let shared_secret = session.derive_key(
        &Mechanism::Ecdh1Derive(params),
        private,
        &[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::Sensitive(false),
            Attribute::Extractable(true),
            Attribute::Token(false),
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

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn derive_key_sp800() -> TestResult {
    if is_softhsm() {
        return Ok(());
    }

    use cryptoki::mechanism::elliptic_curve::*;

    let (pkcs11, slot) = init_pins();

    if is_kryoptic() {
        let (major, minor) = get_firmware_version(&pkcs11, slot);
        // Kryoptic added support for sha256_sp800 in version 1.3.
        if !(major > 1 || minor >= 3) {
            eprintln!("Skipping test: Kryoptic is too old (need 1.3, got {major}.{minor})");
            pkcs11.finalize()?;
            return Ok(());
        }
    }

    // open a session
    let session = pkcs11.open_rw_session(slot)?;

    // log in the session
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // sha256_sp800
    let key = hex::decode("F00670C5F139E7E6C2511EA04FF507AFBBE237CE3C71A89CA59A1C5CF8856562")
        .expect("valid hex");
    let ephemeral_key =
        hex::decode("533B3F09E53B3DEED661A13F7A7D9694AB71CE156C728E00DEE87A1EE3A14C4A")
            .expect("valid hex");
    let kdf_param = hex::decode("0A2B0601040197550105011203010807416E6F6E796D6F75732053656E646572202020205633A4C5AE4305BC0FE2ABB699A8EE54632790A0").expect("valid hex");
    let derivation = hex::decode("AF8CE51D0139A6D60831A9BABAB20186").expect("valid hex");

    let template = [
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::EC_MONTGOMERY),
        Attribute::EcParams(vec![
            0x13, 0x0a, 0x63, 0x75, 0x72, 0x76, 0x65, 0x32, 0x35, 0x35, 0x31, 0x39,
        ]),
        Attribute::Value(key),
        Attribute::Id(b"foo".to_vec()),
        Attribute::Label(b"bar".to_vec()),
        Attribute::Sensitive(true),
        Attribute::Token(true),
        Attribute::Derive(true),
    ];

    let private = session.create_object(&template)?;

    let kdf = EcKdf::sha256_sp800(&kdf_param);

    let params = Ecdh1DeriveParams::new(kdf, &ephemeral_key);

    let shared_secret = session.derive_key(
        &Mechanism::Ecdh1Derive(params),
        private,
        &[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::ValueLen(Ulong::new(derivation.len().try_into().unwrap())),
            Attribute::Sensitive(false),
            Attribute::Extractable(true),
            Attribute::Token(false),
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

    assert_eq!(value, derivation);

    // delete keys
    session.destroy_object(private)?;

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn derive_key_concatenation_two_keys() -> TestResult {
    // Mechanism not supported by SoftHSM
    if is_softhsm() {
        /* return Ignore(); */
        return Ok(());
    }

    let (pkcs11, slot) = init_pins();

    // Open a session and log in
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // Define keys to concatenate
    let key_value = [0x12, 0x34, 0x56, 0x78, 0x90, 0x01];

    let key1_template = [
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
        Attribute::Value(key_value[..3].to_vec()),
        Attribute::Derive(true),
        Attribute::Sensitive(false),
        Attribute::Extractable(true),
    ];
    let key2_template = [
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
        Attribute::Value(key_value[3..].to_vec()),
        Attribute::Derive(true),
        Attribute::Sensitive(false),
        Attribute::Extractable(true),
    ];

    let key1 = session.create_object(&key1_template)?;
    let key2 = session.create_object(&key2_template)?;

    // Derive key from two input keys
    let derived_key_template = [
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::Sensitive(false),
        Attribute::Extractable(true),
    ];
    let derived_key = session.derive_key(
        &Mechanism::ConcatenateBaseAndKey(key2),
        key1,
        &derived_key_template,
    )?;

    let derived_key_value = session
        .get_attributes(derived_key, &[AttributeType::Value])?
        .remove(0);
    let derived_key_value = if let Attribute::Value(value) = derived_key_value {
        value
    } else {
        panic!("Expected value attribute.");
    };

    assert_eq!(&derived_key_value, &key_value);

    // Delete keys
    session.destroy_object(key1)?;
    session.destroy_object(key2)?;
    session.destroy_object(derived_key)?;

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn derive_key_concatenation_key_and_data() -> TestResult {
    // Mechanism not supported by SoftHSM
    if is_softhsm() {
        /* return Ignore(); */
        return Ok(());
    }

    let (pkcs11, slot) = init_pins();

    // Open a session and log in
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // Define key/data to concatenate
    let mut data_value = [0x12, 0x34, 0x56, 0x78, 0x90, 0x01];

    let key_template = [
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
        Attribute::Value(data_value[..3].to_vec()),
        Attribute::Derive(true),
    ];

    let key = session.create_object(&key_template)?;

    // Derive keys from input key and data, both appended and prepended
    let derived_key_template = [
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::Sensitive(false),
        Attribute::Extractable(true),
    ];
    let data = KeyDerivationStringData::new(&data_value[3..]);
    let derived_key1 = session.derive_key(
        &Mechanism::ConcatenateBaseAndData(data),
        key,
        &derived_key_template,
    )?;
    let derived_key2 = session.derive_key(
        &Mechanism::ConcatenateDataAndBase(data),
        key,
        &derived_key_template,
    )?;

    let derived_key1_value = session
        .get_attributes(derived_key1, &[AttributeType::Value])?
        .remove(0);
    let derived_key1_value = if let Attribute::Value(value) = derived_key1_value {
        value
    } else {
        panic!("Expected value attribute.");
    };
    let derived_key2_value = session
        .get_attributes(derived_key2, &[AttributeType::Value])?
        .remove(0);
    let derived_key2_value = if let Attribute::Value(value) = derived_key2_value {
        value
    } else {
        panic!("Expected value attribute.");
    };

    assert_eq!(&derived_key1_value, &data_value);
    // Swap halves of the data_value in-place
    let (first_half, second_half) = data_value.split_at_mut(3);
    first_half.swap_with_slice(second_half);
    assert_eq!(&derived_key2_value, &data_value);

    // Delete keys
    session.destroy_object(key)?;
    session.destroy_object(derived_key1)?;
    session.destroy_object(derived_key2)?;

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn derive_key_xor_key_and_data() -> TestResult {
    // Mechanism not supported by SoftHSM
    if is_softhsm() {
        /* return Ignore(); */
        return Ok(());
    }

    let (pkcs11, slot) = init_pins();

    // Open a session and log in
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // Define key/data to xor
    let data_value = [0x12, 0x34, 0x56, 0x78, 0x90, 0x01];

    let key_template = [
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
        Attribute::Value(data_value.to_vec()),
        Attribute::Derive(true),
    ];

    let key = session.create_object(&key_template)?;

    // Derive key by xor-ing input key and data
    let derived_key_template = [
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::Sensitive(false),
        Attribute::Extractable(true),
    ];
    let data = KeyDerivationStringData::new(&data_value);
    let derived_key =
        session.derive_key(&Mechanism::XorBaseAndData(data), key, &derived_key_template)?;

    let derived_key_value = session
        .get_attributes(derived_key, &[AttributeType::Value])?
        .remove(0);
    let derived_key_value = if let Attribute::Value(value) = derived_key_value {
        value
    } else {
        panic!("Expected value attribute.");
    };

    assert_eq!(&derived_key_value, &[0; 6]);

    // Delete keys
    session.destroy_object(key)?;
    session.destroy_object(derived_key)?;

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn derive_key_extract_from_key() -> TestResult {
    // Mechanism not supported by SoftHSM
    if is_softhsm() {
        /* return Ignore(); */
        return Ok(());
    }

    let (pkcs11, slot) = init_pins();

    // Open a session and log in
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // Define key to extract from
    let data_value = [0x12, 0x34, 0x56, 0x78, 0x90, 0x01];

    let key_template = [
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
        Attribute::Value(data_value.to_vec()),
        Attribute::Derive(true),
    ];

    let key = session.create_object(&key_template)?;

    // Derive key by extracting subset of base key
    let derived_key_template = [
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::ValueLen(2.into()),
        Attribute::Sensitive(false),
        Attribute::Extractable(true),
    ];
    let params = ExtractParams::new(3);
    let derived_key = session.derive_key(
        &Mechanism::ExtractKeyFromKey(params),
        key,
        &derived_key_template,
    )?;

    let derived_key_value = session
        .get_attributes(derived_key, &[AttributeType::Value])?
        .remove(0);
    let derived_key_value = if let Attribute::Value(value) = derived_key_value {
        value
    } else {
        panic!("Expected value attribute.");
    };

    // Manually extract exactly the same part of the original value, to compare
    let mut result_value = u32::from_be_bytes(data_value[..4].try_into().unwrap());
    result_value <<= 3;
    result_value &= 0xFFFF0000;

    assert_eq!(&derived_key_value, &result_value.to_be_bytes()[..2]);

    // Delete keys
    session.destroy_object(key)?;
    session.destroy_object(derived_key)?;

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn import_export() -> TestResult {
    let (pkcs11, slot) = init_pins();

    // open a session
    let session = pkcs11.open_rw_session(slot)?;

    // log in the session
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01];
    let modulus = vec![0xFF; 1024];

    let template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::PublicExponent(public_exponent),
        Attribute::Modulus(modulus.clone()),
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(KeyType::RSA),
        Attribute::Verify(true),
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

    let mut attrs =
        session.get_attributes(is_it_the_public_key, &[AttributeType::AllowedMechanisms])?;

    if is_softhsm() {
        let attr = attrs.remove(0);
        if let Attribute::AllowedMechanisms(v) = attr {
            assert_eq!(v, Vec::<MechanismType>::new());
        } else {
            panic!("Expected the AllowedMechanisms attribute.");
        }
    } else {
        assert_eq!(attrs, Vec::<Attribute>::new());
    }

    // delete key
    session.destroy_object(is_it_the_public_key)?;

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn get_token_info() -> TestResult {
    let (pkcs11, slot) = init_pins();
    let info = pkcs11.get_token_info(slot)?;
    assert_ne!("", info.manufacturer_id());

    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn session_find_objects() -> testresult::TestResult {
    let (pkcs11, slot) = init_pins();
    // open a session
    let session = pkcs11.open_rw_session(slot)?;

    // log in the session
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // we generate 11 keys with the same CKA_ID
    // we will check 3 different use cases, this will cover all cases for Session.find_objects
    // find 11 keys with the same CKA_ID => should result in two internal iterations over MAX_OBJECT_COUNT
    // find 10 keys with the same CKA_ID => should result in two internal iterations over MAX_OBJECT_COUNT
    // find 9 keys with the same CKA_ID  => should result in one internal iteration over MAX_OBJECT_COUNT

    (1..=11).for_each(|i| {
        let key_template = vec![
            Attribute::Token(true),
            Attribute::Encrypt(true),
            Attribute::Label(format!("key_{i}").as_bytes().to_vec()),
            Attribute::ValueLen(32.into()),
            Attribute::Id("12345678".as_bytes().to_vec()), // reusing the same CKA_ID
        ];

        // generate a secret key
        let _key = session
            .generate_key(&Mechanism::AesKeyGen, &key_template)
            .unwrap();
    });

    // retrieve the keys by searching for them
    let key_search_template = vec![
        Attribute::Token(true),
        Attribute::Id("12345678".as_bytes().to_vec()),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
    ];

    let mut found_keys = session.find_objects(&key_search_template)?;
    assert_eq!(found_keys.len(), 11);

    // destroy one key
    session.destroy_object(found_keys.pop().unwrap())?;

    let mut found_keys = session.find_objects(&key_search_template)?;
    assert_eq!(found_keys.len(), 10);

    // destroy another key
    session.destroy_object(found_keys.pop().unwrap())?;
    let found_keys = session.find_objects(&key_search_template)?;
    assert_eq!(found_keys.len(), 9);
    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn session_objecthandle_iterator() -> testresult::TestResult {
    let (pkcs11, slot) = init_pins();
    // open a session
    let session = pkcs11.open_rw_session(slot)?;

    // log in the session
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // we generate 11 keys with the same CKA_ID

    for i in 1..=11 {
        let key_template = vec![
            Attribute::Token(true),
            Attribute::Encrypt(true),
            Attribute::ValueLen(32.into()),
            Attribute::Label(format!("key_{i}").as_bytes().to_vec()),
            Attribute::Id("12345678".as_bytes().to_vec()), // reusing the same CKA_ID
        ];

        // generate a secret key
        session.generate_key(&Mechanism::AesKeyGen, &key_template)?;
    }

    // retrieve these keys using this template
    let key_search_template = vec![
        Attribute::Token(true),
        Attribute::Id("12345678".as_bytes().to_vec()),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
    ];

    // test iter_objects_with_cache_size()
    // count keys with cache size of 20
    let found_keys = session
        .iter_objects_with_cache_size(&key_search_template, NonZeroUsize::new(20).unwrap())?;
    let found_keys = found_keys.map_while(|key| key.ok()).count();
    assert_eq!(found_keys, 11);

    // count keys with cache size of 1
    let found_keys = session
        .iter_objects_with_cache_size(&key_search_template, NonZeroUsize::new(1).unwrap())?;
    let found_keys = found_keys.map_while(|key| key.ok()).count();
    assert_eq!(found_keys, 11);

    // count keys with cache size of 10
    let found_keys = session
        .iter_objects_with_cache_size(&key_search_template, NonZeroUsize::new(10).unwrap())?;
    let found_keys = found_keys.map_while(|key| key.ok()).count();
    assert_eq!(found_keys, 11);

    // fetch keys into a vector
    let found_keys: Vec<ObjectHandle> = session
        .iter_objects_with_cache_size(&key_search_template, NonZeroUsize::new(10).unwrap())?
        .map_while(|key| key.ok())
        .collect();
    assert_eq!(found_keys.len(), 11);

    let key0 = found_keys[0];
    let key1 = found_keys[1];

    session.destroy_object(key0).unwrap();
    let found_keys = session
        .iter_objects_with_cache_size(&key_search_template, NonZeroUsize::new(10).unwrap())?;
    let found_keys = found_keys.map_while(|key| key.ok()).count();
    assert_eq!(found_keys, 10);

    // destroy another key
    session.destroy_object(key1).unwrap();
    let found_keys = session
        .iter_objects_with_cache_size(&key_search_template, NonZeroUsize::new(10).unwrap())?;
    let found_keys = found_keys.map_while(|key| key.ok()).count();
    assert_eq!(found_keys, 9);

    // test iter_objects()
    let found_keys = session.iter_objects(&key_search_template)?;
    let found_keys = found_keys.map_while(|key| key.ok()).count();
    assert_eq!(found_keys, 9);

    // test interleaved iterators - the second iterator should fail
    {
        let iter = session.iter_objects(&key_search_template);
        let iter2 = session.iter_objects(&key_search_template);

        assert!(iter.is_ok());
        assert!(matches!(
            iter2,
            Err(Error::Pkcs11(RvError::OperationActive, _))
        ));
    }
    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn wrap_and_unwrap_key() {
    let (pkcs11, slot) = init_pins();
    // open a session
    let session = pkcs11.open_rw_session(slot).unwrap();

    if is_fips(&session) {
        eprintln!("The RSA PKCS#1 encryption is not allowed in FIPS Mode");
        session.close().unwrap();
        pkcs11.finalize().unwrap();
        return;
    }

    // log in the session
    session
        .login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))
        .unwrap();

    let key_to_be_wrapped_template = vec![
        Attribute::Token(true),
        Attribute::ValueLen(32.into()),
        // the key needs to be extractable to be suitable for being wrapped
        Attribute::Extractable(true),
        Attribute::Encrypt(true),
    ];

    // generate a secret key that will be wrapped
    let key_to_be_wrapped = session
        .generate_key(&Mechanism::AesKeyGen, &key_to_be_wrapped_template)
        .unwrap();

    // AesEcb input length must be a multiple of 16
    let encrypted_with_original = session
        .encrypt(
            &Mechanism::AesEcb,
            key_to_be_wrapped,
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        )
        .unwrap();

    // pub key template
    let pub_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
        Attribute::ModulusBits(2048.into()),
        // key needs to have "wrap" attribute to wrap other keys
        Attribute::Wrap(true),
    ];

    // priv key template
    let priv_key_template = vec![Attribute::Token(true), (Attribute::Unwrap(true))];

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
    assert_eq!(wrapped_key.len(), 256);

    let unwrapped_key = session
        .unwrap_key(
            &Mechanism::RsaPkcs,
            unwrapping_key,
            &wrapped_key,
            &[
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Encrypt(true),
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::AES),
            ],
        )
        .unwrap();

    let encrypted_with_unwrapped = session
        .encrypt(
            &Mechanism::AesEcb,
            unwrapped_key,
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        )
        .unwrap();
    assert_eq!(encrypted_with_original, encrypted_with_unwrapped);

    session.close().unwrap();
    pkcs11.finalize().unwrap();
}

#[test]
#[serial]
fn wrap_and_unwrap_key_oaep() {
    let (pkcs11, slot) = init_pins();
    // open a session
    let session = pkcs11.open_rw_session(slot).unwrap();

    // log in the session
    session
        .login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))
        .unwrap();

    let key_to_be_wrapped_template = vec![
        Attribute::Token(true),
        Attribute::ValueLen(32.into()),
        // the key needs to be extractable to be suitable for being wrapped
        Attribute::Extractable(true),
        Attribute::Encrypt(true),
    ];

    // generate a secret key that will be wrapped
    let key_to_be_wrapped = session
        .generate_key(&Mechanism::AesKeyGen, &key_to_be_wrapped_template)
        .unwrap();

    // AesEcb input length must be a multiple of 16
    let encrypted_with_original = session
        .encrypt(
            &Mechanism::AesEcb,
            key_to_be_wrapped,
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        )
        .unwrap();

    // pub key template
    let pub_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
        Attribute::ModulusBits(2048.into()),
        // key needs to have "wrap" attribute to wrap other keys
        Attribute::Wrap(true),
    ];

    // priv key template
    let priv_key_template = vec![Attribute::Token(true), (Attribute::Unwrap(true))];

    let (wrapping_key, unwrapping_key) = session
        .generate_key_pair(
            &Mechanism::RsaPkcsKeyPairGen,
            &pub_key_template,
            &priv_key_template,
        )
        .unwrap();

    let oaep = PkcsOaepParams::new(
        MechanismType::SHA1,
        PkcsMgfType::MGF1_SHA1,
        PkcsOaepSource::empty(),
    );
    let wrapped_key = session
        .wrap_key(
            &Mechanism::RsaPkcsOaep(oaep),
            wrapping_key,
            key_to_be_wrapped,
        )
        .unwrap();
    assert_eq!(wrapped_key.len(), 256);

    let unwrapped_key = session
        .unwrap_key(
            &Mechanism::RsaPkcsOaep(oaep),
            unwrapping_key,
            &wrapped_key,
            &[
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Encrypt(true),
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::AES),
            ],
        )
        .unwrap();

    let encrypted_with_unwrapped = session
        .encrypt(
            &Mechanism::AesEcb,
            unwrapped_key,
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        )
        .unwrap();
    assert_eq!(encrypted_with_original, encrypted_with_unwrapped);

    session.close().unwrap();
    pkcs11.finalize().unwrap();
}

#[test]
#[serial]
fn login_feast() {
    const SESSIONS: usize = 100;

    let (pkcs11, slot) = init_pins();
    let mut threads = Vec::new();

    for _ in 0..SESSIONS {
        let pkcs11 = pkcs11.clone();
        threads.push(thread::spawn(move || {
            let session = pkcs11.open_rw_session(slot).unwrap();
            match session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into()))) {
                Ok(_) | Err(Error::Pkcs11(RvError::UserAlreadyLoggedIn, Function::Login)) => {}
                Err(e) => panic!("Bad error response: {e}"),
            }
            match session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into()))) {
                Ok(_) | Err(Error::Pkcs11(RvError::UserAlreadyLoggedIn, Function::Login)) => {}
                Err(e) => panic!("Bad error response: {e}"),
            }
            match session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into()))) {
                Ok(_) | Err(Error::Pkcs11(RvError::UserAlreadyLoggedIn, Function::Login)) => {}
                Err(e) => panic!("Bad error response: {e}"),
            }
            match session.logout() {
                Ok(_) | Err(Error::Pkcs11(RvError::UserNotLoggedIn, Function::Logout)) => {}
                Err(e) => panic!("Bad error response: {e}"),
            }
            match session.logout() {
                Ok(_) | Err(Error::Pkcs11(RvError::UserNotLoggedIn, Function::Logout)) => {}
                Err(e) => panic!("Bad error response: {e}"),
            }
            match session.logout() {
                Ok(_) | Err(Error::Pkcs11(RvError::UserNotLoggedIn, Function::Logout)) => {}
                Err(e) => panic!("Bad error response: {e}"),
            }
        }));
    }

    for thread in threads {
        thread.join().unwrap();
    }

    pkcs11.finalize().unwrap();
}

#[test]
#[serial]
fn get_info_test() -> TestResult {
    let (pkcs11, _) = init_pins();
    let info = pkcs11.get_library_info()?;

    assert_ne!("", info.manufacturer_id());
    if is_softhsm() {
        assert_eq!(info.cryptoki_version().major(), 2);
        assert_eq!(info.cryptoki_version().minor(), 40);
    } else {
        assert_eq!(info.cryptoki_version().major(), 3);
        let minor = info.cryptoki_version().minor();
        assert!(
            [0, 2].contains(&minor),
            "Only 3.0 and 3.2 versions are expected but got 3.{minor}"
        );
    }
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn get_slot_info_test() -> TestResult {
    let (pkcs11, slot) = init_pins();
    let slot_info = pkcs11.get_slot_info(slot)?;
    assert!(slot_info.token_present());
    assert!(!slot_info.hardware_slot());
    assert!(!slot_info.removable_device());
    assert_ne!("", slot_info.manufacturer_id());
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn get_session_info_test() -> TestResult {
    let (pkcs11, slot) = init_pins();
    {
        let session = pkcs11.open_ro_session(slot)?;
        let session_info = session.get_session_info()?;
        assert!(!session_info.read_write());
        assert_eq!(session_info.slot_id(), slot);
        assert!(matches!(
            session_info.session_state(),
            SessionState::RoPublic
        ));

        session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;
        let session_info = session.get_session_info()?;
        assert!(!session_info.read_write());
        assert_eq!(session_info.slot_id(), slot);
        assert!(matches!(session_info.session_state(), SessionState::RoUser));
        session.logout()?;
        if let Err(cryptoki::error::Error::Pkcs11(rv_error, _)) =
            session.login(UserType::So, Some(&AuthPin::new(SO_PIN.into())))
        {
            assert_eq!(rv_error, RvError::SessionReadOnlyExists)
        } else {
            panic!("Should error when attempting to log in as CKU_SO on a read-only session");
        }
    }

    let session = pkcs11.open_rw_session(slot)?;
    let session_info = session.get_session_info()?;
    assert!(session_info.read_write());
    assert_eq!(session_info.slot_id(), slot);
    assert!(matches!(
        session_info.session_state(),
        SessionState::RwPublic
    ));

    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;
    let session_info = session.get_session_info()?;
    assert!(session_info.read_write());
    assert_eq!(session_info.slot_id(), slot);
    assert!(matches!(session_info.session_state(), SessionState::RwUser));
    session.logout()?;
    session.login(UserType::So, Some(&AuthPin::new(SO_PIN.into())))?;
    let session_info = session.get_session_info()?;
    assert!(session_info.read_write());
    assert_eq!(session_info.slot_id(), slot);
    assert!(matches!(
        session_info.session_state(),
        SessionState::RwSecurityOfficer
    ));

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn generate_random_test() -> TestResult {
    let (pkcs11, slot) = init_pins();

    let session = pkcs11.open_ro_session(slot)?;

    let poor_seed: [u8; 32] = [0; 32];
    session.seed_random(&poor_seed)?;

    let mut random_data: [u8; 32] = [0; 32];
    session.generate_random_slice(&mut random_data)?;

    // This of course assumes the RBG in the the SoftHSM is not terrible
    assert!(!random_data.iter().all(|&x| x == 0));

    let random_vec = session.generate_random_vec(32)?;
    assert_eq!(random_vec.len(), 32);

    assert!(!random_vec.iter().all(|&x| x == 0));
    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn set_pin_test() -> TestResult {
    let new_user_pin = "123456abcdef";
    let (pkcs11, slot) = init_pins();

    let session = pkcs11.open_rw_session(slot)?;
    let user_pin = AuthPin::new(USER_PIN.into());
    let new_user_pin = AuthPin::new(new_user_pin.into());

    session.login(UserType::User, Some(&user_pin))?;
    session.set_pin(&user_pin, &new_user_pin)?;
    session.logout()?;
    session.login(UserType::User, Some(&new_user_pin))?;

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn get_attribute_info_test() -> TestResult {
    let (pkcs11, slot) = init_pins();

    // open a session
    let session = pkcs11.open_rw_session(slot)?;

    // log in the session
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // get mechanism
    let mechanism = Mechanism::RsaPkcsKeyPairGen;

    let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01];
    let modulus_bits = 2048;

    // pub key template
    let pub_key_template = vec![
        Attribute::Token(false),
        Attribute::Private(false),
        Attribute::PublicExponent(public_exponent),
        Attribute::ModulusBits(modulus_bits.into()),
    ];

    // priv key template
    let priv_key_template = vec![
        Attribute::Token(false),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
    ];

    // generate a key pair
    let (public, private) =
        session.generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)?;

    let pub_attribs = vec![AttributeType::PublicExponent, AttributeType::Modulus];
    let priv_attribs = [
        AttributeType::PublicExponent,
        AttributeType::Modulus,
        AttributeType::PrivateExponent,
    ];

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

    let hash = session.get_attribute_info_map(private, &priv_attribs)?;
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

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn is_fn_supported_test() {
    use cryptoki::context::Function;

    let (pkcs11, _) = init_pins();

    assert!(
        pkcs11.is_fn_supported(Function::Initialize),
        "C_Initialize function reports as not supported"
    );
    assert!(
        pkcs11.is_fn_supported(Function::Sign),
        "C_Sign function reports as not supported"
    );
    assert!(
        pkcs11.is_fn_supported(Function::DigestFinal),
        "C_DigestFinal function reports as not supported"
    );
    if is_softhsm() {
        // the SoftHSM does not have PKCS#11 3.0 API so this function is not present
        assert!(
            !pkcs11.is_fn_supported(Function::MessageEncryptInit),
            "C_MessageEncryptInit function reports supported for SoftHSM"
        );
    } else {
        assert!(
            pkcs11.is_fn_supported(Function::MessageEncryptInit),
            "C_MessageEncryptInit function reports as not supported"
        );
    }

    pkcs11.finalize().unwrap();
}

#[test]
#[serial]
fn is_initialized_test() -> TestResult {
    use cryptoki::context::CInitializeArgs;

    let pkcs11 = get_pkcs11();

    // First initialization should work.
    pkcs11
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();

    match pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Err(Error::Pkcs11(RvError::CryptokiAlreadyInitialized, Function::Initialize)) => (), // expected
        Err(e) => panic!("Got unexpected error when initializing: {e}"),
        Ok(()) => panic!("Initializing twice should not have been allowed"),
    }

    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
#[allow(clippy::redundant_clone)]
fn test_clone_initialize() -> TestResult {
    use cryptoki::context::CInitializeArgs;

    let pkcs11 = get_pkcs11();

    {
        let clone = pkcs11.clone();

        // First initialization should work.
        pkcs11
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .unwrap();

        match clone.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
            Err(Error::Pkcs11(RvError::CryptokiAlreadyInitialized, Function::Initialize)) => (), // expected
            Err(e) => panic!("Got unexpected error when initializing: {e}"),
            Ok(()) => panic!("Initializing twice should not have been allowed"),
        }

        match pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
            Err(Error::Pkcs11(RvError::CryptokiAlreadyInitialized, Function::Initialize)) => (), // expected
            Err(e) => panic!("Got unexpected error when initializing: {e}"),
            Ok(()) => panic!("Initializing twice should not have been allowed"),
        }
    }

    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn aes_key_attributes_test() -> TestResult {
    let (pkcs11, slot) = init_pins();

    // open a session
    let session = pkcs11.open_rw_session(slot)?;

    // log in the session
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // get mechanism
    let mechanism = Mechanism::AesKeyGen;

    // pub key template
    let key_template = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::Token(true),
        Attribute::Sensitive(true),
        Attribute::ValueLen(16.into()),
        Attribute::KeyType(KeyType::AES),
        Attribute::Label(b"testAES".to_vec()),
        Attribute::Private(true),
    ];

    // generate a key pair
    let key = session.generate_key(&mechanism, &key_template)?;

    let mut attributes_result =
        session.get_attributes(key, &[AttributeType::EndDate, AttributeType::StartDate])?;

    if let Some(Attribute::StartDate(date)) = attributes_result.pop() {
        assert!(date.is_empty());
    } else {
        panic!("Last attribute was not a start date");
    }

    if let Some(Attribute::EndDate(date)) = attributes_result.pop() {
        assert!(date.is_empty());
    } else {
        panic!("First attribute was not an end date");
    }

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn ro_rw_session_test() -> TestResult {
    let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01];
    let modulus = vec![0xFF; 1024];

    let template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::PublicExponent(public_exponent),
        Attribute::Modulus(modulus),
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(KeyType::RSA),
        Attribute::Verify(true),
    ];

    let (pkcs11, slot) = init_pins();

    // Try out Read-Only session
    {
        // open a session
        let ro_session = pkcs11.open_ro_session(slot)?;

        // log in the session
        ro_session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

        // generate a key pair
        // This should NOT work using the Read-Only session
        let e = ro_session.create_object(&template).unwrap_err();

        if let Error::Pkcs11(RvError::SessionReadOnly, _f) = e {
            // as expected
        } else {
            panic!("Got wrong error code (expecting SessionReadOnly): {e}");
        }
        ro_session.logout()?;
    }

    // Try out Read/Write session
    {
        // open a session
        let rw_session = pkcs11.open_rw_session(slot)?;

        // log in the session
        rw_session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

        // generate a key pair
        // This should work using the Read/Write session
        let object = rw_session.create_object(&template)?;

        // delete keys
        rw_session.destroy_object(object)?;
        rw_session.logout()?;
    }

    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn session_copy_object() -> TestResult {
    let aes128_template = [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Encrypt(true),
        Attribute::Token(false),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::ValueLen(16.into()),
        Attribute::Label("original".as_bytes().to_vec()),
    ];

    let copy_template = vec![Attribute::Label("copy".as_bytes().to_vec())];

    let insecure_copy_template = vec![Attribute::Extractable(true)];

    let (pkcs11, slot) = init_pins();

    // open a session
    let rw_session = pkcs11.open_rw_session(slot)?;

    // log in the session
    rw_session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // create a key object
    let object = rw_session.generate_key(&Mechanism::AesKeyGen, &aes128_template)?;

    // copy the object without a template
    let copy = rw_session.copy_object(object, &[])?;
    rw_session.destroy_object(copy)?;

    // copy the object with a template
    let copy = rw_session.copy_object(object, &copy_template)?;
    rw_session.destroy_object(copy)?;

    // try the copy with the insecure template. It should fail. Returning CKR_OK is considered a failure.
    rw_session
        .copy_object(object, &insecure_copy_template)
        .unwrap_err();

    // delete keys
    rw_session.destroy_object(object)?;
    rw_session.logout()?;

    rw_session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn aes_cbc_encrypt() -> TestResult {
    // Encrypt two blocks of zeros with AES-128-CBC, and zero IV
    let key = vec![0; 16];
    let iv = [0; 16];
    let plain = [0; 32];
    let expected_cipher = [
        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b,
        0x2e, 0xf7, 0x95, 0xbd, 0x4a, 0x52, 0xe2, 0x9e, 0xd7, 0x13, 0xd3, 0x13, 0xfa, 0x20, 0xe9,
        0x8d, 0xbc,
    ];

    let (pkcs11, slot) = init_pins();
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let template = [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Value(key),
        Attribute::Encrypt(true),
    ];
    let key_handle = session.create_object(&template)?;
    let mechanism = Mechanism::AesCbc(iv);
    let cipher = session.encrypt(&mechanism, key_handle, &plain)?;
    assert_eq!(expected_cipher[..], cipher[..]);
    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn aes_cbc_pad_encrypt() -> TestResult {
    // Encrypt two blocks of zeros with AES-128-CBC and PKCS#7 padding, and zero IV
    let key = vec![0; 16];
    let iv = [0; 16];
    let plain = [0; 32];
    let expected_cipher = [
        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b,
        0x2e, 0xf7, 0x95, 0xbd, 0x4a, 0x52, 0xe2, 0x9e, 0xd7, 0x13, 0xd3, 0x13, 0xfa, 0x20, 0xe9,
        0x8d, 0xbc, 0x5c, 0x04, 0x76, 0x16, 0x75, 0x6f, 0xdc, 0x1c, 0x32, 0xe0, 0xdf, 0x6e, 0x8c,
        0x59, 0xbb, 0x2a,
    ];

    let (pkcs11, slot) = init_pins();
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let template = [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Value(key),
        Attribute::Encrypt(true),
    ];
    let key_handle = session.create_object(&template)?;
    let mechanism = Mechanism::AesCbcPad(iv);
    let cipher = session.encrypt(&mechanism, key_handle, &plain)?;
    assert_eq!(expected_cipher[..], cipher[..]);
    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn update_attributes_key() -> TestResult {
    let (pkcs11, slot) = init_pins();
    // open a session
    let session = pkcs11.open_rw_session(slot)?;

    // log in the session
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // pub key template
    let pub_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
        Attribute::ModulusBits(2048.into()),
    ];

    // priv key template
    let priv_key_template = vec![Attribute::Token(true), Attribute::Extractable(true)];

    let (_public_key, private_key) = session.generate_key_pair(
        &Mechanism::RsaPkcsKeyPairGen,
        &pub_key_template,
        &priv_key_template,
    )?;

    let updated_attributes = vec![Attribute::Extractable(false)];

    session.update_attributes(private_key, &updated_attributes)?;

    let mut attributes_result =
        session.get_attributes(private_key, &[AttributeType::Extractable])?;

    if let Some(Attribute::Extractable(ext)) = attributes_result.pop() {
        assert!(!ext);
    } else {
        panic!("Last attribute was not extractable");
    }

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn sha256_digest() -> TestResult {
    let (pkcs11, slot) = init_pins();

    // open a session
    let session = pkcs11.open_rw_session(slot)?;

    // log in the session
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // data to digest
    let data = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    let want = [
        0x17, 0x22, 0x6b, 0x1f, 0x68, 0xae, 0xba, 0xcd, 0xef, 0x07, 0x46, 0x45, 0x0f, 0x64, 0x28,
        0x74, 0x63, 0x8b, 0x29, 0x57, 0x07, 0xef, 0x73, 0xfb, 0x2c, 0x6b, 0xb7, 0xf8, 0x8e, 0x89,
        0x92, 0x9f,
    ];
    let have = session.digest(&Mechanism::Sha256, &data)?;
    assert_eq!(want[..], have[..]);

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn sha256_digest_multipart() -> TestResult {
    let (pkcs11, slot) = init_pins();

    // Open a session and log in
    let session = pkcs11.open_ro_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // Data to digest
    let data = [
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    ];

    // Digest data in parts
    session.digest_init(&Mechanism::Sha256)?;
    for part in data.chunks(3) {
        session.digest_update(part)?;
    }

    let have = session.digest_final()?;
    let want = vec![
        0x8c, 0x18, 0xb1, 0x5f, 0x01, 0x47, 0x13, 0x2a, 0x03, 0xc2, 0xe3, 0xfd, 0x4f, 0x29, 0xb7,
        0x75, 0x80, 0x19, 0xb5, 0x58, 0x5e, 0xfc, 0xeb, 0x45, 0x18, 0x33, 0x2b, 0x2f, 0xa7, 0xa4,
        0x1f, 0x6e,
    ];

    assert_eq!(have, want);

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn sha256_digest_multipart_with_key() -> TestResult {
    let (pkcs11, slot) = init_pins();

    // Open a session and log in
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // Create a key to add to the digest
    let key_template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::ValueLen(AES128_BLOCK_SIZE),
        // Key must be non-sensitive and extractable to get its bytes and digest them directly, for comparison
        Attribute::Sensitive(false),
        Attribute::Extractable(true),
    ];
    let key = session.generate_key(&Mechanism::AesKeyGen, &key_template)?;

    // Data and key bytes to digest
    let mut data = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    let attributes = session.get_attributes(key, &[AttributeType::Value])?;
    let key_data = attributes.first().unwrap();
    let mut key_data = match key_data {
        Attribute::Value(key_data) => key_data.to_owned(),
        _ => unreachable!(),
    };

    // Digest data in parts
    session.digest_init(&Mechanism::Sha256)?;
    session.digest_update(&data)?;
    session.digest_key(key)?;

    // Create digests to compare
    let have = session.digest_final()?;

    data.append(&mut key_data);
    let want = session.digest(&Mechanism::Sha256, &data)?;

    assert_eq!(have, want);

    // Delete key
    session.destroy_object(key)?;

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn sha256_digest_multipart_not_initialized() -> TestResult {
    let (pkcs11, slot) = init_pins();

    // Open a session and log in
    let session = pkcs11.open_ro_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // Data to digest
    let data = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    // Attempt to update digest without an operation having been initialized
    let result = session.digest_update(&data);

    assert!(result.is_err());
    // The exact error returned is inconsistent between backends, so we only match on the function
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(_, Function::DigestUpdate)
    ));

    // Attempt to finalize digest without an operation having been initialized
    let result = session.digest_final();

    assert!(result.is_err());
    // The exact error returned is inconsistent between backends, so we only match on the function
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(_, Function::DigestFinal)
    ));

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn sha256_digest_multipart_already_initialized() -> TestResult {
    let (pkcs11, slot) = init_pins();

    // Open a session and log in
    let session = pkcs11.open_ro_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // Initialize digesting operation twice in a row
    session.digest_init(&Mechanism::Sha256)?;
    let result = session.digest_init(&Mechanism::Sha256);

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(RvError::OperationActive, Function::DigestInit)
    ));

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[cfg(target_pointer_width = "64")]
#[test]
#[serial]
fn gcm_param_graceful_failure() -> TestResult {
    // Try to generate GcmParams with max size IV (2^32-1)
    // Verify that the ulIvBits doesn't cause failover
    // setting this as a [u8] array causes stack overflow before operation has even begun
    let mut iv = vec![0; 4294967295];
    let aad = [0; 16];
    GcmParams::new(&mut iv, &aad, 96.into())?;

    Ok(())
}

#[test]
#[serial]
fn aes_gcm_no_aad() -> TestResult {
    // Currently empty AAD crashes SoftHSM, see: https://github.com/opendnssec/SoftHSMv2/issues/605
    if is_softhsm() {
        /* return Ignore(); */
        return Ok(());
    }

    // Encrypt two blocks of zeros with AES-128-GCM
    let key = vec![0; 16];
    let mut iv = [0; 12];
    let aad = [];
    let plain = [0; 32];
    let expected_cipher_and_tag = [
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe,
        0x78, 0xf7, 0x95, 0xaa, 0xab, 0x49, 0x4b, 0x59, 0x23, 0xf7, 0xfd, 0x89, 0xff, 0x94, 0x8b,
        0xc1, 0xe0, 0x40, 0x49, 0x0a, 0xf4, 0x80, 0x56, 0x06, 0xb2, 0xa3, 0xa2, 0xe7, 0x93,
    ];

    let (pkcs11, slot) = init_pins();
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let template = [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Value(key),
        Attribute::Encrypt(true),
    ];
    let key_handle = session.create_object(&template)?;
    let mechanism = Mechanism::AesGcm(GcmParams::new(&mut iv, &aad, 96.into())?);
    let cipher_and_tag = session.encrypt(&mechanism, key_handle, &plain)?;
    assert_eq!(expected_cipher_and_tag[..], cipher_and_tag[..]);
    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn aes_gcm_with_aad() -> TestResult {
    // Encrypt a block of zeros with AES-128-GCM.
    // Use another block of zeros for AAD.
    let key = vec![0; 16];
    let mut iv = [0; 12];
    let aad = [0; 16];
    let plain = [0; 16];
    let expected_cipher_and_tag = [
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe,
        0x78, 0xd2, 0x4e, 0x50, 0x3a, 0x1b, 0xb0, 0x37, 0x07, 0x1c, 0x71, 0xb3, 0x5d,
    ];

    let (pkcs11, slot) = init_pins();
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let template = [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Value(key),
        Attribute::Encrypt(true),
    ];
    let key_handle = session.create_object(&template)?;
    let gcm_params = GcmParams::new(&mut iv, &aad, 96.into())?;
    let mechanism = Mechanism::AesGcm(gcm_params);
    let cipher_and_tag = session.encrypt(&mechanism, key_handle, &plain)?;
    assert_eq!(expected_cipher_and_tag[..], cipher_and_tag[..]);
    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn encrypt_decrypt_gcm_message_no_aad() -> TestResult {
    let (pkcs11, slot) = init_pins();
    // PKCS#11 3.0 API is not supported by this token. Skip
    if !pkcs11.is_fn_supported(Function::MessageEncryptInit) {
        /* return Ignore(); */
        print!("SKIP: The PKCS#11 module does not support message based encryption");
        pkcs11.finalize()?;
        return Ok(());
    }

    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // The same input as in aes_gcm_no_aad()
    let key = vec![0; 16];
    let mut iv = [0; 12];
    let mut tag = [0; 12];
    let aad = [];
    let plain = [0; 32];
    let expected_cipher = [
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe,
        0x78, 0xf7, 0x95, 0xaa, 0xab, 0x49, 0x4b, 0x59, 0x23, 0xf7, 0xfd, 0x89, 0xff, 0x94, 0x8b,
        0xc1, 0xe0,
    ];
    let expected_tag = [
        0x40, 0x49, 0x0a, 0xf4, 0x80, 0x56, 0x06, 0xb2, 0xa3, 0xa2, 0xe7, 0x93,
    ];

    let template = [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Value(key),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
    ];
    let key_handle = session.create_object(&template)?;

    let param = GcmMessageParams::new(&mut iv, 96.into(), GeneratorFunction::NoGenerate, &mut tag)?;
    let mechanism = Mechanism::AesGcmMessage(param);
    session.message_encrypt_init(&mechanism, key_handle)?;

    let param2 = MessageParam::AesGcmMessage(param);
    let cipher = session.encrypt_message(&param2, &aad, &plain)?;
    assert_eq!(expected_cipher[..], cipher[..]);
    assert_eq!(expected_tag[..], tag[..]);
    session.message_encrypt_final()?;

    /* Do also decryption */
    let param = GcmMessageParams::new(&mut iv, 96.into(), GeneratorFunction::NoGenerate, &mut tag)?;
    let mechanism = Mechanism::AesGcmMessage(param);
    session.message_decrypt_init(&mechanism, key_handle)?;

    let param2 = MessageParam::AesGcmMessage(param);
    let plain_decrypted = session.decrypt_message(&param2, &aad, &cipher)?;
    assert_eq!(plain_decrypted[..], plain[..]);
    session.message_decrypt_final()?;
    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn encrypt_decrypt_gcm_message_with_aad() -> TestResult {
    let (pkcs11, slot) = init_pins();
    // PKCS#11 3.0 API is not supported by this token. Skip
    if !pkcs11.is_fn_supported(Function::MessageEncryptInit) {
        /* return Ignore(); */
        print!("SKIP: The PKCS#11 module does not support message based encryption");
        pkcs11.finalize()?;
        return Ok(());
    }

    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // The same input as in aes_gcm_with_aad()
    let key = vec![0; 16];
    let mut iv = [0; 12];
    let mut tag = [0; 12];
    let aad = [0; 16];
    let plain = [0; 16];
    let expected_cipher = [
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe,
        0x78,
    ];
    let expected_tag = [
        0xd2, 0x4e, 0x50, 0x3a, 0x1b, 0xb0, 0x37, 0x07, 0x1c, 0x71, 0xb3, 0x5d,
    ];

    let template = [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Value(key),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
    ];
    let key_handle = session.create_object(&template)?;

    let param = GcmMessageParams::new(&mut iv, 96.into(), GeneratorFunction::NoGenerate, &mut tag)?;
    let mechanism = Mechanism::AesGcmMessage(param);
    session.message_encrypt_init(&mechanism, key_handle)?;

    let param2 = MessageParam::AesGcmMessage(param);
    let cipher = session.encrypt_message(&param2, &aad, &plain)?;
    assert_eq!(expected_cipher[..], cipher[..]);
    assert_eq!(expected_tag[..], tag[..]);
    session.message_encrypt_final()?;

    /* Do also decryption */
    let param = GcmMessageParams::new(&mut iv, 96.into(), GeneratorFunction::NoGenerate, &mut tag)?;
    let mechanism = Mechanism::AesGcmMessage(param);
    session.message_decrypt_init(&mechanism, key_handle)?;

    let param2 = MessageParam::AesGcmMessage(param);
    let plain_decrypted = session.decrypt_message(&param2, &aad, &cipher)?;
    assert_eq!(plain_decrypted[..], plain[..]);
    session.message_decrypt_final()?;
    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn rsa_pkcs_oaep_empty() -> TestResult {
    let (pkcs11, slot) = init_pins();
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let pub_key_template = [
        Attribute::ModulusBits(2048.into()),
        Attribute::Encrypt(true),
    ];
    let priv_key_template = [Attribute::Decrypt(true)];
    let (pubkey, privkey) = session.generate_key_pair(
        &Mechanism::RsaPkcsKeyPairGen,
        &pub_key_template,
        &priv_key_template,
    )?;
    let oaep = PkcsOaepParams::new(
        MechanismType::SHA1,
        PkcsMgfType::MGF1_SHA1,
        PkcsOaepSource::empty(),
    );
    assert_eq!(MechanismType::SHA1, oaep.hash_alg());
    let encrypt_mechanism: Mechanism = Mechanism::RsaPkcsOaep(oaep);
    let encrypted_data = session.encrypt(&encrypt_mechanism, pubkey, b"Hello")?;

    let decrypted_data = session.decrypt(&encrypt_mechanism, privkey, &encrypted_data)?;
    let decrypted = String::from_utf8(decrypted_data)?;
    assert_eq!("Hello", decrypted);

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn rsa_pkcs_oaep_with_data() -> TestResult {
    /* SoftHSM does not support additional OAEP Source */
    if is_softhsm() {
        /* return Ignore(); */
        return Ok(());
    }

    let (pkcs11, slot) = init_pins();
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let pub_key_template = [
        Attribute::ModulusBits(2048.into()),
        Attribute::Encrypt(true),
    ];
    let priv_key_template = vec![Attribute::Decrypt(true)];
    let (pubkey, privkey) = session.generate_key_pair(
        &Mechanism::RsaPkcsKeyPairGen,
        &pub_key_template,
        &priv_key_template,
    )?;
    let oaep = PkcsOaepParams::new(
        MechanismType::SHA1,
        PkcsMgfType::MGF1_SHA1,
        PkcsOaepSource::data_specified(&[1, 2, 3, 4, 5, 6, 7, 8]),
    );
    let encrypt_mechanism: Mechanism = Mechanism::RsaPkcsOaep(oaep);
    let encrypted_data = session.encrypt(&encrypt_mechanism, pubkey, b"Hello")?;

    let decrypted_data = session.decrypt(&encrypt_mechanism, privkey, &encrypted_data)?;
    let decrypted = String::from_utf8(decrypted_data)?;
    assert_eq!("Hello", decrypted);

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn get_slot_event() -> TestResult {
    let (pkcs11, _slot) = init_pins();
    if is_softhsm() {
        // Not implemented in SoftHSMv2
        // https://github.com/opendnssec/SoftHSMv2/issues/370
        let event = pkcs11.get_slot_event()?;
        assert_eq!(None, event);
    } else {
        // Not implemented in Kryoptic
        pkcs11.get_slot_event().unwrap_err();
    }
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn wait_for_slot_event() {
    // Not implemented in SoftHSMv2
    // https://github.com/opendnssec/SoftHSMv2/issues/370
    let (pkcs11, _slot) = init_pins();
    let res = pkcs11.wait_for_slot_event();

    assert!(
        matches!(
            res,
            Err(Error::Pkcs11(
                RvError::FunctionNotSupported,
                Function::WaitForSlotEvent
            ))
        ),
        "res = {res:?}"
    );

    pkcs11.finalize().unwrap();
}

#[test]
#[serial]
fn generate_generic_secret_key() -> TestResult {
    let (pkcs11, slot) = init_pins();
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let key_label = Attribute::Label(b"test_generic_secret_key_gen".to_vec());
    let key_template = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
        Attribute::Token(true),
        Attribute::Sensitive(true),
        Attribute::Private(true),
        Attribute::ValueLen(512.into()),
        key_label.clone(),
    ];

    let key = session.generate_key(&Mechanism::GenericSecretKeyGen, &key_template)?;
    let attributes_result = session.find_objects(&[key_label])?.remove(0);
    assert_eq!(key, attributes_result);

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn ekdf_aes_cbc_encrypt_data() -> TestResult {
    let (pkcs11, slot) = init_pins();
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // key template
    let key_template = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Token(true),
        Attribute::Sensitive(true),
        Attribute::Private(true),
        Attribute::ValueLen(32.into()),
        Attribute::Derive(true),
    ];

    // generate master key
    let master_key_label = Attribute::Label(b"test_aes_cbc_encrypt_data_master_key".to_vec());
    let mut master_key_template = key_template.clone();
    master_key_template.insert(0, master_key_label.clone());

    let master_key = session.generate_key(&Mechanism::AesKeyGen, &master_key_template)?;
    assert_eq!(
        master_key,
        session.find_objects(&[master_key_label])?.remove(0)
    );

    // generate a derived pair
    let derived_key_label = Attribute::Label(b"test_aes_cbc_encrypt_data_child_key".to_vec());
    let mut derived_key_template = key_template.clone();
    derived_key_template.insert(0, derived_key_label.clone());

    // ============================================== IMPORTANT ==============================================
    // When using this derivation method in production, be aware that it's better to keep first bytes of data
    // filled with actual data (e.g., derivation path) - this shall cause CBC mode to propagate randomness to
    // remaining 128 bit-wide AES blocks.
    // Otherwise, if filling only last bytes, you are risking to keep first N of 128 bit-wide chunks of your
    // derived private key the same for all child keys. If deriving a key for 256-bit AES, this means half of
    // the key to be static.
    // =======================================================================================================
    let aes_cbc_derive_params = AesCbcDeriveParams::new([0u8; 16], [1u8; 32].as_slice());
    let derived_key = session.derive_key(
        &Mechanism::AesCbcEncryptData(aes_cbc_derive_params),
        master_key,
        &derived_key_template,
    )?;
    assert_eq!(
        derived_key,
        session.find_objects(&[derived_key_label])?.remove(0)
    );

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn kbkdf_counter_mode() -> TestResult {
    /* SoftHSM does not support NIST SP800-108 KDF yet */
    if is_softhsm() {
        return Ok(());
    }

    let (pkcs11, slot) = init_pins();

    // Open a session and log in
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // Generate base key
    let base_template = [
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::ValueLen(AES256_BLOCK_SIZE),
        Attribute::Derive(true),
    ];
    let base_key = session.generate_key(&Mechanism::AesKeyGen, &base_template)?;

    // The template of the key to derive
    let derived_key_template = [
        Attribute::Token(false),
        Attribute::Private(false),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::ValueLen(AES256_BLOCK_SIZE),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
    ];

    // Some variables we will use throughout
    let counter_format = KbkdfCounterFormat::new(Endianness::Big, NonZeroUsize::new(16).unwrap());
    let dkm_length_format = KbkdfDkmLengthFormat::new(
        KbkdfDkmLengthMethod::SumOfSegments,
        Endianness::Big,
        NonZeroUsize::new(32).unwrap(),
    );

    // Instantiate KBKDF in counter-mode without additional keys
    let data_params = [
        PrfDataParam::new(PrfDataParamType::IterationVariable(Some(&counter_format))),
        PrfDataParam::new(PrfDataParamType::ByteArray(b"test_label")),
        PrfDataParam::new(PrfDataParamType::ByteArray(&[0])),
        PrfDataParam::new(PrfDataParamType::ByteArray(b"\xfe\xed\xbe\xef")),
        PrfDataParam::new(PrfDataParamType::DkmLength(&dkm_length_format)),
    ];
    let params = KbkdfParams::new(MechanismType::AES_CMAC, &data_params, None);

    // Derive key
    let derived_key = session.derive_key(
        &Mechanism::KbkdfCounter(params),
        base_key,
        &derived_key_template,
    )?;

    // Verify derive key matches template
    let attributes_to_check = [
        AttributeType::Class,
        AttributeType::KeyType,
        AttributeType::ValueLen,
        AttributeType::Encrypt,
        AttributeType::Decrypt,
        AttributeType::Sign,
        AttributeType::Verify,
        AttributeType::Derive,
    ];
    let wanted_attributes = [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::ValueLen(AES256_BLOCK_SIZE),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
        Attribute::Sign(false),
        Attribute::Verify(false),
        Attribute::Derive(false),
    ];
    let have_attributes = session.get_attributes(derived_key, &attributes_to_check)?;

    for (value_wanted, value_have) in wanted_attributes.iter().zip(have_attributes.iter()) {
        assert_eq!(value_wanted, value_have);
    }

    // Delete keys
    session.destroy_object(derived_key)?;
    session.destroy_object(base_key)?;

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn kbkdf_feedback_mode() -> TestResult {
    /* SoftHSM does not support NIST SP800-108 KDF yet */
    if is_softhsm() {
        return Ok(());
    }

    let (pkcs11, slot) = init_pins();

    // Open a session and log in
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // Generate base key
    let base_template = [
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::ValueLen(AES256_BLOCK_SIZE),
        Attribute::Derive(true),
    ];
    let base_key = session.generate_key(&Mechanism::AesKeyGen, &base_template)?;

    // The template of the key to derive
    let derived_key_template = [
        Attribute::Token(false),
        Attribute::Private(false),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::ValueLen(AES256_BLOCK_SIZE),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
    ];

    // Some variables we will use throughout
    let counter_format = KbkdfCounterFormat::new(Endianness::Big, NonZeroUsize::new(16).unwrap());
    let dkm_length_format = KbkdfDkmLengthFormat::new(
        KbkdfDkmLengthMethod::SumOfKeys,
        Endianness::Big,
        NonZeroUsize::new(32).unwrap(),
    );

    /* FEEDBACK-MODE - no IV */

    // Instantiate KBKDF in feedback-mode without additional keys or an IV
    let data_params = [
        PrfDataParam::new(PrfDataParamType::IterationVariable(None)),
        PrfDataParam::new(PrfDataParamType::Counter(&counter_format)),
        PrfDataParam::new(PrfDataParamType::DkmLength(&dkm_length_format)),
    ];
    let params = KbkdfFeedbackParams::new(MechanismType::AES_CMAC, &data_params, None, None);

    // Derive key
    let derived_key_feedback_no_iv = session.derive_key(
        &Mechanism::KbkdfFeedback(params),
        base_key,
        &derived_key_template,
    )?;

    /* FEEDBACK-MODE - with IV */

    // Instantiate KBKDF in feedback-mode without additional keys but with an IV
    let data_params = [
        PrfDataParam::new(PrfDataParamType::IterationVariable(None)),
        PrfDataParam::new(PrfDataParamType::Counter(&counter_format)),
    ];
    let iv = b"sixteen bytes iv";
    let params = KbkdfFeedbackParams::new(MechanismType::AES_CMAC, &data_params, Some(iv), None);

    // Derive key
    let derived_key_feedback_iv = session.derive_key(
        &Mechanism::KbkdfFeedback(params),
        base_key,
        &derived_key_template,
    )?;

    // Verify derived keys match template
    let derived_keys = [derived_key_feedback_no_iv, derived_key_feedback_iv];

    let attributes_to_check = [
        AttributeType::Class,
        AttributeType::KeyType,
        AttributeType::ValueLen,
        AttributeType::Encrypt,
        AttributeType::Decrypt,
        AttributeType::Sign,
        AttributeType::Verify,
        AttributeType::Derive,
    ];
    let wanted_attributes = [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::ValueLen(AES256_BLOCK_SIZE),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
        Attribute::Sign(false),
        Attribute::Verify(false),
        Attribute::Derive(false),
    ];

    for key in derived_keys {
        let have_attributes = session.get_attributes(key, &attributes_to_check)?;

        for (value_wanted, value_have) in wanted_attributes.iter().zip(have_attributes.iter()) {
            assert_eq!(value_wanted, value_have);
        }
    }

    // Delete all keys
    for key in derived_keys {
        session.destroy_object(key)?;
    }
    session.destroy_object(base_key)?;

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
#[ignore = "unsupported by both SoftHSM and Kryoptic for the moment"]
fn kbkdf_double_pipeline_mode() -> TestResult {
    let (pkcs11, slot) = init_pins();

    // Open a session and log in
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // Generate base key
    let base_template = [
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::ValueLen(AES256_BLOCK_SIZE),
        Attribute::Derive(true),
    ];
    let base_key = session.generate_key(&Mechanism::AesKeyGen, &base_template)?;

    // The template of the key to derive
    let derived_key_template = [
        Attribute::Token(false),
        Attribute::Private(false),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::ValueLen(AES256_BLOCK_SIZE),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
    ];

    // Some variables we will use throughout
    let dkm_length_format = KbkdfDkmLengthFormat::new(
        KbkdfDkmLengthMethod::SumOfKeys,
        Endianness::Big,
        NonZeroUsize::new(32).unwrap(),
    );

    // Instantiate KBKDF in feedback-mode without additional keys
    let data_params = [
        PrfDataParam::new(PrfDataParamType::IterationVariable(None)),
        PrfDataParam::new(PrfDataParamType::DkmLength(&dkm_length_format)),
    ];
    let params = KbkdfParams::new(MechanismType::AES_CMAC, &data_params, None);

    // Derive key
    let derived_key = session.derive_key(
        &Mechanism::KbkdfDoublePipeline(params),
        base_key,
        &derived_key_template,
    )?;

    // Verify derive key matches template
    let attributes_to_check = [
        AttributeType::Class,
        AttributeType::KeyType,
        AttributeType::ValueLen,
        AttributeType::Encrypt,
        AttributeType::Decrypt,
        AttributeType::Sign,
        AttributeType::Verify,
        AttributeType::Derive,
    ];
    let wanted_attributes = [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::ValueLen(AES256_BLOCK_SIZE),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
        Attribute::Sign(false),
        Attribute::Verify(false),
        Attribute::Derive(false),
    ];
    let have_attributes = session.get_attributes(derived_key, &attributes_to_check)?;

    for (value_wanted, value_have) in wanted_attributes.iter().zip(have_attributes.iter()) {
        assert_eq!(value_wanted, value_have);
    }

    // Delete keys
    session.destroy_object(derived_key)?;
    session.destroy_object(base_key)?;

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn kbkdf_additional_keys_counter_mode() -> TestResult {
    /* SoftHSM does not support NIST SP800-108 KDF yet */
    if is_softhsm() {
        return Ok(());
    }

    let (pkcs11, slot) = init_pins();

    // Open a session and log in
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // Generate base key
    let base_template = [
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::ValueLen(AES256_BLOCK_SIZE),
        Attribute::Derive(true),
    ];
    let base_key = session.generate_key(&Mechanism::AesKeyGen, &base_template)?;

    // The templates of the keys to derive. We supply more than one to test deriving additional keys
    let derived_key_templates = [
        vec![
            Attribute::Token(false),
            Attribute::Private(false),
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::ValueLen(AES256_BLOCK_SIZE),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
        ],
        vec![
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::ValueLen(AES128_BLOCK_SIZE),
            Attribute::Sign(true),
            Attribute::Verify(true),
        ],
        vec![
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::ValueLen(1.into()),
            Attribute::Derive(true),
        ],
    ];

    // Some variables we will use throughout
    let counter_format = KbkdfCounterFormat::new(Endianness::Big, NonZeroUsize::new(16).unwrap());
    let dkm_length_format = KbkdfDkmLengthFormat::new(
        KbkdfDkmLengthMethod::SumOfSegments,
        Endianness::Big,
        NonZeroUsize::new(32).unwrap(),
    );

    // Instantiate KBKDF in counter-mode without additional keys
    let data_params = [
        PrfDataParam::new(PrfDataParamType::IterationVariable(Some(&counter_format))),
        PrfDataParam::new(PrfDataParamType::ByteArray(b"test_label")),
        PrfDataParam::new(PrfDataParamType::ByteArray(&[0])),
        PrfDataParam::new(PrfDataParamType::ByteArray(b"\xfe\xed\xbe\xef")),
        PrfDataParam::new(PrfDataParamType::DkmLength(&dkm_length_format)),
    ];
    let mut additional_derived_keys = derived_key_templates[1..]
        .iter()
        .map(|template| DerivedKey::new(template))
        .collect::<Vec<_>>();
    let params = KbkdfParams::new(
        MechanismType::AES_CMAC,
        &data_params,
        Some(&mut additional_derived_keys),
    );

    let mut derived_keys = vec![];

    // Derive all keys
    let main_derived_key = session.derive_key(
        &Mechanism::KbkdfCounter(params),
        base_key,
        &derived_key_templates[0],
    )?;
    let additional_derived_keys = additional_derived_keys
        .iter()
        .filter_map(|key| key.handle())
        .collect::<Vec<_>>();

    derived_keys.push(main_derived_key);
    derived_keys.extend(additional_derived_keys);

    // Verify all derived keys match template
    let attributes_to_check = [
        AttributeType::Class,
        AttributeType::KeyType,
        AttributeType::ValueLen,
        AttributeType::Encrypt,
        AttributeType::Decrypt,
        AttributeType::Sign,
        AttributeType::Verify,
        AttributeType::Derive,
    ];
    let wanted_attributes = [
        vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::ValueLen(AES256_BLOCK_SIZE),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
            Attribute::Sign(false),
            Attribute::Verify(false),
            Attribute::Derive(false),
        ],
        vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::ValueLen(AES128_BLOCK_SIZE),
            Attribute::Encrypt(false),
            Attribute::Decrypt(false),
            Attribute::Sign(true),
            Attribute::Verify(true),
            Attribute::Derive(false),
        ],
        vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::ValueLen(1.into()),
            Attribute::Encrypt(false),
            Attribute::Decrypt(false),
            Attribute::Sign(false),
            Attribute::Verify(false),
            Attribute::Derive(true),
        ],
    ];

    for (key, wanted_attributes) in derived_keys.iter().zip(wanted_attributes.iter().cycle()) {
        let have_attributes = session.get_attributes(*key, &attributes_to_check)?;

        for (value_wanted, value_have) in wanted_attributes.iter().zip(have_attributes.iter()) {
            assert_eq!(value_wanted, value_have);
        }
    }

    // Delete all keys
    for key in derived_keys {
        session.destroy_object(key)?;
    }
    session.destroy_object(base_key)?;

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn kbkdf_additional_keys_feedback_mode() -> TestResult {
    /* SoftHSM does not support NIST SP800-108 KDF yet */
    if is_softhsm() {
        return Ok(());
    }

    let (pkcs11, slot) = init_pins();

    // Open a session and log in
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // Generate base key
    let base_template = [
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::ValueLen(AES256_BLOCK_SIZE),
        Attribute::Derive(true),
    ];
    let base_key = session.generate_key(&Mechanism::AesKeyGen, &base_template)?;

    // The templates of the keys to derive. We supply more than one to test deriving additional keys
    let derived_key_templates = [
        vec![
            Attribute::Token(false),
            Attribute::Private(false),
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::ValueLen(AES256_BLOCK_SIZE),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
        ],
        vec![
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::ValueLen(AES128_BLOCK_SIZE),
            Attribute::Sign(true),
            Attribute::Verify(true),
        ],
        vec![
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::ValueLen(1.into()),
            Attribute::Derive(true),
        ],
    ];

    // Some variables we will use throughout
    let counter_format = KbkdfCounterFormat::new(Endianness::Big, NonZeroUsize::new(16).unwrap());
    let dkm_length_format = KbkdfDkmLengthFormat::new(
        KbkdfDkmLengthMethod::SumOfKeys,
        Endianness::Big,
        NonZeroUsize::new(32).unwrap(),
    );

    let mut derived_keys = vec![];

    /* FEEDBACK-MODE - no IV */

    // Instantiate KBKDF in feedback-mode without additional keys or an IV
    let data_params = [
        PrfDataParam::new(PrfDataParamType::IterationVariable(None)),
        PrfDataParam::new(PrfDataParamType::Counter(&counter_format)),
        PrfDataParam::new(PrfDataParamType::DkmLength(&dkm_length_format)),
    ];
    let mut additional_derived_keys = derived_key_templates[1..]
        .iter()
        .map(|template| DerivedKey::new(template))
        .collect::<Vec<_>>();
    let params = KbkdfFeedbackParams::new(
        MechanismType::AES_CMAC,
        &data_params,
        None,
        Some(&mut additional_derived_keys),
    );

    // Derive all keys
    let main_derived_key = session.derive_key(
        &Mechanism::KbkdfFeedback(params),
        base_key,
        &derived_key_templates[0],
    )?;
    let additional_derived_keys = additional_derived_keys
        .iter()
        .filter_map(|key| key.handle())
        .collect::<Vec<_>>();

    derived_keys.push(main_derived_key);
    derived_keys.extend(additional_derived_keys);

    /* FEEDBACK-MODE - with IV */

    // Instantiate KBKDF in feedback-mode without additional keys but with an IV
    let data_params = [
        PrfDataParam::new(PrfDataParamType::IterationVariable(None)),
        PrfDataParam::new(PrfDataParamType::Counter(&counter_format)),
    ];
    let mut additional_derived_keys = derived_key_templates[1..]
        .iter()
        .map(|template| DerivedKey::new(template))
        .collect::<Vec<_>>();
    let iv = b"sixteen bytes iv";
    let params = KbkdfFeedbackParams::new(
        MechanismType::AES_CMAC,
        &data_params,
        Some(iv),
        Some(&mut additional_derived_keys),
    );

    // Derive all keys
    let main_derived_key = session.derive_key(
        &Mechanism::KbkdfFeedback(params),
        base_key,
        &derived_key_templates[0],
    )?;
    let additional_derived_keys = additional_derived_keys
        .iter()
        .filter_map(|key| key.handle())
        .collect::<Vec<_>>();

    derived_keys.push(main_derived_key);
    derived_keys.extend(additional_derived_keys);

    // Verify all derived keys match template
    let attributes_to_check = [
        AttributeType::Class,
        AttributeType::KeyType,
        AttributeType::ValueLen,
        AttributeType::Encrypt,
        AttributeType::Decrypt,
        AttributeType::Sign,
        AttributeType::Verify,
        AttributeType::Derive,
    ];
    let wanted_attributes = [
        vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::ValueLen(AES256_BLOCK_SIZE),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
            Attribute::Sign(false),
            Attribute::Verify(false),
            Attribute::Derive(false),
        ],
        vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::ValueLen(AES128_BLOCK_SIZE),
            Attribute::Encrypt(false),
            Attribute::Decrypt(false),
            Attribute::Sign(true),
            Attribute::Verify(true),
            Attribute::Derive(false),
        ],
        vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::ValueLen(1.into()),
            Attribute::Encrypt(false),
            Attribute::Decrypt(false),
            Attribute::Sign(false),
            Attribute::Verify(false),
            Attribute::Derive(true),
        ],
    ];

    for (key, wanted_attributes) in derived_keys.iter().zip(wanted_attributes.iter().cycle()) {
        let have_attributes = session.get_attributes(*key, &attributes_to_check)?;

        for (value_wanted, value_have) in wanted_attributes.iter().zip(have_attributes.iter()) {
            assert_eq!(value_wanted, value_have);
        }
    }

    // Delete all keys
    for key in derived_keys {
        session.destroy_object(key)?;
    }
    session.destroy_object(base_key)?;

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
#[ignore = "unsupported by both SoftHSM and Kryoptic for the moment"]
fn kbkdf_additional_keys_double_pipeline_mode() -> TestResult {
    let (pkcs11, slot) = init_pins();

    // Open a session and log in
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // Generate base key
    let base_template = [
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::ValueLen(AES256_BLOCK_SIZE),
        Attribute::Derive(true),
    ];
    let base_key = session.generate_key(&Mechanism::AesKeyGen, &base_template)?;

    // The templates of the keys to derive. We supply more than one to test deriving additional keys
    let derived_key_templates = [
        vec![
            Attribute::Token(false),
            Attribute::Private(false),
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::ValueLen(AES256_BLOCK_SIZE),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
        ],
        vec![
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::ValueLen(AES128_BLOCK_SIZE),
            Attribute::Sign(true),
            Attribute::Verify(true),
        ],
        vec![
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::ValueLen(1.into()),
            Attribute::Derive(true),
        ],
    ];

    // Some variables we will use throughout
    let dkm_length_format = KbkdfDkmLengthFormat::new(
        KbkdfDkmLengthMethod::SumOfKeys,
        Endianness::Big,
        NonZeroUsize::new(32).unwrap(),
    );

    // Instantiate KBKDF in feedback-mode without additional keys
    let data_params = [
        PrfDataParam::new(PrfDataParamType::IterationVariable(None)),
        PrfDataParam::new(PrfDataParamType::DkmLength(&dkm_length_format)),
    ];
    let mut additional_derived_keys = derived_key_templates[1..]
        .iter()
        .map(|template| DerivedKey::new(template))
        .collect::<Vec<_>>();
    let params = KbkdfParams::new(
        MechanismType::AES_CMAC,
        &data_params,
        Some(&mut additional_derived_keys),
    );

    let mut derived_keys = vec![];

    // Derive all keys
    let main_derived_key = session.derive_key(
        &Mechanism::KbkdfDoublePipeline(params),
        base_key,
        &derived_key_templates[0],
    )?;
    let additional_derived_keys = additional_derived_keys
        .iter()
        .filter_map(|key| key.handle())
        .collect::<Vec<_>>();

    derived_keys.push(main_derived_key);
    derived_keys.extend(additional_derived_keys);

    // Verify all derived keys match template
    let attributes_to_check = [
        AttributeType::Class,
        AttributeType::KeyType,
        AttributeType::ValueLen,
        AttributeType::Encrypt,
        AttributeType::Decrypt,
        AttributeType::Sign,
        AttributeType::Verify,
        AttributeType::Derive,
    ];
    let wanted_attributes = [
        vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::ValueLen(AES256_BLOCK_SIZE),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
            Attribute::Sign(false),
            Attribute::Verify(false),
            Attribute::Derive(false),
        ],
        vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::ValueLen(AES128_BLOCK_SIZE),
            Attribute::Encrypt(false),
            Attribute::Decrypt(false),
            Attribute::Sign(true),
            Attribute::Verify(true),
            Attribute::Derive(false),
        ],
        vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::ValueLen(1.into()),
            Attribute::Encrypt(false),
            Attribute::Decrypt(false),
            Attribute::Sign(false),
            Attribute::Verify(false),
            Attribute::Derive(true),
        ],
    ];

    for (key, wanted_attributes) in derived_keys.iter().zip(wanted_attributes.iter().cycle()) {
        let have_attributes = session.get_attributes(*key, &attributes_to_check)?;

        for (value_wanted, value_have) in wanted_attributes.iter().zip(have_attributes.iter()) {
            assert_eq!(value_wanted, value_have);
        }
    }

    // Delete all keys
    for key in derived_keys {
        session.destroy_object(key)?;
    }
    session.destroy_object(base_key)?;

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn kbkdf_invalid_data_params_counter_mode() -> TestResult {
    /* SoftHSM does not support NIST SP800-108 KDF yet */
    if is_softhsm() {
        return Ok(());
    }

    let (pkcs11, slot) = init_pins();

    // Open a session and log in
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // Generate base key
    let base_template = [
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::ValueLen(AES256_BLOCK_SIZE),
        Attribute::Derive(true),
    ];
    let base_key = session.generate_key(&Mechanism::AesKeyGen, &base_template)?;

    // The template of the key to derive
    let derived_key_template = [
        Attribute::Token(false),
        Attribute::Private(false),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::ValueLen(AES256_BLOCK_SIZE),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
    ];

    // Some variables we will use throughout
    let counter_format = KbkdfCounterFormat::new(Endianness::Big, NonZeroUsize::new(16).unwrap());
    let dkm_length_format = KbkdfDkmLengthFormat::new(
        KbkdfDkmLengthMethod::SumOfSegments,
        Endianness::Big,
        NonZeroUsize::new(32).unwrap(),
    );

    /* MISSING ITERATION VARIABLE */

    // Instantiate KBKDF
    let data_params = [
        PrfDataParam::new(PrfDataParamType::ByteArray(b"test_label")),
        PrfDataParam::new(PrfDataParamType::ByteArray(&[0])),
        PrfDataParam::new(PrfDataParamType::ByteArray(b"\xfe\xed\xbe\xef")),
        PrfDataParam::new(PrfDataParamType::DkmLength(&dkm_length_format)),
    ];
    let params = KbkdfParams::new(MechanismType::AES_CMAC, &data_params, None);

    // Derive key
    let result = session.derive_key(
        &Mechanism::KbkdfCounter(params),
        base_key,
        &derived_key_template,
    );

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(RvError::MechanismParamInvalid, Function::DeriveKey)
    ));

    /* MISSING COUNTER FORMAT IN ITERATION VARIABLE */

    // Instantiate KBKDF
    let data_params = [
        PrfDataParam::new(PrfDataParamType::IterationVariable(None)),
        PrfDataParam::new(PrfDataParamType::ByteArray(b"test_label")),
        PrfDataParam::new(PrfDataParamType::ByteArray(&[0])),
        PrfDataParam::new(PrfDataParamType::ByteArray(b"\xfe\xed\xbe\xef")),
        PrfDataParam::new(PrfDataParamType::DkmLength(&dkm_length_format)),
    ];
    let params = KbkdfParams::new(MechanismType::AES_CMAC, &data_params, None);

    // Derive key
    let result = session.derive_key(
        &Mechanism::KbkdfCounter(params),
        base_key,
        &derived_key_template,
    );

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(RvError::MechanismParamInvalid, Function::DeriveKey)
    ));

    /* INCLUDING COUNTER */

    // Instantiate KBKDF
    let data_params = [
        PrfDataParam::new(PrfDataParamType::IterationVariable(Some(&counter_format))),
        PrfDataParam::new(PrfDataParamType::Counter(&counter_format)),
        PrfDataParam::new(PrfDataParamType::ByteArray(b"test_label")),
        PrfDataParam::new(PrfDataParamType::ByteArray(&[0])),
        PrfDataParam::new(PrfDataParamType::ByteArray(b"\xfe\xed\xbe\xef")),
        PrfDataParam::new(PrfDataParamType::DkmLength(&dkm_length_format)),
    ];
    let params = KbkdfParams::new(MechanismType::AES_CMAC, &data_params, None);

    // Derive key
    let result = session.derive_key(
        &Mechanism::KbkdfCounter(params),
        base_key,
        &derived_key_template,
    );

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(RvError::MechanismParamInvalid, Function::DeriveKey)
    ));

    /* INCLUDING MORE THAN 1 DKM LENGTH FORMAT */

    // Instantiate KBKDF
    let data_params = [
        PrfDataParam::new(PrfDataParamType::IterationVariable(Some(&counter_format))),
        PrfDataParam::new(PrfDataParamType::ByteArray(b"test_label")),
        PrfDataParam::new(PrfDataParamType::ByteArray(&[0])),
        PrfDataParam::new(PrfDataParamType::ByteArray(b"\xfe\xed\xbe\xef")),
        PrfDataParam::new(PrfDataParamType::DkmLength(&dkm_length_format)),
        PrfDataParam::new(PrfDataParamType::DkmLength(&dkm_length_format)),
    ];
    let params = KbkdfParams::new(MechanismType::AES_CMAC, &data_params, None);

    // Derive key
    let result = session.derive_key(
        &Mechanism::KbkdfCounter(params),
        base_key,
        &derived_key_template,
    );

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(RvError::MechanismParamInvalid, Function::DeriveKey)
    ));

    // Delete base key
    session.destroy_object(base_key)?;

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn kbkdf_invalid_data_params_feedback_mode() -> TestResult {
    /* SoftHSM does not support NIST SP800-108 KDF yet */
    if is_softhsm() {
        return Ok(());
    }

    let (pkcs11, slot) = init_pins();

    // Open a session and log in
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // Generate base key
    let base_template = [
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::ValueLen(AES256_BLOCK_SIZE),
        Attribute::Derive(true),
    ];
    let base_key = session.generate_key(&Mechanism::AesKeyGen, &base_template)?;

    // The template of the key to derive
    let derived_key_template = [
        Attribute::Token(false),
        Attribute::Private(false),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::ValueLen(AES256_BLOCK_SIZE),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
    ];

    // Some variables we will use throughout
    let counter_format = KbkdfCounterFormat::new(Endianness::Big, NonZeroUsize::new(16).unwrap());
    let dkm_length_format = KbkdfDkmLengthFormat::new(
        KbkdfDkmLengthMethod::SumOfKeys,
        Endianness::Big,
        NonZeroUsize::new(32).unwrap(),
    );

    /* MISSING ITERATION VARIABLE */

    // Instantiate KBKDF
    let data_params = [
        PrfDataParam::new(PrfDataParamType::ByteArray(b"test_label")),
        PrfDataParam::new(PrfDataParamType::ByteArray(&[0])),
        PrfDataParam::new(PrfDataParamType::ByteArray(b"\xfe\xed\xbe\xef")),
        PrfDataParam::new(PrfDataParamType::DkmLength(&dkm_length_format)),
    ];
    let params = KbkdfFeedbackParams::new(MechanismType::AES_CMAC, &data_params, None, None);

    // Derive key
    let result = session.derive_key(
        &Mechanism::KbkdfFeedback(params),
        base_key,
        &derived_key_template,
    );

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(RvError::MechanismParamInvalid, Function::DeriveKey)
    ));

    /* INCLUDING COUNTER FORMAT IN ITERATION VARIABLE */

    // Instantiate KBKDF
    let data_params = [
        PrfDataParam::new(PrfDataParamType::IterationVariable(Some(&counter_format))),
        PrfDataParam::new(PrfDataParamType::ByteArray(b"test_label")),
        PrfDataParam::new(PrfDataParamType::ByteArray(&[0])),
        PrfDataParam::new(PrfDataParamType::ByteArray(b"\xfe\xed\xbe\xef")),
        PrfDataParam::new(PrfDataParamType::DkmLength(&dkm_length_format)),
    ];
    let params = KbkdfFeedbackParams::new(MechanismType::AES_CMAC, &data_params, None, None);

    // Derive key
    let result = session.derive_key(
        &Mechanism::KbkdfFeedback(params),
        base_key,
        &derived_key_template,
    );

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(RvError::MechanismParamInvalid, Function::DeriveKey)
    ));

    /* INCLUDING MORE THAN 1 DKM LENGTH FORMAT */

    // Instantiate KBKDF
    let data_params = [
        PrfDataParam::new(PrfDataParamType::IterationVariable(Some(&counter_format))),
        PrfDataParam::new(PrfDataParamType::ByteArray(b"test_label")),
        PrfDataParam::new(PrfDataParamType::ByteArray(&[0])),
        PrfDataParam::new(PrfDataParamType::ByteArray(b"\xfe\xed\xbe\xef")),
        PrfDataParam::new(PrfDataParamType::DkmLength(&dkm_length_format)),
        PrfDataParam::new(PrfDataParamType::DkmLength(&dkm_length_format)),
    ];
    let params = KbkdfFeedbackParams::new(MechanismType::AES_CMAC, &data_params, None, None);

    // Derive key
    let result = session.derive_key(
        &Mechanism::KbkdfFeedback(params),
        base_key,
        &derived_key_template,
    );

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(RvError::MechanismParamInvalid, Function::DeriveKey)
    ));

    // Delete base key
    session.destroy_object(base_key)?;

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn kbkdf_invalid_data_params_double_pipeline_mode() -> TestResult {
    /* FIXME: NIST SP800-108 in double-pipeline mode is not yet supported by SoftHSM or Kryoptic */
    if true {
        return Ok(());
    }

    let (pkcs11, slot) = init_pins();

    // Open a session and log in
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // Generate base key
    let base_template = [
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::ValueLen(AES256_BLOCK_SIZE),
        Attribute::Derive(true),
    ];
    let base_key = session.generate_key(&Mechanism::AesKeyGen, &base_template)?;

    // The template of the key to derive
    let derived_key_template = [
        Attribute::Token(false),
        Attribute::Private(false),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::ValueLen(AES256_BLOCK_SIZE),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
    ];

    // Some variables we will use throughout
    let counter_format = KbkdfCounterFormat::new(Endianness::Big, NonZeroUsize::new(16).unwrap());
    let dkm_length_format = KbkdfDkmLengthFormat::new(
        KbkdfDkmLengthMethod::SumOfKeys,
        Endianness::Big,
        NonZeroUsize::new(32).unwrap(),
    );

    /* MISSING ITERATION VARIABLE */

    // Instantiate KBKDF
    let data_params = [
        PrfDataParam::new(PrfDataParamType::ByteArray(b"test_label")),
        PrfDataParam::new(PrfDataParamType::ByteArray(&[0])),
        PrfDataParam::new(PrfDataParamType::ByteArray(b"\xfe\xed\xbe\xef")),
        PrfDataParam::new(PrfDataParamType::DkmLength(&dkm_length_format)),
    ];
    let params = KbkdfParams::new(MechanismType::AES_CMAC, &data_params, None);

    // Derive key
    let result = session.derive_key(
        &Mechanism::KbkdfDoublePipeline(params),
        base_key,
        &derived_key_template,
    );

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(RvError::MechanismParamInvalid, Function::DeriveKey)
    ));

    /* INCLUDING COUNTER FORMAT IN ITERATION VARIABLE */

    // Instantiate KBKDF
    let data_params = [
        PrfDataParam::new(PrfDataParamType::IterationVariable(Some(&counter_format))),
        PrfDataParam::new(PrfDataParamType::ByteArray(b"test_label")),
        PrfDataParam::new(PrfDataParamType::ByteArray(&[0])),
        PrfDataParam::new(PrfDataParamType::ByteArray(b"\xfe\xed\xbe\xef")),
        PrfDataParam::new(PrfDataParamType::DkmLength(&dkm_length_format)),
    ];
    let params = KbkdfParams::new(MechanismType::AES_CMAC, &data_params, None);

    // Derive key
    let result = session.derive_key(
        &Mechanism::KbkdfDoublePipeline(params),
        base_key,
        &derived_key_template,
    );

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(RvError::MechanismParamInvalid, Function::DeriveKey)
    ));

    /* INCLUDING MORE THAN 1 DKM LENGTH FORMAT */

    // Instantiate KBKDF
    let data_params = [
        PrfDataParam::new(PrfDataParamType::IterationVariable(Some(&counter_format))),
        PrfDataParam::new(PrfDataParamType::ByteArray(b"test_label")),
        PrfDataParam::new(PrfDataParamType::ByteArray(&[0])),
        PrfDataParam::new(PrfDataParamType::ByteArray(b"\xfe\xed\xbe\xef")),
        PrfDataParam::new(PrfDataParamType::DkmLength(&dkm_length_format)),
        PrfDataParam::new(PrfDataParamType::DkmLength(&dkm_length_format)),
    ];
    let params = KbkdfParams::new(MechanismType::AES_CMAC, &data_params, None);

    // Derive key
    let result = session.derive_key(
        &Mechanism::KbkdfDoublePipeline(params),
        base_key,
        &derived_key_template,
    );

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(RvError::MechanismParamInvalid, Function::DeriveKey)
    ));

    // Delete base key
    session.destroy_object(base_key)?;

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn sign_verify_sha1_hmac() -> TestResult {
    let (pkcs11, slot) = init_pins();
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let priv_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Sign(true),
        Attribute::Verify(true),
        Attribute::ValueLen(256.into()),
    ];

    let private = session.generate_key(
        /* FIXME: SoftHSM does not yet support SHA-n key gen mechanisms (see https://github.com/softhsm/SoftHSMv2/issues/604) */
        if is_softhsm() {
            &Mechanism::GenericSecretKeyGen
        } else {
            &Mechanism::Sha1KeyGen
        },
        &priv_key_template,
    )?;

    let data = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    let signature = session.sign(&Mechanism::Sha1Hmac, private, &data)?;

    session.verify(&Mechanism::Sha1Hmac, private, &data, &signature)?;

    session.destroy_object(private)?;
    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn sign_verify_sha224_hmac() -> TestResult {
    let (pkcs11, slot) = init_pins();
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let priv_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Sign(true),
        Attribute::Verify(true),
        Attribute::ValueLen(256.into()),
    ];

    let private = session.generate_key(
        /* FIXME: SoftHSM does not yet support SHA-n key gen mechanisms (see https://github.com/softhsm/SoftHSMv2/issues/604) */
        if is_softhsm() {
            &Mechanism::GenericSecretKeyGen
        } else {
            &Mechanism::Sha224KeyGen
        },
        &priv_key_template,
    )?;

    let data = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    let signature = session.sign(&Mechanism::Sha224Hmac, private, &data)?;

    session.verify(&Mechanism::Sha224Hmac, private, &data, &signature)?;

    session.destroy_object(private)?;
    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn sign_verify_sha256_hmac() -> TestResult {
    let (pkcs11, slot) = init_pins();
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let priv_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Sign(true),
        Attribute::Verify(true),
        Attribute::ValueLen(256.into()),
    ];

    let private = session.generate_key(
        /* FIXME: SoftHSM does not yet support SHA-n key gen mechanisms (see https://github.com/softhsm/SoftHSMv2/issues/604) */
        if is_softhsm() {
            &Mechanism::GenericSecretKeyGen
        } else {
            &Mechanism::Sha256KeyGen
        },
        &priv_key_template,
    )?;

    let data = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    let signature = session.sign(&Mechanism::Sha256Hmac, private, &data)?;

    session.verify(&Mechanism::Sha256Hmac, private, &data, &signature)?;

    session.destroy_object(private)?;
    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn sign_verify_sha384_hmac() -> TestResult {
    let (pkcs11, slot) = init_pins();
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let priv_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Sign(true),
        Attribute::Verify(true),
        Attribute::ValueLen(256.into()),
    ];

    let private = session.generate_key(
        /* FIXME: SoftHSM does not yet support SHA-n key gen mechanisms (see https://github.com/softhsm/SoftHSMv2/issues/604) */
        if is_softhsm() {
            &Mechanism::GenericSecretKeyGen
        } else {
            &Mechanism::Sha384KeyGen
        },
        &priv_key_template,
    )?;

    let data = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    let signature = session.sign(&Mechanism::Sha384Hmac, private, &data)?;

    session.verify(&Mechanism::Sha384Hmac, private, &data, &signature)?;

    session.destroy_object(private)?;
    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn sign_verify_sha512_hmac() -> TestResult {
    let (pkcs11, slot) = init_pins();
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let priv_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Sign(true),
        Attribute::Verify(true),
        Attribute::ValueLen(256.into()),
    ];

    let private = session.generate_key(
        /* FIXME: SoftHSM does not yet support SHA-n key gen mechanisms (see https://github.com/softhsm/SoftHSMv2/issues/604) */
        if is_softhsm() {
            &Mechanism::GenericSecretKeyGen
        } else {
            &Mechanism::Sha512KeyGen
        },
        &priv_key_template,
    )?;

    let data = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    let signature = session.sign(&Mechanism::Sha512Hmac, private, &data)?;

    session.verify(&Mechanism::Sha512Hmac, private, &data, &signature)?;

    session.destroy_object(private)?;
    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

/// AES-CMAC test vectors from RFC 4493
#[test]
#[serial]
fn aes_cmac_sign() -> TestResult {
    let key: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];

    let message_len0: [u8; 0] = [];
    let expected_mac_len0: [u8; 16] = [
        0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67,
        0x46,
    ];
    aes_cmac_sign_impl(key, &message_len0, expected_mac_len0)?;

    let message_len16: [u8; 16] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a,
    ];
    let expected_mac_len16: [u8; 16] = [
        0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28,
        0x7c,
    ];
    aes_cmac_sign_impl(key, &message_len16, expected_mac_len16)?;

    let message_len40: [u8; 40] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
        0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    ];

    let expected_mac_len40: [u8; 16] = [
        0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30, 0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8,
        0x27,
    ];
    aes_cmac_sign_impl(key, &message_len40, expected_mac_len40)?;

    let message_len64: [u8; 64] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
        0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a,
        0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b,
        0xe6, 0x6c, 0x37, 0x10,
    ];
    let expected_mac_len64: [u8; 16] = [
        0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92, 0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c,
        0xfe,
    ];
    aes_cmac_sign_impl(key, &message_len64, expected_mac_len64)
}

fn aes_cmac_sign_impl(key: [u8; 16], message: &[u8], expected_mac: [u8; 16]) -> TestResult {
    let (pkcs11, slot) = init_pins();
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let key_template = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Token(true),
        Attribute::Sensitive(true),
        Attribute::Private(true),
        Attribute::Value(key.into()),
        Attribute::Sign(true),
    ];
    let key = session.create_object(&key_template)?;
    let signature = session.sign(&Mechanism::AesCMac, key, message)?;

    assert_eq!(expected_mac.as_slice(), signature.as_slice());
    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

/// AES-CMAC test vectors from RFC 4493
#[test]
#[serial]
fn aes_cmac_verify() -> TestResult {
    let key: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];

    let message_len0: [u8; 0] = [];
    let expected_mac_len0: [u8; 16] = [
        0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67,
        0x46,
    ];
    aes_cmac_verify_impl(key, &message_len0, expected_mac_len0)?;

    let message_len16: [u8; 16] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a,
    ];
    let expected_mac_len16: [u8; 16] = [
        0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28,
        0x7c,
    ];
    aes_cmac_verify_impl(key, &message_len16, expected_mac_len16)?;

    let message_len40: [u8; 40] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
        0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    ];

    let expected_mac_len40: [u8; 16] = [
        0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30, 0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8,
        0x27,
    ];
    aes_cmac_verify_impl(key, &message_len40, expected_mac_len40)?;

    let message_len64: [u8; 64] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
        0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a,
        0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b,
        0xe6, 0x6c, 0x37, 0x10,
    ];
    let expected_mac_len64: [u8; 16] = [
        0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92, 0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c,
        0xfe,
    ];
    aes_cmac_verify_impl(key, &message_len64, expected_mac_len64)
}

fn aes_cmac_verify_impl(key: [u8; 16], message: &[u8], expected_mac: [u8; 16]) -> TestResult {
    let (pkcs11, slot) = init_pins();
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let key_template = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Token(true),
        Attribute::Sensitive(true),
        Attribute::Private(true),
        Attribute::Value(key.into()),
        Attribute::Verify(true),
    ];
    let key = session.create_object(&key_template)?;
    session.verify(&Mechanism::AesCMac, key, message, &expected_mac)?;
    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn unique_id() -> TestResult {
    let (pkcs11, slot) = init_pins();
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let key: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];

    // Can not create object with Unique Id
    let key_template = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Token(true),
        Attribute::Sensitive(true),
        Attribute::Private(true),
        Attribute::Value(key.into()),
        Attribute::UniqueId(vec![0x00, 0x00, 0x00, 0x01]),
    ];
    let res = session.create_object(&key_template);
    assert!(res.is_err());
    assert!(matches!(
        res,
        Err(Error::Pkcs11(
            RvError::AttributeTypeInvalid,
            Function::CreateObject
        ))
    ));

    let generate_template = vec![
        Attribute::Token(true),
        Attribute::ValueLen(32.into()),
        Attribute::Encrypt(true),
    ];

    // generate a secret key
    let key = session.generate_key(&Mechanism::AesKeyGen, &generate_template)?;

    // we can get the UniqueId attribute
    let attrs = session.get_attributes(key, &[AttributeType::UniqueId])?;
    if is_softhsm() {
        // SoftHSM does not support this attribute at all
        assert_eq!(attrs.len(), 0);
    } else {
        assert!(matches!(attrs.first(), Some(Attribute::UniqueId(_))));
    }

    // we can not set the UniqueId attribute
    let update_template = vec![Attribute::UniqueId(vec![0x01, 0x02, 0x03])];
    let res = session.update_attributes(key, &update_template);
    assert!(res.is_err());
    if is_softhsm() {
        // SoftHSM does not support this attribute at all
        assert!(matches!(
            res,
            Err(Error::Pkcs11(
                RvError::AttributeTypeInvalid,
                Function::SetAttributeValue
            ))
        ));
    } else {
        assert!(matches!(
            res,
            Err(Error::Pkcs11(_, Function::SetAttributeValue))
        ));
    }

    session.destroy_object(key)?;

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn validation() -> TestResult {
    let (pkcs11, slot) = init_pins();
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let key: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];

    // Can not create object with ObjectValidationFlags
    let key_template = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Token(true),
        Attribute::Sensitive(true),
        Attribute::Private(true),
        Attribute::Value(key.into()),
        Attribute::ObjectValidationFlags(0x03.into()),
    ];
    let res = session.create_object(&key_template);
    assert!(res.is_err());
    assert!(matches!(
        res,
        Err(Error::Pkcs11(
            RvError::AttributeTypeInvalid,
            Function::CreateObject
        ))
    ));

    let generate_template = vec![
        Attribute::Token(true),
        Attribute::ValueLen(32.into()),
        Attribute::Encrypt(true),
    ];

    // generate a secret key
    let key = session.generate_key(&Mechanism::AesKeyGen, &generate_template)?;

    // we can get the ObjectValidationFlags attribute
    let attrs = session.get_attributes(key, &[AttributeType::ObjectValidationFlags])?;
    if is_fips(&session) {
        // Kryoptic supports the ObjectValidationFlag only if it is built as a FIPS provider
        if let Attribute::ObjectValidationFlags(flag) = attrs.first().unwrap() {
            assert_eq!(flag, &Ulong::new(1));
        } else {
            panic!("The ObjectValidationFlags attribute was expected to be present.")
        };
    } else {
        assert_eq!(attrs.len(), 0);
    }

    // we can not set the ObjectValidationFlags attribute
    let update_template = vec![Attribute::ObjectValidationFlags(0x03.into())];
    let res = session.update_attributes(key, &update_template);
    assert!(res.is_err());
    if is_softhsm() {
        // SoftHSM does not support this attribute at all
        assert!(matches!(
            res,
            Err(Error::Pkcs11(
                RvError::AttributeTypeInvalid,
                Function::SetAttributeValue
            ))
        ));
    } else {
        assert!(matches!(
            res,
            Err(Error::Pkcs11(_, Function::SetAttributeValue))
        ));
    }

    session.destroy_object(key)?;

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn object_handle_new_from_raw() -> TestResult {
    let (pkcs11, slot) = init_pins();

    // open a session
    let session = pkcs11.open_rw_session(slot)?;

    // log in the session
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // get mechanism
    let mechanism = Mechanism::RsaPkcsKeyPairGen;

    let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01];
    let modulus_bits = 2048;

    // pub key template
    let pub_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::PublicExponent(public_exponent),
        Attribute::ModulusBits(modulus_bits.into()),
        Attribute::Verify(true),
    ];

    // priv key template
    let priv_key_template = vec![Attribute::Token(true), Attribute::Sign(true)];

    // generate a key pair
    let (public, private) =
        session.generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)?;

    let private_cloned = unsafe { ObjectHandle::new_from_raw(private.handle()) };
    let public_cloned = unsafe { ObjectHandle::new_from_raw(public.handle()) };

    // data to sign
    let data = [0xFF, 0x55, 0xDD];

    // sign something with it
    let signature = session.sign(&Mechanism::RsaPkcs, private_cloned, &data)?;

    // verify the signature
    session.verify(&Mechanism::RsaPkcs, public_cloned, &data, &signature)?;

    // delete keys
    session.destroy_object(public)?;
    session.destroy_object(private)?;

    session.close()?;
    pkcs11.finalize()?;

    Ok(())
}

#[test]
#[serial]
fn get_attributes_test() -> TestResult {
    let (pkcs11, slot) = init_pins();

    // open a session
    let session = pkcs11.open_rw_session(slot)?;

    // log in the session
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    // get mechanism
    let mechanism = Mechanism::RsaPkcsKeyPairGen;

    let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01];
    let modulus_bits = 2048;

    // pub key template
    let pub_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::PublicExponent(public_exponent.clone()),
        Attribute::ModulusBits(modulus_bits.into()),
        Attribute::Verify(true),
    ];

    // priv key template
    let priv_key_template = vec![
        Attribute::Token(true),
        Attribute::Sign(true),
        Attribute::Private(true),
    ];

    // generate a key pair
    let (public, private) =
        session.generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)?;

    // Test get_attributes_fast with various attribute types
    let attributes_to_check = vec![
        AttributeType::Class,
        AttributeType::KeyType,
        AttributeType::Token,
        AttributeType::Private,
        AttributeType::Modulus,
        AttributeType::PublicExponent,
        AttributeType::Verify,
        AttributeType::ModulusBits,
    ];

    // Test 1: Get multiple attributes from public key
    let attrs = session.get_attributes(public, &attributes_to_check)?;

    // Check that we got the expected attributes
    assert!(!attrs.is_empty(), "No attributes returned");

    // Verify specific attributes
    let has_class = attrs.iter().any(|attr| matches!(attr, Attribute::Class(_)));
    let has_key_type = attrs
        .iter()
        .any(|attr| matches!(attr, Attribute::KeyType(_)));
    let has_modulus = attrs
        .iter()
        .any(|attr| matches!(attr, Attribute::Modulus(_)));
    let has_public_exp = attrs
        .iter()
        .any(|attr| matches!(attr, Attribute::PublicExponent(_)));

    assert!(has_class, "Class attribute not found");
    assert!(has_key_type, "KeyType attribute not found");
    assert!(has_modulus, "Modulus attribute not found");
    assert!(has_public_exp, "PublicExponent attribute not found");

    // Verify the public exponent value matches what we set
    for attr in &attrs {
        if let Attribute::PublicExponent(exp) = attr {
            assert_eq!(exp, &public_exponent, "Public exponent mismatch");
        }
    }

    // Test 2: Get multiple attributes from private key
    let priv_attributes_to_check = vec![
        AttributeType::Class,
        AttributeType::KeyType,
        AttributeType::Token,
        AttributeType::Private,
        AttributeType::Sign,
    ];

    let priv_attrs = session.get_attributes(private, &priv_attributes_to_check)?;

    assert!(!priv_attrs.is_empty(), "No private key attributes returned");

    // Test 3: Single attribute with known fixed length (CK_ULONG)
    let single_fixed = vec![AttributeType::KeyType];
    let attrs_single_fixed = session.get_attributes(public, &single_fixed)?;
    assert_eq!(
        attrs_single_fixed.len(),
        1,
        "Should return exactly 1 attribute"
    );
    assert!(
        matches!(attrs_single_fixed[0], Attribute::KeyType(_)),
        "Should be KeyType attribute"
    );

    // Test 4: Single attribute with variable length
    let single_variable = vec![AttributeType::Modulus];
    let attrs_single_variable = session.get_attributes(public, &single_variable)?;
    assert_eq!(
        attrs_single_variable.len(),
        1,
        "Should return exactly 1 attribute"
    );
    assert!(
        matches!(attrs_single_variable[0], Attribute::Modulus(_)),
        "Should be Modulus attribute"
    );

    // Test 5: Single attribute that doesn't exist for this object (EC point for RSA key)
    let single_invalid = vec![AttributeType::EcPoint];
    let attrs_single_invalid = session.get_attributes(public, &single_invalid)?;
    assert_eq!(
        attrs_single_invalid.len(),
        0,
        "Should return 0 attributes for invalid attribute type"
    );

    // delete keys
    session.destroy_object(public)?;
    session.destroy_object(private)?;

    Ok(())
}
