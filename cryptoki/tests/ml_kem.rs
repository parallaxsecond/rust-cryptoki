// Copyright 2025 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod common;

use crate::common::{init_pins, USER_PIN};
use cryptoki::context::Function;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, MlKemParameterSetType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use serial_test::serial;

use testresult::TestResult;

#[test]
#[serial]
fn ml_kem() -> TestResult {
    let (pkcs11, slot) = init_pins();
    // PKCS#11 3.2 API is not supported by this token. Skip
    if !pkcs11.is_fn_supported(Function::EncapsulateKey) {
        /* return Ignore(); */
        print!("SKIP: The PKCS#11 module does not support encapsulation API");
        return Ok(());
    }

    // open a session
    let session = pkcs11.open_rw_session(slot)?;

    // log in the session
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let mechanism = Mechanism::MlKemKeyPairGen;

    // pub key template
    let pub_key_template = vec![
        Attribute::Token(true),
        Attribute::ParameterSet(MlKemParameterSetType::ML_KEM_768.into()),
        Attribute::Encapsulate(true),
    ];

    // priv key template
    let priv_key_template = vec![Attribute::Token(true), Attribute::Decapsulate(true)];

    // generate a key pair
    let (public, private) =
        session.generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)?;

    let secret_template = vec![
        Attribute::Token(true),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Sensitive(false),
        Attribute::Extractable(true),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
    ];

    let mechanism = Mechanism::MlKem;

    let (ciphertext, secret) = session.encapsulate_key(&mechanism, public, &secret_template)?;

    let secret2 = session.decapsulate_key(&mechanism, private, &secret_template, &ciphertext)?;

    // The secret and secret2 keys should be the same now. Try to extract them and compare
    let value_attribute = session
        .get_attributes(secret, &[AttributeType::Value])?
        .remove(0);
    let value = if let Attribute::Value(value) = value_attribute {
        value
    } else {
        panic!("Expected value attribute.");
    };
    let value_attribute2 = session
        .get_attributes(secret2, &[AttributeType::Value])?
        .remove(0);
    let value2 = if let Attribute::Value(value) = value_attribute2 {
        value
    } else {
        panic!("Expected value attribute.");
    };
    assert_eq!(value, value2);

    // Test the generated keys can do some encryption/decryption operation
    let data = vec![
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    // Encrypt data with first key and decrypt with the other
    let ctext = session.encrypt(&Mechanism::AesEcb, secret, &data)?;
    let ptext = session.decrypt(&Mechanism::AesEcb, secret2, &ctext)?;
    assert_eq!(data, ptext);
    // and vice versa
    let ctext = session.encrypt(&Mechanism::AesEcb, secret2, &data)?;
    let ptext = session.decrypt(&Mechanism::AesEcb, secret, &ctext)?;
    assert_eq!(data, ptext);

    // delete keys
    session.destroy_object(public)?;
    session.destroy_object(private)?;
    session.destroy_object(secret)?;
    session.destroy_object(secret2)?;

    Ok(())
}
