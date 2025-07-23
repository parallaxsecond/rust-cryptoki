// Copyright 2025 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod common;

use crate::common::{init_pins, USER_PIN};
use cryptoki::context::Function;
use cryptoki::error::{Error, RvError};
use cryptoki::mechanism::mldsa::{HashSignAdditionalContext, HedgeType, SignAdditionalContext};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, MlDsaParameterSetType};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use serial_test::serial;

use testresult::TestResult;

#[test]
#[serial]
fn ml_dsa() -> TestResult {
    let (pkcs11, slot) = init_pins();
    // PKCS#11 3.2 API is not supported by this token. Skip
    if !pkcs11.is_fn_supported(Function::VerifySignature) {
        /* return Ignore(); */
        print!("SKIP: The PKCS#11 module does not support VerifySignature API");
        return Ok(());
    }

    // open a session
    let session = pkcs11.open_rw_session(slot)?;

    // log in the session
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let mechanism = Mechanism::MlDsaKeyPairGen;

    // pub key template
    let pub_key_template = vec![
        Attribute::Token(true),
        Attribute::ParameterSet(MlDsaParameterSetType::ML_DSA_65.into()),
        Attribute::Verify(true),
    ];

    // priv key template
    let priv_key_template = vec![Attribute::Token(true), Attribute::Sign(true)];

    // generate a key pair
    let (public, private) =
        session.generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)?;

    // without optional context
    let mechanism = Mechanism::MlDsa(SignAdditionalContext::new(HedgeType::Preferred, None));

    // data to sign
    let data = [0xFF, 0x55, 0xDD];

    let signature1 = session.sign(&mechanism, private, &data)?;

    session.verify(&mechanism, public, &data, &signature1)?;

    // also using the new API
    session.verify_signature_init(&mechanism, public, &signature1)?;
    session.verify_signature(&data)?;

    // With Context + Deterministic Hedge
    let context = [
        0xEE, 0x0B, 0x3F, 0x67, 0x9F, 0xB5, 0x0F, 0x59, 0xAD, 0x31, 0x32, 0x8A, 0xAF, 0x4E, 0x70,
        0x2C, 0xCF, 0x60, 0x92, 0xDA, 0x47, 0x94, 0xDC, 0xF0, 0x7C, 0x8, 0xEA, 0x27, 0x8B, 0x34,
        0x22, 0x8A, 0x41,
    ];
    let mechanism = Mechanism::MlDsa(SignAdditionalContext::new(
        HedgeType::DeterministicRequired,
        Some(&context),
    ));

    let signature2 = session.sign(&mechanism, private, &data)?;
    let signature3 = session.sign(&mechanism, private, &data)?;
    // Deterministic signature
    assert_eq!(signature2, signature3);

    session.verify(&mechanism, public, &data, &signature2)?;

    // also using the new API
    session.verify_signature_init(&mechanism, public, &signature2)?;
    session.verify_signature(&data)?;

    // the signature from previous step should fail to verify with different context
    let result = session.verify(&mechanism, public, &data, &signature1);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(_, Function::Verify)
    ));

    // also using the new API
    session.verify_signature_init(&mechanism, public, &signature1)?;
    let result = session.verify_signature(&data);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(_, Function::VerifySignature)
    ));

    // Test convrting ParameterSet attributes back to algorithm specific values
    let param_attribute = session
        .get_attributes(public, &[AttributeType::ParameterSet])?
        .remove(0);
    let param: MlDsaParameterSetType = if let Attribute::ParameterSet(num) = param_attribute {
        num.into()
    } else {
        panic!("Expected ParameterSet attribute.");
    };
    assert_eq!(param, MlDsaParameterSetType::ML_DSA_65);

    // delete keys
    session.destroy_object(public)?;
    session.destroy_object(private)?;

    Ok(())
}

#[test]
#[serial]
fn ml_dsa_multipart() -> TestResult {
    let (pkcs11, slot) = init_pins();
    // PKCS#11 3.2 API is not supported by this token. Skip
    if !pkcs11.is_fn_supported(Function::VerifySignature) {
        /* return Ignore(); */
        print!("SKIP: The PKCS#11 module does not support VerifySignature API");
        return Ok(());
    }

    // open a session
    let session = pkcs11.open_rw_session(slot)?;

    // log in the session
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let mechanism = Mechanism::MlDsaKeyPairGen;

    // pub key template
    let pub_key_template = vec![
        Attribute::Token(true),
        Attribute::ParameterSet(MlDsaParameterSetType::ML_DSA_87.into()),
        Attribute::Verify(true),
    ];

    // priv key template
    let priv_key_template = vec![Attribute::Token(true), Attribute::Sign(true)];

    // generate a key pair
    let (public, private) =
        session.generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)?;

    // without optional context
    let mechanism = Mechanism::MlDsa(SignAdditionalContext::new(HedgeType::Required, None));

    // data to sign
    let data = [
        0x1E, 0x5A, 0x78, 0xAD, 0x64, 0xDF, 0x22, 0x9A, 0xA2, 0x2F, 0xD7, 0x94, 0xEC, 0x0E, 0x82,
        0xD0, 0xF6, 0x99, 0x53, 0x11, 0x8C, 0x09, 0xD1, 0x34, 0xDF, 0xA2, 0x0F, 0x1C, 0xC6, 0x4A,
        0x36, 0x71,
    ];

    session.sign_init(&mechanism, private)?;
    for part in data.chunks(10) {
        session.sign_update(part)?;
    }
    let signature = session.sign_final()?;

    // verification of multi-part signature
    session.verify_init(&mechanism, public)?;
    for part in data.chunks(10) {
        session.verify_update(part)?;
    }
    session.verify_final(&signature)?;

    // but works with the new API
    session.verify_signature_init(&mechanism, public, &signature)?;
    for part in data.chunks(10) {
        session.verify_signature_update(part)?;
    }
    session.verify_signature_final()?;

    // delete keys
    session.destroy_object(public)?;
    session.destroy_object(private)?;

    Ok(())
}

#[test]
#[serial]
fn ml_dsa_hash() -> TestResult {
    let (pkcs11, slot) = init_pins();
    // PKCS#11 3.2 API is not supported by this token. Skip
    if !pkcs11.is_fn_supported(Function::VerifySignature) {
        /* return Ignore(); */
        print!("SKIP: The PKCS#11 module does not support VerifySignature API");
        return Ok(());
    }

    // open a session
    let session = pkcs11.open_rw_session(slot)?;

    // log in the session
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let mechanism = Mechanism::MlDsaKeyPairGen;

    // pub key template
    let pub_key_template = vec![
        Attribute::Token(true),
        Attribute::ParameterSet(MlDsaParameterSetType::ML_DSA_44.into()),
        Attribute::Verify(true),
    ];

    // priv key template
    let priv_key_template = vec![Attribute::Token(true), Attribute::Sign(true)];

    // generate a key pair
    let (public, private) =
        session.generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)?;

    // without optional context
    let mechanism = Mechanism::HashMlDsa(HashSignAdditionalContext::new(
        HedgeType::Preferred,
        None,
        MechanismType::SHA384,
    ));

    // data to sign is already sha384 hash!
    let data = [
        0x1E, 0x5A, 0x78, 0xAD, 0x64, 0xDF, 0x22, 0x9A, 0xA2, 0x2F, 0xD7, 0x94, 0xEC, 0x0E, 0x82,
        0xD0, 0xF6, 0x99, 0x53, 0x11, 0x8C, 0x09, 0xD1, 0x34, 0xDF, 0xA2, 0x0F, 0x1C, 0xC6, 0x4A,
        0xD0, 0xF6, 0x99, 0x53, 0x11, 0x8C, 0x09, 0xD1, 0x34, 0xDF, 0xA2, 0x0F, 0x1C, 0xC6, 0x4A,
        0x36, 0x71, 0x31,
    ];

    // the hash ML-DSA does not support multi-part operation
    session.sign_init(&mechanism, private)?;
    let result = session.sign_update(&data[..10]);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(RvError::OperationNotInitialized, Function::SignUpdate)
    ));

    // this should do with one-shot
    let signature = session.sign(&mechanism, private, &data)?;

    // verification of multi-part signature does not work here either
    session.verify_init(&mechanism, public)?;
    let result = session.verify_update(&data[..10]);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(RvError::OperationNotInitialized, Function::VerifyUpdate)
    ));

    // this should do with one-shot
    session.verify(&mechanism, public, &data, &signature)?;

    // multipart verification does not work with the new API either
    session.verify_signature_init(&mechanism, public, &signature)?;
    let result = session.verify_signature_update(&data[..10]);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Pkcs11(
            RvError::OperationNotInitialized,
            Function::VerifySignatureUpdate
        )
    ));

    // should work with one-shot new API
    session.verify_signature_init(&mechanism, public, &signature)?;
    session.verify_signature(&data)?;

    // delete keys
    session.destroy_object(public)?;
    session.destroy_object(private)?;

    Ok(())
}

#[test]
#[serial]
fn ml_dsa_hashes() -> TestResult {
    let (pkcs11, slot) = init_pins();
    // PKCS#11 3.2 API is not supported by this token. Skip
    if !pkcs11.is_fn_supported(Function::VerifySignature) {
        /* return Ignore(); */
        print!("SKIP: The PKCS#11 module does not support VerifySignature API");
        return Ok(());
    }

    // open a session
    let session = pkcs11.open_rw_session(slot)?;

    // log in the session
    session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;

    let mechanism = Mechanism::MlDsaKeyPairGen;

    // pub key template
    let pub_key_template = vec![
        Attribute::Token(true),
        Attribute::ParameterSet(MlDsaParameterSetType::ML_DSA_65.into()),
        Attribute::Verify(true),
    ];

    // priv key template
    let priv_key_template = vec![Attribute::Token(true), Attribute::Sign(true)];

    // generate a key pair
    let (public, private) =
        session.generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)?;

    // without optional context
    let mechanism =
        Mechanism::HashMlDsaSha3_224(SignAdditionalContext::new(HedgeType::Required, None));

    let data = [
        0xD0, 0xF6, 0x99, 0x53, 0x11, 0x8C, 0x09, 0xD1, 0x34, 0xDF, 0xA2, 0x0F, 0x1C, 0xC6, 0x4A,
        0x1E, 0x5A, 0x78, 0xAD, 0x64, 0xDF, 0x22, 0x9A, 0xA2, 0x2F, 0xD7, 0x94, 0xEC, 0x0E, 0x82,
    ];

    // first try multipart
    session.sign_init(&mechanism, private)?;
    for part in data.chunks(10) {
        session.sign_update(part)?;
    }
    let signature = session.sign_final()?;

    // this should do with one-shot
    let signature2 = session.sign(&mechanism, private, &data)?;

    // first try multipart
    session.verify_init(&mechanism, public)?;
    for part in data.chunks(10) {
        session.verify_update(part)?;
    }
    session.verify_final(&signature)?;

    // this should do with one-shot
    session.verify(&mechanism, public, &data, &signature)?;

    // first try multipart
    session.verify_signature_init(&mechanism, public, &signature2)?;
    for part in data.chunks(10) {
        session.verify_signature_update(part)?;
    }
    session.verify_signature_final()?;

    // should work with one-shot new API
    session.verify_signature_init(&mechanism, public, &signature2)?;
    session.verify_signature(&data)?;

    // delete keys
    session.destroy_object(public)?;
    session.destroy_object(private)?;

    Ok(())
}
