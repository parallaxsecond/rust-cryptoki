// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

mod common;

use crate::common::{get_pkcs11_path, USER_PIN};
use common::{get_pkcs11_from_self, init_pins_from_pkcs11};
use cryptoki::context::Function;
use cryptoki::error::{Result, Rv};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use cryptoki_sys::{
    CK_ATTRIBUTE, CK_MECHANISM, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE,
    CK_ULONG,
};
use libloading::os::unix::{RTLD_GLOBAL, RTLD_NOW};
use serial_test::serial;

use testresult::TestResult;

type C_DeriveKey = unsafe extern "C" fn(
    arg1: CK_SESSION_HANDLE,
    arg2: *mut CK_MECHANISM,
    arg3: CK_OBJECT_HANDLE,
    arg4: *mut CK_ATTRIBUTE,
    arg5: CK_ULONG,
    arg6: *mut CK_OBJECT_HANDLE,
) -> CK_RV;

#[cfg(not(target_os = "windows"))]
fn load_library(library_path: String) -> libloading::Library {
    unsafe {
        libloading::os::unix::Library::open(Some(library_path), RTLD_NOW | RTLD_GLOBAL)
            .unwrap()
            .into()
    }
}

#[cfg(target_os = "windows")]
fn load_library(library_path: String) -> libloading::Library {
    unsafe { ::libloading::Library::new(library_path).unwrap().into() }
}

fn load_from_library(library_path: String) -> Result<(libloading::Library, C_DeriveKey)> {
    let library = load_library(library_path);

    let C_DeriveKey = unsafe { library.get(b"C_DeriveKey\0").map(|sym| *sym) }?;

    Ok((library, C_DeriveKey))
}

trait VendorDeriveKey {
    fn vendor_derive_key(
        &self,
        vendor_fn: C_DeriveKey,
        mechanism: &Mechanism,
        base_key: ObjectHandle,
        template: &[Attribute],
    ) -> Result<ObjectHandle>;
}

impl VendorDeriveKey for Session {
    /// re-implement derive_key to test unsafe accessors for vendor extensions
    fn vendor_derive_key(
        &self,
        vendor_fn: C_DeriveKey,
        mechanism: &Mechanism,
        base_key: ObjectHandle,
        template: &[Attribute],
    ) -> Result<ObjectHandle> {
        let mut mechanism: CK_MECHANISM = mechanism.into();
        let mut template: Vec<CK_ATTRIBUTE> = template.iter().map(|attr| attr.into()).collect();
        let mut handle = 0;
        unsafe {
            Rv::from(vendor_fn(
                self.raw_handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                base_key.raw_handle(),
                template.as_mut_ptr(),
                template.len().try_into()?,
                &mut handle,
            ))
            .into_result(Function::DeriveKey)?;

            Ok(ObjectHandle::new_from_raw(handle))
        }
    }
}

#[test]
#[serial]
fn unsafe_accessors_for_vendor_extension() -> TestResult {
    let (_library, C_DeriveKey) = load_from_library(get_pkcs11_path())?;
    let pkcs11 = get_pkcs11_from_self();
    let slot = init_pins_from_pkcs11(&pkcs11);

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

    let shared_secret = session.vendor_derive_key(
        C_DeriveKey,
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

    Ok(())
}
