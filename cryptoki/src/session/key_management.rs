// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Key management functions

use crate::error::{Result, Rv};
use crate::mechanism::Mechanism;
use crate::object::{Attribute, ObjectHandle};
use crate::session::Session;
use cryptoki_sys::{CK_ATTRIBUTE, CK_MECHANISM, CK_MECHANISM_PTR};
use std::convert::TryInto;

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn generate_key(
    session: &Session<'_>,
    mechanism: &Mechanism,
    template: &[Attribute],
) -> Result<ObjectHandle> {
    let mut mechanism: CK_MECHANISM = mechanism.into();
    let mut template: Vec<CK_ATTRIBUTE> = template.iter().map(|attr| attr.into()).collect();
    let mut handle = 0;
    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_GenerateKey)(
            session.handle(),
            &mut mechanism as CK_MECHANISM_PTR,
            template.as_mut_ptr(),
            template.len().try_into()?,
            &mut handle,
        ))
        .into_result()?;
    }

    Ok(ObjectHandle::new(handle))
}

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn generate_key_pair(
    session: &Session<'_>,
    mechanism: &Mechanism,
    pub_key_template: &[Attribute],
    priv_key_template: &[Attribute],
) -> Result<(ObjectHandle, ObjectHandle)> {
    let mut mechanism: CK_MECHANISM = mechanism.into();
    let mut pub_key_template: Vec<CK_ATTRIBUTE> =
        pub_key_template.iter().map(|attr| attr.into()).collect();
    let mut priv_key_template: Vec<CK_ATTRIBUTE> =
        priv_key_template.iter().map(|attr| attr.into()).collect();
    let mut pub_handle = 0;
    let mut priv_handle = 0;
    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_GenerateKeyPair)(
            session.handle(),
            &mut mechanism as CK_MECHANISM_PTR,
            pub_key_template.as_mut_ptr(),
            pub_key_template.len().try_into()?,
            priv_key_template.as_mut_ptr(),
            priv_key_template.len().try_into()?,
            &mut pub_handle,
            &mut priv_handle,
        ))
        .into_result()?;
    }

    Ok((
        ObjectHandle::new(pub_handle),
        ObjectHandle::new(priv_handle),
    ))
}

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn derive_key(
    session: &Session<'_>,
    mechanism: &Mechanism,
    base_key: ObjectHandle,
    template: &[Attribute],
) -> Result<ObjectHandle> {
    let mut mechanism: CK_MECHANISM = mechanism.into();
    let mut template: Vec<CK_ATTRIBUTE> = template.iter().map(|attr| attr.into()).collect();
    let mut handle = 0;
    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_DeriveKey)(
            session.handle(),
            &mut mechanism as CK_MECHANISM_PTR,
            base_key.handle(),
            template.as_mut_ptr(),
            template.len().try_into()?,
            &mut handle,
        ))
        .into_result()?;
    }

    Ok(ObjectHandle::new(handle))
}

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn wrap_key(
    session: &Session<'_>,
    mechanism: &Mechanism,
    wrapping_key: ObjectHandle,
    key: ObjectHandle,
) -> Result<Vec<u8>> {
    let mut mechanism: CK_MECHANISM = mechanism.into();
    unsafe {
        let mut wrapped_key_len = 0;

        Rv::from(get_pkcs11!(session.client(), C_WrapKey)(
            session.handle(),
            &mut mechanism as CK_MECHANISM_PTR,
            wrapping_key.handle(),
            key.handle(),
            std::ptr::null_mut(),
            &mut wrapped_key_len,
        ))
        .into_result()?;

        let mut wrapped_key = vec![0; wrapped_key_len.try_into()?];

        Rv::from(get_pkcs11!(session.client(), C_WrapKey)(
            session.handle(),
            &mut mechanism as CK_MECHANISM_PTR,
            wrapping_key.handle(),
            key.handle(),
            wrapped_key.as_mut_ptr(),
            &mut wrapped_key_len,
        ))
        .into_result()?;

        Ok(wrapped_key)
    }
}

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn unwrap_key(
    session: &Session<'_>,
    mechanism: &Mechanism,
    unwrapping_key: ObjectHandle,
    wrapped_key: &[u8],
    template: &[Attribute],
) -> Result<ObjectHandle> {
    let mut mechanism: CK_MECHANISM = mechanism.into();
    let mut template: Vec<CK_ATTRIBUTE> = template.iter().map(|attr| attr.into()).collect();
    let mut handle = 0;
    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_UnwrapKey)(
            session.handle(),
            &mut mechanism as CK_MECHANISM_PTR,
            unwrapping_key.handle(),
            wrapped_key.as_ptr() as *mut u8,
            wrapped_key.len().try_into()?,
            template.as_mut_ptr(),
            template.len().try_into()?,
            &mut handle,
        ))
        .into_result()?;
    }

    Ok(ObjectHandle::new(handle))
}
