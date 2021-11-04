// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Signing and authentication functions

use crate::error::{Result, Rv};
use crate::mechanism::Mechanism;
use crate::object::ObjectHandle;
use crate::session::Session;
use cryptoki_sys::*;
use std::convert::TryInto;

// See public docs on stub in parent mod.rs
pub(super) fn sign(
    session: &Session<'_>,
    mechanism: &Mechanism,
    key: ObjectHandle,
    data: &[u8],
) -> Result<Vec<u8>> {
    let mut mechanism: CK_MECHANISM = mechanism.into();
    let mut signature_len = 0;

    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_SignInit)(
            session.handle(),
            &mut mechanism as CK_MECHANISM_PTR,
            key.handle(),
        ))
        .into_result()?;
    }

    // Get the output buffer length
    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_Sign)(
            session.handle(),
            data.as_ptr() as *mut u8,
            data.len().try_into()?,
            std::ptr::null_mut(),
            &mut signature_len,
        ))
        .into_result()?;
    }

    let mut signature = vec![0; signature_len.try_into()?];

    //TODO: we should add a new error instead of those unwrap!
    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_Sign)(
            session.handle(),
            data.as_ptr() as *mut u8,
            data.len().try_into()?,
            signature.as_mut_ptr(),
            &mut signature_len,
        ))
        .into_result()?;
    }

    signature.resize(signature_len.try_into()?, 0);

    Ok(signature)
}

// See public docs on stub in parent mod.rs
pub(super) fn verify(
    session: &Session<'_>,
    mechanism: &Mechanism,
    key: ObjectHandle,
    data: &[u8],
    signature: &[u8],
) -> Result<()> {
    let mut mechanism: CK_MECHANISM = mechanism.into();

    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_VerifyInit)(
            session.handle(),
            &mut mechanism as CK_MECHANISM_PTR,
            key.handle(),
        ))
        .into_result()?;
    }

    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_Verify)(
            session.handle(),
            data.as_ptr() as *mut u8,
            data.len().try_into()?,
            signature.as_ptr() as *mut u8,
            signature.len().try_into()?,
        ))
        .into_result()
    }
}
