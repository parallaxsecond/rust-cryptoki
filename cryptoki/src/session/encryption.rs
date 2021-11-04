// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Encrypting data

use crate::error::{Result, Rv};
use crate::mechanism::Mechanism;
use crate::object::ObjectHandle;
use crate::session::Session;
use cryptoki_sys::*;
use std::convert::TryInto;

// See public docs on stub in parent mod.rs
#[inline(always)]
pub fn encrypt(
    session: &Session,
    mechanism: &Mechanism,
    key: ObjectHandle,
    data: &[u8],
) -> Result<Vec<u8>> {
    let mut mechanism: CK_MECHANISM = mechanism.into();
    let mut encrypted_data_len = 0;

    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_EncryptInit)(
            session.handle(),
            &mut mechanism as CK_MECHANISM_PTR,
            key.handle(),
        ))
        .into_result()?;
    }

    // Get the output buffer length
    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_Encrypt)(
            session.handle(),
            data.as_ptr() as *mut u8,
            data.len().try_into()?,
            std::ptr::null_mut(),
            &mut encrypted_data_len,
        ))
        .into_result()?;
    }

    let mut encrypted_data = vec![0; encrypted_data_len.try_into()?];

    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_Encrypt)(
            session.handle(),
            data.as_ptr() as *mut u8,
            data.len().try_into()?,
            encrypted_data.as_mut_ptr(),
            &mut encrypted_data_len,
        ))
        .into_result()?;
    }

    encrypted_data.resize(encrypted_data_len.try_into()?, 0);

    Ok(encrypted_data)
}
