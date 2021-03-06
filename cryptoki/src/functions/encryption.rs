// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Encrypting data

use crate::get_pkcs11;
use crate::types::function::Rv;
use crate::types::mechanism::Mechanism;
use crate::types::object::ObjectHandle;
use crate::types::session::Session;
use crate::Result;
use cryptoki_sys::*;
use std::convert::TryInto;

impl<'a> Session<'a> {
    /// Single-part encryption operation
    pub fn encrypt(
        &self,
        mechanism: &Mechanism,
        key: ObjectHandle,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut mechanism: CK_MECHANISM = mechanism.into();
        let mut encrypted_data_len = 0;

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_EncryptInit)(
                self.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                key.handle(),
            ))
            .into_result()?;
        }

        // Get the output buffer length
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_Encrypt)(
                self.handle(),
                data.as_ptr() as *mut u8,
                data.len().try_into()?,
                std::ptr::null_mut(),
                &mut encrypted_data_len,
            ))
            .into_result()?;
        }

        let mut encrypted_data = vec![0; encrypted_data_len.try_into()?];

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_Encrypt)(
                self.handle(),
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
}
