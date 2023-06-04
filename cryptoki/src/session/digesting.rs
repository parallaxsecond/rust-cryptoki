// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Digesting functions

use crate::context::Function;
use crate::error::{Result, Rv};
use crate::mechanism::Mechanism;
use crate::session::Session;
use cryptoki_sys::*;
use std::convert::TryInto;

impl Session {
    /// Single-part digesting operation
    pub fn digest(&self, m: &Mechanism, data: &[u8]) -> Result<Vec<u8>> {
        let mut mechanism: CK_MECHANISM = m.into();
        let mut digest_len = 0;

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_DigestInit)(
                self.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
            ))
            .into_result(Function::DigestInit)?;
        }

        // Get the output buffer length
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_Digest)(
                self.handle(),
                data.as_ptr() as *mut u8,
                data.len().try_into()?,
                std::ptr::null_mut(),
                &mut digest_len,
            ))
            .into_result(Function::Digest)?;
        }

        let mut digest = vec![0; digest_len.try_into()?];

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_Digest)(
                self.handle(),
                data.as_ptr() as *mut u8,
                data.len().try_into()?,
                digest.as_mut_ptr(),
                &mut digest_len,
            ))
            .into_result(Function::Digest)?;
        }

        digest.resize(digest_len.try_into()?, 0);

        Ok(digest)
    }
}
