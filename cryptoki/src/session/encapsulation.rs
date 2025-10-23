// Copyright 2025 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Encapsulating/decapsulating data

use crate::context::Function;
use crate::error::{Result, Rv};
use crate::mechanism::Mechanism;
use crate::object::{Attribute, ObjectHandle};
use crate::session::Session;
use cryptoki_sys::*;
use std::convert::TryInto;

impl Session<'_> {
    /// Encapsulate key
    pub fn encapsulate_key(
        &self,
        mechanism: &Mechanism,
        publickey: ObjectHandle,
        template: &[Attribute],
    ) -> Result<(Vec<u8>, ObjectHandle)> {
        let mut mechanism: CK_MECHANISM = mechanism.into();
        let mut template: Vec<CK_ATTRIBUTE> = template.iter().map(|attr| attr.into()).collect();
        let mut encapsulated_len = 0;
        let mut handle = 0;

        // Get the output buffer length
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_EncapsulateKey)(
                self.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                publickey.handle(),
                template.as_mut_ptr(),
                template.len().try_into()?,
                std::ptr::null_mut(),
                &mut encapsulated_len,
                &mut handle,
            ))
            .into_result(Function::EncapsulateKey)?;
        }

        let mut encapsulated = vec![0; encapsulated_len.try_into()?];

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_EncapsulateKey)(
                self.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                publickey.handle(),
                template.as_mut_ptr(),
                template.len().try_into()?,
                encapsulated.as_mut_ptr(),
                &mut encapsulated_len,
                &mut handle,
            ))
            .into_result(Function::EncapsulateKey)?;
        }

        encapsulated.truncate(encapsulated_len.try_into()?);

        Ok((encapsulated, ObjectHandle::new(handle)))
    }

    /// Decapsulate key
    pub fn decapsulate_key(
        &self,
        mechanism: &Mechanism,
        privatekey: ObjectHandle,
        template: &[Attribute],
        ciphertext: &[u8],
    ) -> Result<ObjectHandle> {
        let mut mechanism: CK_MECHANISM = mechanism.into();
        let mut template: Vec<CK_ATTRIBUTE> = template.iter().map(|attr| attr.into()).collect();
        let mut handle = 0;

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_DecapsulateKey)(
                self.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                privatekey.handle(),
                template.as_mut_ptr(),
                template.len().try_into()?,
                ciphertext.as_ptr() as *mut u8,
                ciphertext.len().try_into()?,
                &mut handle,
            ))
            .into_result(Function::DecapsulateKey)?;
        }

        Ok(ObjectHandle::new(handle))
    }
}
