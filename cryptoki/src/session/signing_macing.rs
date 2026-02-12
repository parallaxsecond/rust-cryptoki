// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Signing and authentication functions

use crate::context::Function;
use crate::error::{Result, Rv};
use crate::mechanism::Mechanism;
use crate::object::ObjectHandle;
use crate::session::Session;
use cryptoki_sys::*;
use std::convert::TryInto;

impl Session {
    /// Sign data in single-part
    pub fn sign(&self, mechanism: &Mechanism, key: ObjectHandle, data: &[u8]) -> Result<Vec<u8>> {
        self.sign_init(mechanism, key)?;
        self.sign_single(data)
    }

    /// Sign data in single-part.
    ///
    /// This function can be used instead of the single shot related sign
    /// function when the user needs to perform something like
    /// context-specific user authentication after [`Session::sign_init`]
    /// is called.
    pub fn sign_single(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut signature_len = 0;

        // Get the output buffer length
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_Sign)(
                self.handle(),
                data.as_ptr() as *mut u8,
                data.len().try_into()?,
                std::ptr::null_mut(),
                &mut signature_len,
            ))
            .into_result(Function::Sign)?;
        }

        let mut signature = vec![0; signature_len.try_into()?];

        //TODO: we should add a new error instead of those unwrap!
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_Sign)(
                self.handle(),
                data.as_ptr() as *mut u8,
                data.len().try_into()?,
                signature.as_mut_ptr(),
                &mut signature_len,
            ))
            .into_result(Function::Sign)?;
        }

        signature.truncate(signature_len.try_into()?);

        Ok(signature)
    }

    /// Starts new single-part or multi-part signing operation
    pub fn sign_init(&self, mechanism: &Mechanism, key: ObjectHandle) -> Result<()> {
        let mut mechanism: CK_MECHANISM = mechanism.into();

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_SignInit)(
                self.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                key.handle(),
            ))
            .into_result(Function::SignInit)?;
        }

        Ok(())
    }

    /// Continues an ongoing multi-part signing operation,
    /// taking in the next part of the data to sign
    pub fn sign_update(&self, data: &[u8]) -> Result<()> {
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_SignUpdate)(
                self.handle(),
                data.as_ptr() as *mut u8,
                data.len().try_into()?,
            ))
            .into_result(Function::SignUpdate)?;
        }

        Ok(())
    }

    /// Finalizes ongoing multi-part signing operation,
    /// returning the signature
    pub fn sign_final(&self) -> Result<Vec<u8>> {
        let mut signature_len = 0;

        // Get the output buffer length
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_SignFinal)(
                self.handle(),
                std::ptr::null_mut(),
                &mut signature_len,
            ))
            .into_result(Function::SignFinal)?;
        }

        let mut signature = vec![0; signature_len.try_into()?];

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_SignFinal)(
                self.handle(),
                signature.as_mut_ptr(),
                &mut signature_len,
            ))
            .into_result(Function::SignFinal)?;
        }

        signature.truncate(signature_len.try_into()?);

        Ok(signature)
    }

    /// Verify data in single-part
    pub fn verify(
        &self,
        mechanism: &Mechanism,
        key: ObjectHandle,
        data: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        self.verify_init(mechanism, key)?;
        self.verify_single(data, signature)
    }

    /// Verify data in single-part.
    ///
    /// This function can be used instead of the single shot related verify
    /// function when the user needs to perform something like
    /// context-specific user authentication after [`Session::verify_init`]
    /// is called.
    pub fn verify_single(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_Verify)(
                self.handle(),
                data.as_ptr() as *mut u8,
                data.len().try_into()?,
                signature.as_ptr() as *mut u8,
                signature.len().try_into()?,
            ))
            .into_result(Function::Verify)
        }
    }

    /// Starts new single-part or multi-part verifying operation
    pub fn verify_init(&self, mechanism: &Mechanism, key: ObjectHandle) -> Result<()> {
        let mut mechanism: CK_MECHANISM = mechanism.into();

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_VerifyInit)(
                self.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                key.handle(),
            ))
            .into_result(Function::VerifyInit)?;
        }

        Ok(())
    }

    /// Continues an ongoing multi-part verifying operation,
    /// taking in the next part of the data to verify
    pub fn verify_update(&self, data: &[u8]) -> Result<()> {
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_VerifyUpdate)(
                self.handle(),
                data.as_ptr() as *mut u8,
                data.len().try_into()?,
            ))
            .into_result(Function::VerifyUpdate)?;
        }

        Ok(())
    }

    /// Finalizes ongoing multi-part verifying operation,
    /// returning Ok only if the signature verifies
    pub fn verify_final(&self, signature: &[u8]) -> Result<()> {
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_VerifyFinal)(
                self.handle(),
                signature.as_ptr() as *mut u8,
                signature.len().try_into()?,
            ))
            .into_result(Function::VerifyFinal)?;
        }

        Ok(())
    }

    /// Initialize Signature verification operation, by including the signature at initialization
    pub fn verify_signature_init(
        &self,
        mechanism: &Mechanism,
        key: ObjectHandle,
        signature: &[u8],
    ) -> Result<()> {
        let mut mechanism: CK_MECHANISM = mechanism.into();

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_VerifySignatureInit)(
                self.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                key.handle(),
                signature.as_ptr() as *mut u8,
                signature.len().try_into()?,
            ))
            .into_result(Function::VerifySignatureInit)?;
        }

        Ok(())
    }

    /// Verify Signature in single-part operation
    pub fn verify_signature(&self, data: &[u8]) -> Result<()> {
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_VerifySignature)(
                self.handle(),
                data.as_ptr() as *mut u8,
                data.len().try_into()?,
            ))
            .into_result(Function::VerifySignature)?;
        }

        Ok(())
    }

    /// continue multi-part Verify Signature operation
    pub fn verify_signature_update(&self, data: &[u8]) -> Result<()> {
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_VerifySignatureUpdate)(
                self.handle(),
                data.as_ptr() as *mut u8,
                data.len().try_into()?,
            ))
            .into_result(Function::VerifySignatureUpdate)?;
        }

        Ok(())
    }

    /// finalize multi-part Verify Signature operation
    pub fn verify_signature_final(&self) -> Result<()> {
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_VerifySignatureFinal)(
                self.handle(),
            ))
            .into_result(Function::VerifySignatureFinal)?;
        }

        Ok(())
    }
}
