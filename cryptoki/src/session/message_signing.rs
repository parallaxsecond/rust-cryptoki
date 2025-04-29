// Copyright 2025 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Message Signing/Verification and authentication functions

use crate::context::Function;
use crate::error::{Result, Rv};
use crate::mechanism::{Mechanism, MessageParam};
use crate::object::ObjectHandle;
use crate::session::Session;
use cryptoki_sys::*;
use std::convert::TryInto;

impl Session {
    /// Prepare a session for one or more Message-based signature using the same mechanism and key
    pub fn message_sign_init(&self, mechanism: &Mechanism, key: ObjectHandle) -> Result<()> {
        let mut mechanism: CK_MECHANISM = mechanism.into();

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_MessageSignInit)(
                self.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                key.handle(),
            ))
            .into_result(Function::MessageSignInit)?;
        }

        Ok(())
    }

    /// Sign a message in single part
    pub fn sign_message(&self, param: &MessageParam, data: &[u8]) -> Result<Vec<u8>> {
        let mut signature_len = 0;

        // Get the output buffer length
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_SignMessage)(
                self.handle(),
                param.as_ptr(),
                param.len(),
                data.as_ptr() as *mut u8,
                data.len().try_into()?,
                std::ptr::null_mut(),
                &mut signature_len,
            ))
            .into_result(Function::SignMessage)?;
        }

        let mut signature = vec![0; signature_len.try_into()?];

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_SignMessage)(
                self.handle(),
                param.as_ptr(),
                param.len(),
                data.as_ptr() as *mut u8,
                data.len().try_into()?,
                signature.as_mut_ptr(),
                &mut signature_len,
            ))
            .into_result(Function::SignMessage)?;
        }

        signature.resize(signature_len.try_into()?, 0);

        Ok(signature)
    }

    /// Begin multi-part message signature operation
    pub fn sign_message_begin(&self, param: MessageParam) -> Result<()> {
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_SignMessageBegin)(
                self.handle(),
                param.as_ptr(),
                param.len(),
            ))
            .into_result(Function::SignMessageBegin)
        }
    }

    /// Continue mutli-part message signature operation
    pub fn sign_message_next(
        &self,
        param: MessageParam,
        data: &[u8],
        end: bool,
    ) -> Result<Option<Vec<u8>>> {
        if !end {
            // Just pass in the data
            unsafe {
                Rv::from(get_pkcs11!(self.client(), C_SignMessageNext)(
                    self.handle(),
                    param.as_ptr(),
                    param.len(),
                    data.as_ptr() as *mut u8,
                    data.len().try_into()?,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                ))
                .into_result(Function::SignMessageNext)?;
            }
            return Ok(None);
        }
        let mut signature_len = 0;
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_SignMessageNext)(
                self.handle(),
                param.as_ptr(),
                param.len(),
                data.as_ptr() as *mut u8,
                data.len().try_into()?,
                std::ptr::null_mut(),
                &mut signature_len,
            ))
            .into_result(Function::SignMessageNext)?;
        }

        let mut signature = vec![0; signature_len.try_into()?];

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_SignMessageNext)(
                self.handle(),
                param.as_ptr(),
                param.len(),
                data.as_ptr() as *mut u8,
                data.len().try_into()?,
                signature.as_mut_ptr(),
                &mut signature_len,
            ))
            .into_result(Function::SignMessageNext)?;
        }

        signature.resize(signature_len.try_into()?, 0);

        Ok(Some(signature))
    }

    /// Finalize mutli-part message signature process
    pub fn message_sign_final(&self) -> Result<()> {
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_MessageSignFinal)(
                self.handle(),
            ))
            .into_result(Function::MessageSignFinal)
        }
    }

    /// Prepare a session for one or more Message-based verifications using the same mechanism and key
    pub fn message_verify_init(&self, mechanism: &Mechanism, key: ObjectHandle) -> Result<()> {
        let mut mechanism: CK_MECHANISM = mechanism.into();

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_MessageVerifyInit)(
                self.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                key.handle(),
            ))
            .into_result(Function::MessageVerifyInit)?;
        }

        Ok(())
    }

    /// Verify message in single-part
    pub fn verify_message(
        &self,
        param: &MessageParam,
        data: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_VerifyMessage)(
                self.handle(),
                param.as_ptr(),
                param.len(),
                data.as_ptr() as *mut u8,
                data.len().try_into()?,
                signature.as_ptr() as *mut u8,
                signature.len().try_into()?,
            ))
            .into_result(Function::VerifyMessage)?;
        }
        Ok(())
    }

    /// Begin multi-part message signature verification operation
    pub fn verify_message_begin(&self, param: MessageParam) -> Result<()> {
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_VerifyMessageBegin)(
                self.handle(),
                param.as_ptr(),
                param.len(),
            ))
            .into_result(Function::VerifyMessageBegin)
        }
    }

    /// Continue mutli-part message signature verification operation
    pub fn verify_message_next(
        &self,
        param: MessageParam,
        data: &[u8],
        signature: Option<&[u8]>,
    ) -> Result<()> {
        match signature {
            None => {
                // Just pass in the data
                unsafe {
                    Rv::from(get_pkcs11!(self.client(), C_VerifyMessageNext)(
                        self.handle(),
                        param.as_ptr(),
                        param.len(),
                        data.as_ptr() as *mut u8,
                        data.len().try_into()?,
                        std::ptr::null_mut(),
                        0,
                    ))
                    .into_result(Function::VerifyMessageNext)?;
                }
                return Ok(());
            }
            Some(s) => unsafe {
                Rv::from(get_pkcs11!(self.client(), C_VerifyMessageNext)(
                    self.handle(),
                    param.as_ptr(),
                    param.len(),
                    data.as_ptr() as *mut u8,
                    data.len().try_into()?,
                    s.as_ptr() as *mut u8,
                    s.len().try_into()?,
                ))
                .into_result(Function::VerifyMessageNext)?;
            },
        }
        Ok(())
    }

    /// Finalize mutli-part message signature verification process
    pub fn message_verify_final(&self) -> Result<()> {
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_MessageVerifyFinal)(
                self.handle(),
            ))
            .into_result(Function::MessageVerifyFinal)
        }
    }
}
