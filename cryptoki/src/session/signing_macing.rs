// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Signing and authentication functions

use crate::context::Function;
#[cfg(doc)]
use crate::error::RvError;
use crate::error::{Result, Rv};
use crate::mechanism::Mechanism;
use crate::object::ObjectHandle;
use crate::session::Session;
use cryptoki_sys::*;
use std::convert::TryInto;

/// # Generating and Verifying Signatures
///
/// Several functions are provided for signing data and verifying signatures.
/// This includes message authentication codes (MACs). The signed data can be
/// provided in one-shot and streaming modes.
impl Session {
    /// Sign data in one-shot mode.
    ///
    /// `data` should be a byte sequence representing the input message. It will
    /// be signed using the specified key, and the resulting signature will be
    /// returned in a `Vec`.
    ///
    /// Use [`Self::sign_into()`] if (an upper bound for) the size of the
    /// signature is known, to avoid the heap allocation of `Vec`. Use
    /// [`Self::sign_init()`] etc. if the input data is being streamed (i.e. it
    /// is not all immediately available).
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

        // Get the output buffer length.
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

        // Allocate the output buffer.
        let mut signature = vec![0; signature_len.try_into()?];

        // Perform the actual signing.
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

        // Limit the output buffer to the size of the generated signature.
        signature.truncate(signature_len.try_into()?);

        Ok(signature)
    }

    /// Sign data into the given buffer.
    ///
    /// `data` should be a byte sequence representing the input message. It will
    /// be signed using the specified key, and the resulting signature will be
    /// written to the buffer `sig`.
    ///
    /// `sig` should be large enough to store the signature. The number of
    /// filled bytes will be returned, such that `sig[0..size]` contains the
    /// prepared signature. `sig[size..]` might be modified.
    ///
    /// Use [`Self::sign()`] if (an upper bound for) the size of the signature
    /// is not known. Use [`Self::sign_init()`] etc. if the input data is being
    /// streamed (i.e. it is not all immediately available).
    ///
    /// ## Errors
    ///
    /// Returns [`RvError::BufferTooSmall`] if the generated signature does not
    /// fit in `sig`. `sig` might be modified. The size of the actual signature
    /// is **not** returned. This method should only be used if the caller knows
    /// an upper bound for the signature size.
    pub fn sign_into(
        &self,
        mechanism: &Mechanism,
        key: ObjectHandle,
        data: &[u8],
        sig: &mut [u8],
    ) -> Result<usize> {
        // The size of the signature buffer, into which 'C_Sign' will write the
        // size of the generated signature.
        let sig_buf_len = sig.len().try_into()?;
        let mut sig_len = sig_buf_len;

        // Initialize the signing operation.
        self.sign_init(mechanism, key)?;

        // Perform the actual signing.
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_Sign)(
                self.handle(),
                data.as_ptr() as *mut u8,
                data.len().try_into()?,
                sig.as_mut_ptr(),
                &mut sig_len,
            ))
            .into_result(Function::Sign)?;
        }

        assert!(
            sig_len <= sig_buf_len,
            "'C_Sign' succeeded but increased 'sig_len', possibly indicating out-of-bounds accesses"
        );

        // NOTE: As checked above, 'sig_len <= sig_buf_len <= usize::MAX'.
        Ok(sig_len as usize)
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

    /// Complete an ongoing streaming signing operation.
    ///
    /// This must be preceded by [`Self::sign_init()`] and zero or more calls
    /// to [`Self::sign_update()`]. This method will terminate the multi-part
    /// signing operation. The resulting signature will be returned in a `Vec`.
    ///
    /// Use [`Self::sign_final_into()`] if (an upper bound for) the size of
    /// the signature is known, to avoid the heap allocation of `Vec`. Use
    /// [`Self::sign()`] if the input data is entirely available in a single
    /// buffer (i.e. does not have to be streamed).
    pub fn sign_final(&self) -> Result<Vec<u8>> {
        let mut signature_len = 0;

        // Get the output buffer length.
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_SignFinal)(
                self.handle(),
                std::ptr::null_mut(),
                &mut signature_len,
            ))
            .into_result(Function::SignFinal)?;
        }

        // Allocate the output buffer.
        let mut signature = vec![0; signature_len.try_into()?];

        // Perform the actual signing.
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_SignFinal)(
                self.handle(),
                signature.as_mut_ptr(),
                &mut signature_len,
            ))
            .into_result(Function::SignFinal)?;
        }

        // Limit the output buffer to the size of the generated signature.
        signature.truncate(signature_len.try_into()?);

        Ok(signature)
    }

    /// Complete an ongoing multi-part signing operation, writing the signature
    /// into the given buffer.
    ///
    /// This must be preceded by [`Self::sign_init()`] and zero or more calls
    /// to [`Self::sign_update()`]. This method will terminate the multi-part
    /// signing operation, and write the signature to the buffer `sig`.
    ///
    /// `sig` should be large enough to store the signature. The number of
    /// filled bytes will be returned, such that `sig[0..size]` contains the
    /// prepared signature. `sig[size..]` might be modified.
    ///
    /// Use [`Self::sign_final()`] if (an upper bound for) the size of the
    /// signature is not known. Use [`Self::sign_into()`] if the input data
    /// is entirely available in a single buffer (i.e. does not have to be
    /// streamed).
    ///
    /// ## Errors
    ///
    /// Returns [`RvError::BufferTooSmall`] if the generated signature does not
    /// fit in `sig`. `sig` might be modified. The size of the actual signature
    /// is **not** returned. This method should only be used if the caller knows
    /// an upper bound for the signature size.
    pub fn sign_final_into(&self, sig: &mut [u8]) -> Result<usize> {
        // The size of the signature buffer, into which 'C_SignFinal' will write
        // the size of the generated signature.
        let sig_buf_len = sig.len().try_into()?;
        let mut sig_len = sig_buf_len;

        // Perform the underlying finalization.
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_SignFinal)(
                self.handle(),
                sig.as_mut_ptr(),
                &mut sig_len,
            ))
            .into_result(Function::SignFinal)?;
        }

        assert!(
            sig_len <= sig_buf_len,
            "'C_SignFinal' succeeded but increased 'sig_len', possibly indicating out-of-bounds accesses"
        );

        // NOTE: As checked above, 'sig_len <= sig_buf_len <= usize::MAX'.
        Ok(sig_len as usize)
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
