// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Signing and authentication functions

use crate::error::{Result, Rv};
use crate::mechanism::Mechanism;
use crate::object::ObjectHandle;
use crate::session::Session;
use cryptoki_sys::*;
use std::convert::TryInto;

#[cfg(feature = "signature-traits")]
use signature::Signer;

impl Session {
    #[cfg(feature = "signature-traits")]
    /// Prepare a signature request which implements the signature::Signer trait.
    pub fn prepare_signature<'a>(&'a self, mechanism: &'a Mechanism<'a>, key: ObjectHandle) -> SignatureRequest {
        SignatureRequest::new(mechanism, key, self)
    }

    /// Sign data in single-part
    pub fn sign(&self, mechanism: &Mechanism, key: ObjectHandle, data: &[u8]) -> Result<Vec<u8>> {
        let mut mechanism: CK_MECHANISM = mechanism.into();
        let mut signature_len = 0;

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_SignInit)(
                self.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                key.handle(),
            ))
            .into_result()?;
        }

        // Get the output buffer length
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_Sign)(
                self.handle(),
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
            Rv::from(get_pkcs11!(self.client(), C_Sign)(
                self.handle(),
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

    /// Verify data in single-part
    pub fn verify(
        &self,
        mechanism: &Mechanism,
        key: ObjectHandle,
        data: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let mut mechanism: CK_MECHANISM = mechanism.into();

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_VerifyInit)(
                self.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                key.handle(),
            ))
            .into_result()?;
        }

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_Verify)(
                self.handle(),
                data.as_ptr() as *mut u8,
                data.len().try_into()?,
                signature.as_ptr() as *mut u8,
                signature.len().try_into()?,
            ))
            .into_result()
        }
    }
}

#[cfg(feature = "signature-traits")]
#[derive(Debug)]
pub struct SignatureRequest<'sess: 'a, 'a, 'b> {
    mechanism: &'a Mechanism<'b>,
    key: ObjectHandle,
    session: &'sess Session
}

#[cfg(feature = "signature-traits")]
impl<'sess, 'a, 'b> SignatureRequest<'sess, 'a, 'b> {
    pub fn new(mechanism: &'a Mechanism<'b>, key: ObjectHandle, session: &'sess Session) -> Self {
        SignatureRequest {
            mechanism,
            key,
            session
        }
    }
}


#[cfg(feature = "signature-traits")]
impl<'sess, 'a, 'b> Signer<Vec<u8>> for SignatureRequest<'sess, 'a, 'b> {
    fn try_sign(&self, msg: &[u8]) -> core::result::Result<Vec<u8>, signature::Error> {
        self.session.sign(self.mechanism, self.key, msg).map_err(signature::Error::from_source)
    }
}
