// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! AES mechanism types

use cryptoki_sys::CK_AES_CBC_ENCRYPT_DATA_PARAMS;
use std::convert::TryInto;
use std::marker::PhantomData;

/// AES CBC derivation parameters.
/// This structure wraps a CK_AES_CBC_ENCRYPT_DATA_PARAMS structure.
#[derive(Copy, Debug, Clone)]
#[repr(transparent)]
pub struct AesCBCEncryptDataParams<'a> {
    inner: CK_AES_CBC_ENCRYPT_DATA_PARAMS,
    _marker: PhantomData<&'a [u8]>,
}
impl<'a> AesCBCEncryptDataParams<'a> {
    /// Construct AES CBC ENCRYPT DATA parameters.
    ///
    /// # Arguments
    ///
    /// `iv` - The initialization vector.  This must be non-empty.
    /// `data` - The data to cipher.
    ///
    /// # Panics
    ///
    /// This function panics if the lenght of `data` does not
    /// fit into an [Ulong].
    pub fn new(iv: [u8; 16], data: &'a [u8]) -> Self {
        Self {
            inner: CK_AES_CBC_ENCRYPT_DATA_PARAMS {
                iv,
                pData: data.as_ptr() as *mut _,
                length: data
                    .len()
                    .try_into()
                    .expect("data length does not fit in CK_ULONG"),
            },
            _marker: PhantomData,
        }
    }
    /// The initialization vector.
    pub fn iv(&self) -> &[u8] {
        self.inner.iv.as_slice()
    }

    /// The data
    pub fn data(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.inner.pData, self.inner.length as _) }
    }
}