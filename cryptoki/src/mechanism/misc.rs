// Copyright 2025 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Miscellaneous mechanisms:
//! - Simple key derivation mechanisms
//! See: <https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203697>

use std::marker::PhantomData;

use cryptoki_sys::*;

/// A parameter used as input for one of the simple key derivation mechanisms
/// that takes a bytestring as input (CKM_CONCATENATE_BASE_AND_DATA,
/// CKM_CONCATENATE_DATA_AND_BASE, CKM_XOR_BASE_AND_DATA).
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct KeyDerivationStringData<'a> {
    inner: CK_KEY_DERIVATION_STRING_DATA,
    /// Marker type to ensure we don't outlive the data
    _marker: PhantomData<&'a [u8]>,
}

impl<'a> KeyDerivationStringData<'a> {
    /// Construct parameter for simple key derivation mechanisms that take a
    /// bytestring as one of their inputs.
    ///
    /// # Arguments
    ///
    /// * `data` - The bytestring to use as input to the key derivation method.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            inner: CK_KEY_DERIVATION_STRING_DATA {
                pData: data.as_ptr() as *mut _,
                ulLen: data
                    .len()
                    .try_into()
                    .expect("length of data does not fit in CK_ULONG"),
            },
            _marker: PhantomData,
        }
    }
}

/// A parameter indicating the index of the base key from which to extract the
/// derived key.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct ExtractParams(CK_EXTRACT_PARAMS);

impl ExtractParams {
    /// Construct parameter from index to extract the derived key from the base
    /// key.
    ///
    /// # Arguments
    ///
    /// * `index` - The index from which to extract the derived key from the base key.
    pub fn new(index: usize) -> Self {
        Self(
            index
                .try_into()
                .expect("given usize value does not fit into CK_ULONG"),
        )
    }
}
