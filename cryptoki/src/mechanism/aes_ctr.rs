// Copyright 2026 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! AES-CTR mechanism types

use crate::error::Error;
use cryptoki_sys::*;

/// Parameters for AES-CTR.
///
/// This structure wraps a `CK_AES_CTR_PARAMS` structure.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct AesCtrParams {
    inner: CK_AES_CTR_PARAMS,
}

impl AesCtrParams {
    /// Construct AES-CTR parameters.
    ///
    /// # Arguments
    ///
    /// `counter_bits` - The number of least significant bits of `block` that
    /// make up the counter, i.e. that are incremented for every block that is
    /// processed. Must be between 1 and 128.
    ///
    /// `block` - The initial value of the counter block: the nonce, followed by
    /// the initial value of the counter in the `counter_bits` least significant
    /// bits.
    ///
    /// # Errors
    /// This function returns [`Error::InvalidValue`] if `counter_bits` is zero
    /// or larger than the AES block size of 128 bits.
    pub fn new(counter_bits: u8, block: [u8; 16]) -> Result<Self, Error> {
        if counter_bits == 0 || counter_bits > 128 {
            return Err(Error::InvalidValue);
        }

        Ok(AesCtrParams {
            inner: CK_AES_CTR_PARAMS {
                ulCounterBits: counter_bits.into(),
                cb: block,
            },
        })
    }
}
