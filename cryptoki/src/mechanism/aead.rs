// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! AEAD block cipher mechanism types

use crate::types::Ulong;
use cryptoki_sys::*;
use std::convert::TryInto;
use std::marker::PhantomData;
use std::slice;

/// Parameters for AES-GCM.
#[derive(Debug)]
#[repr(transparent)]
pub struct GcmParams<'a> {
    inner: CK_GCM_PARAMS,
    _marker: PhantomData<&'a mut [u8]>,
}

impl<'a> GcmParams<'a> {
    /// Construct GCM parameters.
    ///
    /// # Arguments
    ///
    /// `iv` - The initialization vector.  This must be non-empty.  In PKCS#11
    /// 2.40, the maximum length of the IV is 256 bytes.  A 12-byte IV may be
    /// processed more efficiently than other lengths.
    ///
    /// `aad` - The additional authenticated data.  This data is authenticated
    /// but not encrypted.  This may be between 0 and 2^32-1 bytes.
    ///
    /// `tag_bits` - The length, in **bits**, of the authentication tag.  Must
    /// be between 0 and 128.  The tag is appended to the end of the
    /// ciphertext.
    ///
    /// # Panics
    ///
    /// This function panics if the length of `iv` or `aad` does not
    /// fit into an [Ulong].
    pub fn new(iv: &'a mut [u8], aad: &'a [u8], tag_bits: Ulong) -> Self {
        // The ulIvBits parameter seems to be missing from the 2.40 spec,
        // although it is included in the header file.  In [1], OASIS clarified
        // that the header file is normative.  In 3.0, they added the parameter
        // to the spec, but it seems to be unused:
        //
        // > Do not use ulIvBits to specify the length of the initialization
        // > vector, but ulIvLen instead.
        //
        // Further, in v3.0, the IV is permitted to be up to 2^32-1 bytes,
        // which would cause ulIvBits to overflow on platforms where
        // sizeof(CK_ULONG) = 4.
        //
        // In light of all this, we include ulIvBits in the struct, but always
        // set it to zero.
        //
        // [1]: https://www.oasis-open.org/committees/document.php?document_id=58032&wg_abbrev=pkcs11
        GcmParams {
            inner: CK_GCM_PARAMS {
                pIv: iv.as_mut_ptr(),
                ulIvLen: iv
                    .len()
                    .try_into()
                    .expect("iv length does not fit in CK_ULONG"),
                ulIvBits: 0,
                pAAD: aad.as_ptr() as *mut _,
                ulAADLen: aad
                    .len()
                    .try_into()
                    .expect("aad length does not fit in CK_ULONG"),
                ulTagBits: tag_bits.into(),
            },
            _marker: PhantomData,
        }
    }

    /// The initialization vector.
    pub fn iv(&mut self) -> &mut [u8] {
        // SAFETY: In the constructor, the IV always comes from a &'a mut [u8]
        unsafe { slice::from_raw_parts_mut(self.inner.pIv, self.inner.ulIvLen as _) }
    }

    /// The additional authenticated data.
    pub fn aad(&self) -> &'a [u8] {
        // SAEFTY: In the constructor, the AAD always comes from a &'a [u8]
        unsafe { slice::from_raw_parts(self.inner.pAAD, self.inner.ulAADLen as _) }
    }

    /// The length, in bits, of the authentication tag.
    pub fn tag_bits(&self) -> Ulong {
        self.inner.ulTagBits.into()
    }
}
