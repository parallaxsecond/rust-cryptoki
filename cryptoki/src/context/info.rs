// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! PKCS11 library information

use crate::string_from_blank_padded;
use crate::types::Version;
use cryptoki_sys::*;
use std::ops::Deref;

#[derive(Debug, Clone, Copy)]
/// Type identifying the PKCS#11 library information
pub struct Info {
    val: CK_INFO,
}

impl Info {
    pub(crate) fn new(val: CK_INFO) -> Self {
        Self { val }
    }

    /// Returns the version of Cryptoki that the library is compatible with
    pub fn cryptoki_version(&self) -> Version {
        self.val.cryptokiVersion.into()
    }

    /// Returns the flags of the library (should be zero!)
    pub fn flags(&self) -> CK_FLAGS {
        self.val.flags
    }

    /// Returns the description of the library
    pub fn library_description(&self) -> String {
        string_from_blank_padded(&self.val.libraryDescription)
    }

    /// Returns the version of the library
    pub fn library_version(&self) -> Version {
        self.val.libraryVersion.into()
    }

    /// Returns the manufacturer of the library
    pub fn manufacturer_id(&self) -> String {
        string_from_blank_padded(&self.val.manufacturerID)
    }
}

impl Deref for Info {
    type Target = CK_INFO;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

impl From<Info> for CK_INFO {
    fn from(info: Info) -> Self {
        *info
    }
}
