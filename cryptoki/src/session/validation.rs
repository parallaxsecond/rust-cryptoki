// Copyright 2025 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Session Validation

use crate::context::Function;
use crate::error::{Result, Rv};
use crate::session::Session;
use cryptoki_sys::*;
use std::fmt::{Debug, Formatter};

/// The type of validation flag to query
#[derive(Copy, Clone, Debug)]
pub struct ValidationFlagsType {
    val: CK_SESSION_VALIDATION_FLAGS_TYPE,
}

impl ValidationFlagsType {
    /// Check the last operation met all requirements of a validated mechanism.
    pub const VALIDATION_OK: ValidationFlagsType = ValidationFlagsType {
        val: CKS_LAST_VALIDATION_OK,
    };
}

impl std::fmt::Display for ValidationFlagsType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self.val {
                CKS_LAST_VALIDATION_OK => stringify!(CKS_LAST_VALIDATION_OK),
                flags => return write!(f, "unknown ({flags:08x})"),
            }
        )
    }
}

impl AsRef<CK_SESSION_VALIDATION_FLAGS_TYPE> for ValidationFlagsType {
    fn as_ref(&self) -> &CK_SESSION_VALIDATION_FLAGS_TYPE {
        &self.val
    }
}

impl From<ValidationFlagsType> for CK_SESSION_VALIDATION_FLAGS_TYPE {
    fn from(val: ValidationFlagsType) -> Self {
        *val.as_ref()
    }
}

impl Session<'_> {
    /// Get requested validation flags from the session
    ///
    /// The only supported flag as for PKCS#11 3.2 is `ValidationFlagsType::VALIDATION_OK`
    pub fn get_validation_flags(&self, flags_type: ValidationFlagsType) -> Result<CK_FLAGS> {
        let mut flags: CK_FLAGS = 0;
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_GetSessionValidationFlags)(
                self.handle(),
                flags_type.into(),
                &mut flags,
            ))
            .into_result(Function::GetSessionValidationFlags)?;
        }
        Ok(flags)
    }
}
