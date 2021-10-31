// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! PKCS11 General Data Types

use crate::types::Flags;
use cryptoki_sys::*;
use std::fmt::Formatter;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
/// Collection of flags defined for [`CK_SESSION_INFO`]
pub struct SessionFlags {
    flags: CK_FLAGS,
}

impl Flags for SessionFlags {
    type FlagType = CK_FLAGS;

    fn flag_value(&self) -> Self::FlagType {
        self.flags
    }

    fn flag(&self, flag: Self::FlagType) -> bool {
        self.flag_value() & flag == flag
    }

    fn set_flag(&mut self, flag: Self::FlagType, b: bool) {
        if b {
            self.flags |= flag;
        } else {
            self.flags &= !flag;
        }
    }

    fn stringify_flag(flag: Self::FlagType) -> &'static str {
        match flag {
            CKF_RW_SESSION => std::stringify!(CKF_RW_SESSION),
            CKF_SERIAL_SESSION => std::stringify!(CKF_SERIAL_SESSION),
            _ => "Unknown session flag",
        }
    }
}

impl SessionFlags {
    /// Creates a new instance of `SessionFlags` with no flags set
    pub fn new() -> Self {
        SessionFlags::default()
    }

    /// Gets value of [`CKF_RW_SESSION`]
    pub fn rw_session(&self) -> bool {
        self.flag(CKF_RW_SESSION)
    }

    /// Sets value of [`CKF_RW_SESSION`]
    pub fn set_rw_session(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_RW_SESSION, b);
        self
    }

    /// Gets value of [`CKF_SERIAL_SESSION`]
    pub fn serial_session(&self) -> bool {
        self.flag(CKF_SERIAL_SESSION)
    }

    /// Sets value of [`CKF_SERIAL_SESSION`]
    pub fn set_serial_session(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SERIAL_SESSION, b);
        self
    }
}

impl std::fmt::Display for SessionFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let flags = vec![CKF_RW_SESSION, CKF_SERIAL_SESSION];
        self.stringify_fmt(f, flags)
    }
}

impl From<SessionFlags> for CK_FLAGS {
    fn from(flags: SessionFlags) -> Self {
        flags.flags
    }
}

impl From<CK_FLAGS> for SessionFlags {
    fn from(flags: CK_FLAGS) -> Self {
        Self { flags }
    }
}
