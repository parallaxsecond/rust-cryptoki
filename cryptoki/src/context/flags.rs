// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! PKCS11 flags for use with CInitializeArgs

use crate::error::{Error, Result};
use cryptoki_sys::*;
use std::convert::TryFrom;
use std::fmt::Formatter;
use crate::types::Flags;

#[derive(Debug, Default, Clone, Copy)]
/// Collection of flags defined for [`CK_C_INITIALIZE_ARGS`]
pub struct InitializeFlags {
    flags: CK_FLAGS,
}

impl Flags for InitializeFlags {
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

    fn stringify_flag(flag: CK_FLAGS) -> &'static str {
        match flag {
            CKF_LIBRARY_CANT_CREATE_OS_THREADS => {
                std::stringify!(CKF_LIBRARY_CANT_CREATE_OS_THREADS)
            }
            CKF_OS_LOCKING_OK => std::stringify!(CKF_OS_LOCKING_OK),
            _ => "Unknown CK_C_INITIALIZE_ARGS flag",
        }
    }
}

impl InitializeFlags {
    /// Creates a new instance of `InitializeFlags` with no flags set
    pub fn new() -> Self {
        InitializeFlags::default()
    }

    /// Gets value of [`CKF_LIBRARY_CANT_CREATE_OS_THREADS`]
    pub fn library_cant_create_os_threads(&self) -> bool {
        self.flag(CKF_LIBRARY_CANT_CREATE_OS_THREADS)
    }

    /// Sets value of [`CKF_LIBRARY_CANT_CREATE_OS_THREADS`]
    pub fn set_library_cant_create_os_threads(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_LIBRARY_CANT_CREATE_OS_THREADS, b);
        self
    }

    /// Gets value of [`CKF_OS_LOCKING_OK`]
    pub fn os_locking_ok(&self) -> bool {
        self.flag(CKF_OS_LOCKING_OK)
    }

    /// Sets value of [`CKF_OS_LOCKING_OK`]
    pub fn set_os_locking_ok(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_OS_LOCKING_OK, b);
        self
    }
}

impl std::fmt::Display for InitializeFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let flags = vec![CKF_LIBRARY_CANT_CREATE_OS_THREADS, CKF_OS_LOCKING_OK];
        self.stringify_fmt(f, flags)
    }
}

impl From<InitializeFlags> for CK_FLAGS {
    fn from(flags: InitializeFlags) -> Self {
        flags.flags
    }
}

impl TryFrom<CK_FLAGS> for InitializeFlags {
    type Error = Error;

    fn try_from(flags: CK_FLAGS) -> Result<Self> {
        if flags & !(CKF_OS_LOCKING_OK | CKF_LIBRARY_CANT_CREATE_OS_THREADS) != 0 {
            Err(Error::InvalidValue)
        } else {
            Ok(Self { flags })
        }
    }
}