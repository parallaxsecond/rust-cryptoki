// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Locking related type

use crate::types::InitializeFlags;
use std::ptr;

/// Argument for the initialize function
#[derive(Copy, Clone, Debug)]
pub enum CInitializeArgs {
    /// The library can use the native OS library for locking
    OsThreads,
    // TODO: add variants for custom mutexes here and no multithreading, safety implications for
    // that.
}

impl From<CInitializeArgs> for cryptoki_sys::CK_C_INITIALIZE_ARGS {
    fn from(c_initialize_args: CInitializeArgs) -> Self {
        let mut flags = InitializeFlags::default();
        match c_initialize_args {
            CInitializeArgs::OsThreads => {
                let _ = flags.set_os_locking_ok(true);
                Self {
                    flags: flags.into(),
                    CreateMutex: None,
                    DestroyMutex: None,
                    LockMutex: None,
                    UnlockMutex: None,
                    pReserved: ptr::null_mut(),
                }
            }
        }
    }
}
