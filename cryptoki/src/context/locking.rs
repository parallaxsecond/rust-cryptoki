// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Locking related type

use bitflags::bitflags;
use cryptoki_sys::{self, CK_C_INITIALIZE_ARGS, CK_FLAGS};

use std::{
    os::raw::c_void,
    ptr::{self, NonNull},
};

bitflags! {
    /// Flags to set for the initialize function
    #[derive(Debug, Clone, Copy)]
    pub struct CInitializeFlags: CK_FLAGS {
        /// The library can use the native OS library for locking or the custom
        const OS_LOCKING_OK = cryptoki_sys::CKF_OS_LOCKING_OK;
        /// The library may not create its own threads
        const LIBRARY_CANT_CREATE_OS_THREADS = cryptoki_sys::CKF_LIBRARY_CANT_CREATE_OS_THREADS;
    }
}

/// Argument for the initialize function
#[derive(Debug, Clone, Copy)]
pub struct CInitializeArgs {
    flags: CInitializeFlags,
    p_reserved: Option<NonNull<c_void>>,
}

impl CInitializeArgs {
    /// Create a new `CInitializeArgs` with the given flags
    ///
    /// # Examples
    /// ```
    /// use cryptoki::context::{CInitializeArgs, CInitializeFlags};
    ///
    /// let args = CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK | CInitializeFlags::LIBRARY_CANT_CREATE_OS_THREADS);
    /// ```
    pub fn new(flags: CInitializeFlags) -> Self {
        Self {
            flags,
            p_reserved: None,
        }
    }

    /// Create a new `CInitializeArgs` with the given flags and reserved pointer.
    ///
    /// # Safety
    /// Considered unsafe due to the user's ability to pass any pointer: the
    /// caller must ensure that the provided pointer is valid and points
    /// to a struct that has the same ABI as the one required by cryptoki's
    /// `C_Initialize`
    ///
    /// The user is responsible for managing the memory behind the pointer.
    ///
    /// # Examples
    ///```
    /// use cryptoki::context::{CInitializeArgs, CInitializeFlags};
    /// use std::{ptr::NonNull, os::raw::c_void};
    ///
    /// let flags = CInitializeFlags::OS_LOCKING_OK;
    ///
    /// // Create a box with the reserved data
    /// let boxed_data = Box::new(42);
    ///
    /// // Obtain the raw pointer
    /// let ptr_reserved = NonNull::new(Box::into_raw(boxed_data) as *mut c_void)
    ///     .expect("Failed to create NonNull pointer");
    ///
    /// // SAFETY: since the data was allocated when boxed_data was created, this is safe
    /// let args = unsafe {
    ///     CInitializeArgs::new_with_reserved(flags, ptr_reserved)
    /// };
    ///
    /// // Reassemble back the box to make sure the data is correctly cleaned
    /// // SAFETY: since ptr_reserved was built with valid data, this is safe
    /// let reserved_data = unsafe { Box::from_raw(ptr_reserved.as_ptr()) };
    /// ```
    pub const unsafe fn new_with_reserved(
        flags: CInitializeFlags,
        p_reserved: NonNull<c_void>,
    ) -> Self {
        Self {
            flags,
            p_reserved: Some(p_reserved),
        }
    }
}

impl From<CInitializeArgs> for CK_C_INITIALIZE_ARGS {
    fn from(c_initialize_args: CInitializeArgs) -> Self {
        let flags = c_initialize_args.flags.bits();
        let p_reserved = c_initialize_args
            .p_reserved
            .map(|non_null| non_null.as_ptr())
            .unwrap_or_else(ptr::null_mut);

        Self {
            CreateMutex: None,
            DestroyMutex: None,
            LockMutex: None,
            UnlockMutex: None,
            flags,
            pReserved: p_reserved,
        }
    }
}
