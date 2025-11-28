// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Locking related type

use cryptoki_sys::{CKF_LIBRARY_CANT_CREATE_OS_THREADS, CKF_OS_LOCKING_OK, CK_FLAGS, CK_RV};

use std::{
    os::raw::c_void,
    ptr::{self, NonNull},
};

/// Function pointer that creates a mutex
pub type CreateMutexFn = unsafe extern "C" fn(*mut *mut ::std::os::raw::c_void) -> CK_RV;

/// Function pointer that destroys a mutex
pub type DestroyMutexFn = unsafe extern "C" fn(*mut ::std::os::raw::c_void) -> CK_RV;

/// Function pointer that locks a mutex
pub type LockMutexFn = unsafe extern "C" fn(*mut ::std::os::raw::c_void) -> CK_RV;

/// Function pointer that unlocks a mutex
pub type UnlockMutexFn = unsafe extern "C" fn(*mut ::std::os::raw::c_void) -> CK_RV;

/// Provides function pointers for mutex-handling to ensure safe multi-threaded access.
#[derive(Copy, Clone, Debug)]
pub struct CustomMutexHandling {
    create_mutex: CreateMutexFn,
    destroy_mutex: DestroyMutexFn,
    lock_mutex: LockMutexFn,
    unlock_mutex: UnlockMutexFn,
}

impl CustomMutexHandling {
    /// Create a new `CustomMutexHandling` with the given function pointers
    /// to handle library's thread safety.
    ///
    /// # Safety
    /// Considered unsafe due to user's ability to pass any function pointer.
    pub const unsafe fn new(
        create_mutex: CreateMutexFn,
        destroy_mutex: DestroyMutexFn,
        lock_mutex: LockMutexFn,
        unlock_mutex: UnlockMutexFn,
    ) -> Self {
        Self {
            create_mutex: create_mutex,
            destroy_mutex: destroy_mutex,
            lock_mutex: lock_mutex,
            unlock_mutex: unlock_mutex,
        }
    }
}

/// Flags to set for the initialize function
#[derive(Copy, Clone, Debug)]
pub enum CInitializeFlags {
    /// The library won’t be accessed from multiple threads simultaneously
    None,
    /// The library may not create its own threads
    NoOsThreads,
    /// The library can use the native OS library for locking or the custom
    OsThreads,
    /// The library needs to use the supplied function pointers
    /// for mutex-handling to ensure safe multi-threaded access.
    CustomMutexHandling(CustomMutexHandling),
    /// The library needs to use either the native operating system primitives
    /// or the supplied function pointers for mutex-handling to ensure safe
    /// multi-threaded access
    OsThreadsOrCustomMutexHandling(CustomMutexHandling),
}

#[derive(Copy, Clone, Debug)]
/// Argument for the initialize function
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
    /// let args = CInitializeArgs::new(CInitializeFlags::OsThreads);
    /// ```
    pub const fn new(flags: CInitializeFlags) -> Self {
        Self {
            flags,
            p_reserved: None,
        }
    }

    /// Create a new `CInitializeArgs` with the given flags and reserved pointer.
    ///
    /// # Safety
    /// Considered unsafe due to the user's ability to pass any pointer.
    ///
    /// The user is responsible for managing the memory behind the pointer.
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

impl From<CInitializeArgs> for cryptoki_sys::CK_C_INITIALIZE_ARGS {
    fn from(c_initialize_args: CInitializeArgs) -> Self {
        let mut flags = CK_FLAGS::default();
        let p_reserved = c_initialize_args
            .p_reserved
            .map(|non_null| non_null.as_ptr())
            .unwrap_or_else(ptr::null_mut);

        match c_initialize_args.flags {
            CInitializeFlags::None => Self {
                CreateMutex: None,
                DestroyMutex: None,
                LockMutex: None,
                UnlockMutex: None,
                flags,
                pReserved: p_reserved,
            },
            CInitializeFlags::NoOsThreads => {
                flags |= CKF_LIBRARY_CANT_CREATE_OS_THREADS;
                Self {
                    flags,
                    CreateMutex: None,
                    DestroyMutex: None,
                    LockMutex: None,
                    UnlockMutex: None,
                    pReserved: p_reserved,
                }
            }
            CInitializeFlags::OsThreads => {
                flags |= CKF_OS_LOCKING_OK;
                Self {
                    flags,
                    CreateMutex: None,
                    DestroyMutex: None,
                    LockMutex: None,
                    UnlockMutex: None,
                    pReserved: p_reserved,
                }
            }
            CInitializeFlags::CustomMutexHandling(custom_mutex_handling) => Self {
                flags,
                CreateMutex: Some(custom_mutex_handling.create_mutex),
                DestroyMutex: Some(custom_mutex_handling.destroy_mutex),
                LockMutex: Some(custom_mutex_handling.lock_mutex),
                UnlockMutex: Some(custom_mutex_handling.unlock_mutex),
                pReserved: p_reserved,
            },
            CInitializeFlags::OsThreadsOrCustomMutexHandling(custom_mutex_handling) => {
                flags |= CKF_OS_LOCKING_OK;
                Self {
                    flags,
                    CreateMutex: Some(custom_mutex_handling.create_mutex),
                    DestroyMutex: Some(custom_mutex_handling.destroy_mutex),
                    LockMutex: Some(custom_mutex_handling.lock_mutex),
                    UnlockMutex: Some(custom_mutex_handling.unlock_mutex),
                    pReserved: p_reserved,
                }
            }
        }
    }
}
