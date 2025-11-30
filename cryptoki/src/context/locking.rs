// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Locking related type

use bitflags::bitflags;
use cryptoki_sys::{
    CKF_LIBRARY_CANT_CREATE_OS_THREADS, CKF_OS_LOCKING_OK, CKR_GENERAL_ERROR, CKR_HOST_MEMORY,
    CKR_MUTEX_BAD, CKR_MUTEX_NOT_LOCKED, CKR_OK, CK_FLAGS, CK_RV,
};

use std::{
    mem::ManuallyDrop,
    os::raw::c_void,
    ptr::{self, NonNull},
};

/// Error that occurs during mutex creation
#[derive(Copy, Clone, Debug)]
pub enum CreateError {
    /// CKR_GENERAL_ERROR
    GeneralError,
    ///CKR_HOST_MEMORY
    HostMemory,
}

impl From<CreateError> for CK_RV {
    fn from(value: CreateError) -> Self {
        match value {
            CreateError::GeneralError => CKR_GENERAL_ERROR,
            CreateError::HostMemory => CKR_HOST_MEMORY,
        }
    }
}

/// Error that occurs during mutex destruction
#[derive(Copy, Clone, Debug)]
pub enum DestroyError {
    /// CKR_GENERAL_ERROR
    GeneralError,
    /// CKR_HOST_MEMORY
    HostMemory,
    /// CKR_MUTEX_BAD
    MutexBad,
}

impl From<DestroyError> for CK_RV {
    fn from(value: DestroyError) -> Self {
        match value {
            DestroyError::GeneralError => CKR_GENERAL_ERROR,
            DestroyError::HostMemory => CKR_HOST_MEMORY,
            DestroyError::MutexBad => CKR_MUTEX_BAD,
        }
    }
}

/// Error that occurs during mutex lock
#[derive(Copy, Clone, Debug)]
pub enum LockError {
    /// CKR_GENERAL_ERROR
    GeneralError,
    /// CKR_HOST_MEMORY
    HostMemory,
    /// CKR_MUTEX_BAD
    MutexBad,
}

impl From<LockError> for CK_RV {
    fn from(value: LockError) -> Self {
        match value {
            LockError::GeneralError => CKR_GENERAL_ERROR,
            LockError::HostMemory => CKR_HOST_MEMORY,
            LockError::MutexBad => CKR_MUTEX_BAD,
        }
    }
}

/// Error that occurs during mutex unlock
#[derive(Copy, Clone, Debug)]
pub enum UnlockError {
    /// CKR_GENERAL_ERROR
    GeneralError,
    /// CKR_HOST_MEMORY
    HostMemory,
    /// CKR_MUTEX_BAD
    MutexBad,
    /// CKR_MUTEX_NOT_LOCKED
    MutexNotLocked,
}

impl From<UnlockError> for CK_RV {
    fn from(value: UnlockError) -> Self {
        match value {
            UnlockError::GeneralError => CKR_GENERAL_ERROR,
            UnlockError::HostMemory => CKR_HOST_MEMORY,
            UnlockError::MutexBad => CKR_MUTEX_BAD,
            UnlockError::MutexNotLocked => CKR_MUTEX_NOT_LOCKED,
        }
    }
}

/// Trait to manage lifecycle of mutex objects
pub trait MutexLifeCycle {
    /// Creates a mutex
    fn create() -> Result<Box<Self>, CreateError>;

    /// Destroys a mutex
    fn destroy(&mut self) -> Result<(), DestroyError>;

    /// Locks a mutex
    fn lock(&self) -> Result<(), DestroyError>;

    /// Unlocks a mutex
    fn unlock(&self) -> Result<(), UnlockError>;
}

unsafe extern "C" fn create_mutex<M: MutexLifeCycle>(
    ptr_ptr: *mut *mut ::std::os::raw::c_void,
) -> CK_RV {
    match M::create() {
        Ok(mutex) => {
            // SAFETY: This is called by the PKCS#11 library when it needs to
            // create a mutex so ptr_ptr contains the address of a valid pointer
            unsafe {
                *ptr_ptr = Box::into_raw(mutex) as *mut c_void;
            }

            CKR_OK
        }
        Err(err) => err.into(),
    }
}

unsafe extern "C" fn destroy_mutex<M: MutexLifeCycle>(
    mutex_ptr: *mut ::std::os::raw::c_void,
) -> CK_RV {
    // SAFETY: This is invoked after create_mutex
    // Here we want to drop so ManuallyDrop is not necessary
    let mut mutex = unsafe { Box::<M>::from_raw(mutex_ptr as *mut M) };

    match mutex.destroy() {
        Ok(_) => CKR_OK,
        Err(err) => err.into(),
    }
}

unsafe extern "C" fn lock_mutex<M: MutexLifeCycle>(
    mutex_ptr: *mut ::std::os::raw::c_void,
) -> CK_RV {
    // SAFETY: This is invoked after create_mutex
    let boxed_mutex = unsafe { Box::<M>::from_raw(mutex_ptr as *mut M) };
    // Avoid the call of Box::drop at the end of the function
    let mutex = ManuallyDrop::new(boxed_mutex);

    match mutex.lock() {
        Ok(_) => CKR_OK,
        Err(err) => err.into(),
    }
}

unsafe extern "C" fn unlock_mutex<M: MutexLifeCycle>(
    mutex_ptr: *mut ::std::os::raw::c_void,
) -> CK_RV {
    // SAFETY: This is invoked after create_mutex
    let boxed_mutex = unsafe { Box::<M>::from_raw(mutex_ptr as *mut M) };
    // Avoid the call of Box::drop at the end of the function
    let mutex = ManuallyDrop::new(boxed_mutex);

    match mutex.unlock() {
        Ok(_) => CKR_OK,
        Err(err) => err.into(),
    }
}

bitflags! {
    /// Flags to set for the initialize function
    #[derive(Debug, Clone, Copy)]
    pub struct CInitializeFlags: CK_FLAGS {
        /// The library can use the native OS library for locking or the custom
        const OS_LOCKING_OK = CKF_OS_LOCKING_OK;
        /// The library may not create its own threads
        const LIBRARY_CANT_CREATE_OS_THREADS = CKF_LIBRARY_CANT_CREATE_OS_THREADS;
    }
}

/// Argument for the initialize function
#[derive(Debug, Clone, Copy)]
pub struct CInitializeArgs<M> {
    flags: CInitializeFlags,
    mutex_lifecycle: Option<M>,
    p_reserved: Option<NonNull<c_void>>,
}

impl CInitializeArgs<()> {
    /// Create a new `CInitializeArgs` with the given flags
    ///
    /// # Examples
    /// ```
    /// use cryptoki::context::{CInitializeArgs, CInitializeFlags};
    ///
    /// let args = CInitializeArgs::<()>::new(CInitializeFlags::OS_LOCKING_OK | CInitializeFlags::LIBRARY_CANT_CREATE_OS_THREADS);
    /// ```
    pub fn new(flags: CInitializeFlags) -> Self {
        Self {
            flags,
            mutex_lifecycle: None,
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
            mutex_lifecycle: None,
            p_reserved: Some(p_reserved),
        }
    }
}

impl<M: MutexLifeCycle> CInitializeArgs<M> {
    /// Create a new `CInitializeArgs` with the given flags
    pub const fn new(flags: CInitializeFlags) -> Self {
        Self {
            flags,
            mutex_lifecycle: None,
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
            mutex_lifecycle: None,
            p_reserved: Some(p_reserved),
        }
    }
}

impl From<CInitializeArgs<()>> for cryptoki_sys::CK_C_INITIALIZE_ARGS {
    fn from(c_initialize_args: CInitializeArgs<()>) -> Self {
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

impl<M: MutexLifeCycle> From<CInitializeArgs<M>> for cryptoki_sys::CK_C_INITIALIZE_ARGS {
    fn from(c_initialize_args: CInitializeArgs<M>) -> Self {
        let flags = c_initialize_args.flags.bits();
        let p_reserved = c_initialize_args
            .p_reserved
            .map(|non_null| non_null.as_ptr())
            .unwrap_or_else(ptr::null_mut);
        let mutex_lifecycle = c_initialize_args.mutex_lifecycle;

        Self {
            CreateMutex: mutex_lifecycle.as_ref().map(|_| create_mutex::<M> as _),
            DestroyMutex: mutex_lifecycle.as_ref().map(|_| destroy_mutex::<M> as _),
            LockMutex: mutex_lifecycle.as_ref().map(|_| lock_mutex::<M> as _),
            UnlockMutex: mutex_lifecycle.as_ref().map(|_| unlock_mutex::<M> as _),
            flags,
            pReserved: p_reserved,
        }
    }
}
