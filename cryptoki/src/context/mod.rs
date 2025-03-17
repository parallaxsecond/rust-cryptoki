// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Pkcs11 context and initialization types

/// Directly get the PKCS #11 operation from the context structure and check for null pointers.
/// Note that this macro depends on the get_pkcs11_func! macro.
macro_rules! get_pkcs11 {
    ($pkcs11:expr, $func_name:ident) => {
        (get_pkcs11_func!($pkcs11, $func_name).ok_or(crate::error::Error::NullFunctionPointer)?)
    };
}

/// Same as get_pkcs11! but does not attempt to apply '?' syntactic sugar.
/// Suitable only if the caller can't return a Result.
macro_rules! get_pkcs11_func {
    ($pkcs11:expr, $func_name:ident) => {
        ($pkcs11.impl_.function_list.$func_name)
    };
}

mod general_purpose;
mod info;
mod locking;
mod session_management;
mod slot_token_management;

pub use general_purpose::*;
pub use info::*;
pub use locking::*;

use crate::error::{Error, Result, Rv};

use log::error;
use std::fmt;
use std::mem;
use std::path::Path;
use std::ptr;
use std::sync::Arc;
use std::sync::RwLock;

// Implementation of Pkcs11 class that can be enclosed in a single Arc
pub(crate) struct Pkcs11Impl {
    // Even if this field is never read, it is needed for the pointers in function_list to remain
    // valid.
    _pkcs11_lib: cryptoki_sys::Pkcs11,
    pub(crate) function_list: cryptoki_sys::CK_FUNCTION_LIST,
    pub(crate) function_list_30: Option<cryptoki_sys::CK_FUNCTION_LIST_3_0>,
}

impl fmt::Debug for Pkcs11Impl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Pkcs11Impl")
            .field("function_list", &self.function_list)
            .field("function_list_30", &self.function_list_30)
            .finish()
    }
}

impl Pkcs11Impl {
    // Private finalize call
    #[inline(always)]
    fn finalize(&self) -> Result<()> {
        unsafe {
            Rv::from(self
                .function_list
                .C_Finalize
                .ok_or(Error::NullFunctionPointer)?(
                ptr::null_mut()
            ))
            .into_result(Function::Finalize)
        }
    }
}

impl Drop for Pkcs11Impl {
    fn drop(&mut self) {
        if let Err(e) = self.finalize() {
            error!("Failed to finalize: {}", e);
        }
    }
}

/// Main PKCS11 context. Should usually be unique per application.
#[derive(Clone, Debug)]
pub struct Pkcs11 {
    pub(crate) impl_: Arc<Pkcs11Impl>,
    initialized: Arc<RwLock<bool>>,
}

impl Pkcs11 {
    /// Instantiate a new context from the path of a PKCS11 dynamic library implementation.
    pub fn new<P>(filename: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        unsafe {
            let pkcs11_lib =
                cryptoki_sys::Pkcs11::new(filename.as_ref()).map_err(Error::LibraryLoading)?;
            Self::_new(pkcs11_lib)
        }
    }

    /// Instantiate a new context from current executable, the PKCS11 implementation is contained in the current executable
    pub fn new_from_self() -> Result<Self> {
        unsafe {
            #[cfg(not(windows))]
            let this_lib = libloading::os::unix::Library::this();
            #[cfg(windows)]
            let this_lib = libloading::os::windows::Library::this()?;
            let pkcs11_lib = cryptoki_sys::Pkcs11::from_library(this_lib)?;
            Self::_new(pkcs11_lib)
        }
    }

    unsafe fn _new(pkcs11_lib: cryptoki_sys::Pkcs11) -> Result<Self> {
        /* First try the 3.0 API to get default interface. It might have some more functions than
         * the 2.4 API */
        let mut interface = mem::MaybeUninit::uninit();
        if pkcs11_lib.C_GetInterface.is_ok() {
            Rv::from(pkcs11_lib.C_GetInterface(
                ptr::null_mut(),
                ptr::null_mut(),
                interface.as_mut_ptr(),
                0,
            ))
            .into_result(Function::GetInterface)?;
            if !interface.as_ptr().is_null() {
                let ifce_ptr: *mut cryptoki_sys::CK_INTERFACE = *interface.as_ptr();
                let ifce: cryptoki_sys::CK_INTERFACE = *ifce_ptr;

                let list_ptr: *mut cryptoki_sys::CK_FUNCTION_LIST =
                    ifce.pFunctionList as *mut cryptoki_sys::CK_FUNCTION_LIST;
                let list: cryptoki_sys::CK_FUNCTION_LIST = *list_ptr;
                if list.version.major >= 3 {
                    let list30_ptr: *mut cryptoki_sys::CK_FUNCTION_LIST_3_0 =
                        ifce.pFunctionList as *mut cryptoki_sys::CK_FUNCTION_LIST_3_0;
                    return Ok(Pkcs11 {
                        impl_: Arc::new(Pkcs11Impl {
                            _pkcs11_lib: pkcs11_lib,
                            function_list: *list_ptr, /* the function list aliases */
                            function_list_30: Some(*list30_ptr),
                        }),
                        initialized: Arc::new(RwLock::new(false)),
                    });
                }
                /* fall back to the 2.* API */
            }
        }

        let mut list = mem::MaybeUninit::uninit();

        Rv::from(pkcs11_lib.C_GetFunctionList(list.as_mut_ptr()))
            .into_result(Function::GetFunctionList)?;

        let list_ptr = *list.as_ptr();

        Ok(Pkcs11 {
            impl_: Arc::new(Pkcs11Impl {
                _pkcs11_lib: pkcs11_lib,
                function_list: *list_ptr,
                function_list_30: None,
            }),
            initialized: Arc::new(RwLock::new(false)),
        })
    }

    /// Initialize the PKCS11 library
    pub fn initialize(&self, init_args: CInitializeArgs) -> Result<()> {
        let mut init_lock = self
            .initialized
            .as_ref()
            .write()
            .expect("lock not to be poisoned");
        if *init_lock {
            Err(Error::AlreadyInitialized)?
        }
        initialize(self, init_args).map(|_| *init_lock = true)
    }

    /// Check whether the PKCS11 library has been initialized
    pub fn is_initialized(&self) -> bool {
        *self
            .initialized
            .as_ref()
            .read()
            .expect("lock not to be poisoned")
    }

    /// Finalize the PKCS11 library. Indicates that the application no longer needs to use PKCS11.
    /// The library is also automatically finalized on drop.
    pub fn finalize(self) {}

    /// Returns the information about the library
    pub fn get_library_info(&self) -> Result<Info> {
        get_library_info(self)
    }

    /// Check whether a given PKCS11 spec-defined function is supported by this implementation
    pub fn is_fn_supported(&self, function: Function) -> bool {
        is_fn_supported(self, function)
    }
}
