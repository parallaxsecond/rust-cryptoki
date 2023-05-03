// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Pkcs11 context and initialization types

/// Directly get the PKCS #11 operation from the context structure and check for null pointers.
macro_rules! get_pkcs11 {
    ($pkcs11:expr, $func_name:ident) => {
        ($pkcs11
            .impl_
            .function_list
            .$func_name
            .ok_or(crate::error::Error::NullFunctionPointer)?)
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

// Implementation of Pkcs11 class that can be enclosed in a single Arc
pub(crate) struct Pkcs11Impl {
    // Even if this field is never read, it is needed for the pointers in function_list to remain
    // valid.
    _pkcs11_lib: cryptoki_sys::Pkcs11,
    pub(crate) function_list: cryptoki_sys::_CK_FUNCTION_LIST,
}

impl fmt::Debug for Pkcs11Impl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Pkcs11Impl")
            .field("function_list", &self.function_list)
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
            .into_result()
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
    initialized: bool,
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
            let mut list = mem::MaybeUninit::uninit();

            Rv::from(pkcs11_lib.C_GetFunctionList(list.as_mut_ptr())).into_result()?;

            let list_ptr = *list.as_ptr();

            Ok(Pkcs11 {
                impl_: Arc::new(Pkcs11Impl {
                    _pkcs11_lib: pkcs11_lib,
                    function_list: *list_ptr,
                }),
                initialized: false,
            })
        }
    }

    /// Initialize the PKCS11 library
    pub fn initialize(&mut self, init_args: CInitializeArgs) -> Result<()> {
        if !self.initialized {
            initialize(self, init_args)
        } else {
            Err(Error::AlreadyInitialized)
        }
    }

    /// Check whether the PKCS11 library has been initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
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
