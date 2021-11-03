// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Pkcs11 context and initialization types

/// Directly get the PKCS #11 operation from the context structure and check for null pointers.
macro_rules! get_pkcs11 {
    ($pkcs11:expr, $func_name:ident) => {
        ($pkcs11
            .function_list
            .$func_name
            .ok_or(crate::error::Error::NullFunctionPointer)?)
    };
}

mod flags;
mod general_purpose;
mod info;
mod locking;
mod session_management;
mod slot_token_management;

pub use flags::*;
pub use info::*;
pub use locking::*;

pub use general_purpose::*;
pub use session_management::*;
pub use slot_token_management::*;

use crate::error::{Error, Result, Rv};
use derivative::Derivative;
use log::error;
use std::mem;
use std::path::Path;

/// Main PKCS11 context. Should usually be unique per application.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Pkcs11 {
    // Even if this field is never read, it is needed for the pointers in function_list to remain
    // valid.
    #[derivative(Debug = "ignore")]
    _pkcs11_lib: cryptoki_sys::Pkcs11,
    pub(crate) function_list: cryptoki_sys::_CK_FUNCTION_LIST,
}

impl Pkcs11 {
    /// Instantiate a new context from the path of a PKCS11 dynamic llibrary implementation.
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
                _pkcs11_lib: pkcs11_lib,
                function_list: *list_ptr,
            })
        }
    }
}

impl Drop for Pkcs11 {
    fn drop(&mut self) {
        if let Err(e) = self.finalize_private() {
            error!("Failed to finalize: {}", e);
        }
    }
}
