// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! General-purpose functions

use crate::get_pkcs11;
use crate::types::function::Rv;
use crate::types::locking::CInitializeArgs;
use crate::Pkcs11;
use crate::Result;
use cryptoki_sys::CK_C_INITIALIZE_ARGS;
use std::ptr;

impl Pkcs11 {
    /// Initialize the PKCS11 library
    pub fn initialize(&self, init_args: CInitializeArgs) -> Result<()> {
        // if no args are specified, library expects NULL
        let mut init_args = CK_C_INITIALIZE_ARGS::from(init_args);
        let init_args_ptr = &mut init_args;
        unsafe {
            Rv::from(get_pkcs11!(self, C_Initialize)(
                init_args_ptr as *mut CK_C_INITIALIZE_ARGS as *mut ::std::ffi::c_void,
            ))
            .into_result()
        }
    }

    pub(crate) fn finalize_private(&self) -> Result<()> {
        // Safe because Session contain a reference to self so that this function can not be called
        // while there are live Session instances.
        unsafe { Rv::from(get_pkcs11!(self, C_Finalize)(ptr::null_mut())).into_result() }
    }

    /// Finalize the PKCS11 library. Indicates that the application no longer needs to use PKCS11.
    /// The library is also automatically finalized on drop.
    pub fn finalize(self) {}
}
