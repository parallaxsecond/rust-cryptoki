// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! General-purpose functions

use crate::context::{CInitializeArgs, Info, Pkcs11};
use crate::error::{Result, Rv};
use cryptoki_sys::{CK_C_INITIALIZE_ARGS, CK_INFO};
use std::ptr;

// See public docs on stub in parent mod.rs
pub(super) fn initialize(ctx: &Pkcs11, init_args: CInitializeArgs) -> Result<()> {
    // if no args are specified, library expects NULL
    let mut init_args = CK_C_INITIALIZE_ARGS::from(init_args);
    let init_args_ptr = &mut init_args;
    unsafe {
        Rv::from(get_pkcs11!(ctx, C_Initialize)(
            init_args_ptr as *mut CK_C_INITIALIZE_ARGS as *mut ::std::ffi::c_void,
        ))
        .into_result()
    }
}

pub(super) fn finalize_private(ctx: &Pkcs11) -> Result<()> {
    // Safe because Session contain a reference to self so that this function can not be called
    // while there are live Session instances.
    unsafe { Rv::from(get_pkcs11!(ctx, C_Finalize)(ptr::null_mut())).into_result() }
}

// See public docs on stub in parent mod.rs
pub(super) fn get_library_info(ctx: &Pkcs11) -> Result<Info> {
    let mut info = CK_INFO::default();
    unsafe {
        Rv::from(get_pkcs11!(ctx, C_GetInfo)(&mut info)).into_result()?;
        Ok(Info::new(info))
    }
}
