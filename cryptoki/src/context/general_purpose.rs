// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! General-purpose functions

use crate::context::{CInitializeArgs, Info, Pkcs11};
use crate::error::{Result, Rv};
use cryptoki_sys::{CK_C_INITIALIZE_ARGS, CK_INFO};
use std::convert::TryFrom;

// See public docs on stub in parent mod.rs
#[inline(always)]
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

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn get_library_info(ctx: &Pkcs11) -> Result<Info> {
    let mut info = CK_INFO::default();
    unsafe {
        Rv::from(get_pkcs11!(ctx, C_GetInfo)(&mut info)).into_result()?;
        Info::try_from(info)
    }
}
