// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Session management functions

use cryptoki_sys::{CKF_RW_SESSION, CKF_SERIAL_SESSION};

use crate::context::Pkcs11;
use crate::error::{Result, Rv};
use crate::session::Session;
use crate::slot::Slot;
use std::convert::TryInto;
// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn open_session_no_callback(
    ctx: &Pkcs11,
    slot_id: Slot,
    read_write: bool,
) -> Result<Session> {
    let mut session_handle = 0;

    let flags = if read_write {
        CKF_SERIAL_SESSION | CKF_RW_SESSION
    } else {
        CKF_SERIAL_SESSION
    };
    unsafe {
        Rv::from(get_pkcs11!(ctx, C_OpenSession)(
            slot_id.try_into()?,
            flags,
            // TODO: abstract those types or create new functions for callbacks
            std::ptr::null_mut(),
            None,
            &mut session_handle,
        ))
        .into_result()?;
    }

    Ok(Session::new(session_handle, ctx.clone()))
}
