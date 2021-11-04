// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Slot and token management functions

use crate::error::{Result, Rv};
use crate::session::Session;
use std::convert::TryInto;

// See public docs on stub in parent mod.rs
pub(super) fn init_pin(session: &Session<'_>, pin: &str) -> Result<()> {
    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_InitPIN)(
            session.handle(),
            pin.as_ptr() as *mut u8,
            pin.len().try_into()?,
        ))
        .into_result()
    }
}

// See public docs on stub in parent mod.rs
pub(super) fn set_pin(session: &Session<'_>, old_pin: &str, new_pin: &str) -> Result<()> {
    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_SetPIN)(
            session.handle(),
            old_pin.as_ptr() as *mut u8,
            old_pin.len().try_into()?,
            new_pin.as_ptr() as *mut u8,
            new_pin.len().try_into()?,
        ))
        .into_result()
    }
}
