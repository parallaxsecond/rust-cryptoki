// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Slot and token management functions

use crate::error::{Result, Rv};
use crate::session::Session;
use std::convert::TryInto;

impl Session<'_> {
    /// Initialize the normal user's pin for a token
    pub fn init_pin(&self, pin: &str) -> Result<()> {
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_InitPIN)(
                self.handle(),
                pin.as_ptr() as *mut u8,
                pin.len().try_into()?,
            ))
            .into_result()
        }
    }

    /// Changes the PIN of either the currently logged in user or of the `CKU_USER` if no user is
    /// logged in.
    pub fn set_pin(&self, old_pin: &str, new_pin: &str) -> Result<()> {
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_SetPIN)(
                self.handle(),
                old_pin.as_ptr() as *mut u8,
                old_pin.len().try_into()?,
                new_pin.as_ptr() as *mut u8,
                new_pin.len().try_into()?,
            ))
            .into_result()
        }
    }
}
