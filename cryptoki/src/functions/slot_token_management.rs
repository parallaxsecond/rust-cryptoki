// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Slot and token management functions

use crate::get_pkcs11;
use crate::types::function::Rv;
use crate::types::slot_token::Slot;
use crate::Pkcs11;
use crate::Result;
use crate::Session;
use secrecy::{ExposeSecret, Secret};
use std::convert::TryInto;
use std::ffi::CString;

impl Pkcs11 {
    /// Get all slots available with a token
    pub fn get_slots_with_token(&self) -> Result<Vec<Slot>> {
        let mut slot_count = 0;

        unsafe {
            Rv::from(get_pkcs11!(self, C_GetSlotList)(
                cryptoki_sys::CK_TRUE,
                std::ptr::null_mut(),
                &mut slot_count,
            ))
            .into_result()?;
        }

        let mut slots = vec![0; slot_count.try_into()?];

        unsafe {
            Rv::from(get_pkcs11!(self, C_GetSlotList)(
                cryptoki_sys::CK_TRUE,
                slots.as_mut_ptr(),
                &mut slot_count,
            ))
            .into_result()?;
        }

        let mut slots: Vec<Slot> = slots.into_iter().map(Slot::new).collect();

        // This should always truncate slots.
        slots.resize(slot_count.try_into()?, Slot::new(0));

        Ok(slots)
    }

    /// Get all slots
    pub fn get_all_slots(&self) -> Result<Vec<Slot>> {
        let mut slot_count = 0;

        unsafe {
            Rv::from(get_pkcs11!(self, C_GetSlotList)(
                cryptoki_sys::CK_FALSE,
                std::ptr::null_mut(),
                &mut slot_count,
            ))
            .into_result()?;
        }

        let mut slots = vec![0; slot_count.try_into()?];

        unsafe {
            Rv::from(get_pkcs11!(self, C_GetSlotList)(
                cryptoki_sys::CK_FALSE,
                slots.as_mut_ptr(),
                &mut slot_count,
            ))
            .into_result()?;
        }

        let mut slots: Vec<Slot> = slots.into_iter().map(Slot::new).collect();

        // This should always truncate slots.
        slots.resize(slot_count.try_into()?, Slot::new(0));

        Ok(slots)
    }

    /// Initialize a token
    ///
    /// Currently will use an empty label for all tokens.
    pub fn init_token(&self, slot: Slot, pin: &str) -> Result<()> {
        let pin = Secret::new(CString::new(pin)?.into_bytes());
        // FIXME: make a good conversion to the label format
        // 32 is the ASCII code for ' '
        let label = [b' '; 32];
        unsafe {
            Rv::from(get_pkcs11!(self, C_InitToken)(
                slot.into(),
                pin.expose_secret().as_ptr() as *mut u8,
                pin.expose_secret().len().try_into()?,
                label.as_ptr() as *mut u8,
            ))
            .into_result()
        }
    }
}

impl<'a> Session<'a> {
    /// Initialize the normal user's pin for a token
    pub fn init_pin(&self, pin: &str) -> Result<()> {
        let pin = Secret::new(CString::new(pin)?.into_bytes());
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_InitPIN)(
                self.handle(),
                pin.expose_secret().as_ptr() as *mut u8,
                pin.expose_secret().len().try_into()?,
            ))
            .into_result()
        }
    }
}
