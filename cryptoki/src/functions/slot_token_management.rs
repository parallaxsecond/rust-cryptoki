// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Slot and token management functions

use crate::get_pkcs11;
use crate::types::function::Rv;
use crate::types::mechanism::{MechanismInfo, MechanismType};
use crate::types::slot_token::{Slot, TokenInfo};
use crate::Pkcs11;
use crate::Result;
use crate::Session;
use cryptoki_sys::{CK_MECHANISM_INFO, CK_TOKEN_INFO};
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

    /// Get all slots available with a token
    pub fn get_slots_with_initialized_token(&self) -> Result<Vec<Slot>> {
        let slots = self.get_slots_with_token()?;

        slots
            .into_iter()
            .filter_map(|slot| match self.get_token_info(slot) {
                Ok(token_info) => {
                    if token_info.get_flags().token_initialized() {
                        Some(Ok(slot))
                    } else {
                        None
                    }
                }
                Err(e) => Some(Err(e)),
            })
            .collect()
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

    /// Returns information about a specific token
    pub fn get_token_info(&self, slot: Slot) -> Result<TokenInfo> {
        unsafe {
            let mut token_info = CK_TOKEN_INFO::default();
            Rv::from(get_pkcs11!(self, C_GetTokenInfo)(
                slot.into(),
                &mut token_info,
            ))
            .into_result()?;
            Ok(TokenInfo::new(token_info))
        }
    }

    /// Get all mechanisms support by a slot
    pub fn get_mechanism_list(&self, slot: Slot) -> Result<Vec<MechanismType>> {
        let mut mechanism_count = 0;

        unsafe {
            Rv::from(get_pkcs11!(self, C_GetMechanismList)(
                slot.into(),
                std::ptr::null_mut(),
                &mut mechanism_count,
            ))
            .into_result()?;
        }

        let mut mechanisms = vec![0; mechanism_count.try_into()?];

        unsafe {
            Rv::from(get_pkcs11!(self, C_GetMechanismList)(
                slot.into(),
                mechanisms.as_mut_ptr(),
                &mut mechanism_count,
            ))
            .into_result()?;
        }

        // Truncate mechanisms if count decreased.
        mechanisms.truncate(mechanism_count.try_into()?);

        Ok(mechanisms
            .into_iter()
            .filter_map(|type_| type_.try_into().ok())
            .collect())
    }

    /// Get detailed information about a mechanism for a slot
    pub fn get_mechanism_info(&self, slot: Slot, type_: MechanismType) -> Result<MechanismInfo> {
        unsafe {
            let mut mechanism_info = CK_MECHANISM_INFO::default();
            Rv::from(get_pkcs11!(self, C_GetMechanismInfo)(
                slot.into(),
                type_.into(),
                &mut mechanism_info,
            ))
            .into_result()?;
            Ok(MechanismInfo::new(mechanism_info))
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
