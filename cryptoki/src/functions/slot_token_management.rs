// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Slot and token management functions

use crate::types::function::Rv;
use crate::mechanism::{MechanismInfo, MechanismType};
use crate::slot::{Slot, SlotInfo, TokenInfo};
use crate::Pkcs11;
use crate::Result;
use crate::session::Session;
use crate::{get_pkcs11, label_from_str};
use cryptoki_sys::{CK_MECHANISM_INFO, CK_SLOT_INFO, CK_TOKEN_INFO};
use std::convert::TryInto;

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
                    if token_info.flags().token_initialized() {
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
    pub fn init_token(&self, slot: Slot, pin: &str, label: &str) -> Result<()> {
        let label = label_from_str(label);
        unsafe {
            Rv::from(get_pkcs11!(self, C_InitToken)(
                slot.try_into()?,
                pin.as_ptr() as *mut u8,
                pin.len().try_into()?,
                label.as_ptr() as *mut u8,
            ))
            .into_result()
        }
    }

    /// Returns the slot info
    pub fn get_slot_info(&self, slot: Slot) -> Result<SlotInfo> {
        unsafe {
            let mut slot_info = CK_SLOT_INFO::default();
            Rv::from(get_pkcs11!(self, C_GetSlotInfo)(
                slot.try_into()?,
                &mut slot_info,
            ))
            .into_result()?;
            Ok(SlotInfo::new(slot_info))
        }
    }

    /// Returns information about a specific token
    pub fn get_token_info(&self, slot: Slot) -> Result<TokenInfo> {
        unsafe {
            let mut token_info = CK_TOKEN_INFO::default();
            Rv::from(get_pkcs11!(self, C_GetTokenInfo)(
                slot.try_into()?,
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
                slot.try_into()?,
                std::ptr::null_mut(),
                &mut mechanism_count,
            ))
            .into_result()?;
        }

        let mut mechanisms = vec![0; mechanism_count.try_into()?];

        unsafe {
            Rv::from(get_pkcs11!(self, C_GetMechanismList)(
                slot.try_into()?,
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
                slot.try_into()?,
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
