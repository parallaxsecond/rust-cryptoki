// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Slot and token management functions

use crate::context::Pkcs11;
use crate::error::{Result, Rv};
use crate::label_from_str;
use crate::mechanism::{MechanismInfo, MechanismType};
use crate::slot::{Slot, SlotInfo, TokenInfo};
use cryptoki_sys::{CK_MECHANISM_INFO, CK_SLOT_INFO, CK_TOKEN_INFO};
use std::convert::TryInto;

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn get_slots_with_token(ctx: &Pkcs11) -> Result<Vec<Slot>> {
    let mut slot_count = 0;

    unsafe {
        Rv::from(get_pkcs11!(ctx, C_GetSlotList)(
            cryptoki_sys::CK_TRUE,
            std::ptr::null_mut(),
            &mut slot_count,
        ))
        .into_result()?;
    }

    let mut slots = vec![0; slot_count.try_into()?];

    unsafe {
        Rv::from(get_pkcs11!(ctx, C_GetSlotList)(
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

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn get_slots_with_initialized_token(ctx: &Pkcs11) -> Result<Vec<Slot>> {
    let slots = ctx.get_slots_with_token()?;

    slots
        .into_iter()
        .filter_map(|slot| match ctx.get_token_info(slot) {
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

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn get_all_slots(ctx: &Pkcs11) -> Result<Vec<Slot>> {
    let mut slot_count = 0;

    unsafe {
        Rv::from(get_pkcs11!(ctx, C_GetSlotList)(
            cryptoki_sys::CK_FALSE,
            std::ptr::null_mut(),
            &mut slot_count,
        ))
        .into_result()?;
    }

    let mut slots = vec![0; slot_count.try_into()?];

    unsafe {
        Rv::from(get_pkcs11!(ctx, C_GetSlotList)(
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

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn init_token(ctx: &Pkcs11, slot: Slot, pin: &str, label: &str) -> Result<()> {
    let label = label_from_str(label);
    unsafe {
        Rv::from(get_pkcs11!(ctx, C_InitToken)(
            slot.try_into()?,
            pin.as_ptr() as *mut u8,
            pin.len().try_into()?,
            label.as_ptr() as *mut u8,
        ))
        .into_result()
    }
}

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn get_slot_info(ctx: &Pkcs11, slot: Slot) -> Result<SlotInfo> {
    unsafe {
        let mut slot_info = CK_SLOT_INFO::default();
        Rv::from(get_pkcs11!(ctx, C_GetSlotInfo)(
            slot.try_into()?,
            &mut slot_info,
        ))
        .into_result()?;
        Ok(SlotInfo::from(slot_info))
    }
}

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn get_token_info(ctx: &Pkcs11, slot: Slot) -> Result<TokenInfo> {
    unsafe {
        let mut token_info = CK_TOKEN_INFO::default();
        Rv::from(get_pkcs11!(ctx, C_GetTokenInfo)(
            slot.try_into()?,
            &mut token_info,
        ))
        .into_result()?;
        Ok(TokenInfo::new(token_info))
    }
}

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn get_mechanism_list(ctx: &Pkcs11, slot: Slot) -> Result<Vec<MechanismType>> {
    let mut mechanism_count = 0;

    unsafe {
        Rv::from(get_pkcs11!(ctx, C_GetMechanismList)(
            slot.try_into()?,
            std::ptr::null_mut(),
            &mut mechanism_count,
        ))
        .into_result()?;
    }

    let mut mechanisms = vec![0; mechanism_count.try_into()?];

    unsafe {
        Rv::from(get_pkcs11!(ctx, C_GetMechanismList)(
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

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn get_mechanism_info(
    ctx: &Pkcs11,
    slot: Slot,
    type_: MechanismType,
) -> Result<MechanismInfo> {
    unsafe {
        let mut mechanism_info = CK_MECHANISM_INFO::default();
        Rv::from(get_pkcs11!(ctx, C_GetMechanismInfo)(
            slot.try_into()?,
            type_.into(),
            &mut mechanism_info,
        ))
        .into_result()?;
        Ok(MechanismInfo::new(mechanism_info))
    }
}
