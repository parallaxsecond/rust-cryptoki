// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Slot and token management functions

use crate::context::Pkcs11;
use crate::error::{Result, Rv};
use crate::label_from_str;
use crate::mechanism::{MechanismInfo, MechanismType};
use crate::slot::{Slot, SlotInfo, TokenInfo};
use cryptoki_sys::{CK_BBOOL, CK_MECHANISM_INFO, CK_SLOT_INFO, CK_TOKEN_INFO};
use std::convert::TryInto;

use crate::error::RvError::BufferTooSmall;

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn get_slots(ctx: &Pkcs11, with_token: CK_BBOOL) -> Result<Vec<Slot>> {
    let mut slot_count = 0;
    let rval = unsafe {
        get_pkcs11!(ctx, C_GetSlotList)(with_token, std::ptr::null_mut(), &mut slot_count)
    };
    Rv::from(rval).into_result()?;

    let mut slots;
    loop {
        slots = vec![0; slot_count as usize];
        let rval = unsafe {
            get_pkcs11!(ctx, C_GetSlotList)(with_token, slots.as_mut_ptr(), &mut slot_count)
        };
        // Account for a race condition between the call to get the
        // slot_count and the last call in which the number of slots grew.
        // In this case, slot_count will have been updated to the larger amount
        // and we want to loop again with a resized buffer.
        if !matches!(Rv::from(rval), Rv::Error(BufferTooSmall)) {
            // Account for other possible error types
            Rv::from(rval).into_result()?;
            // Otherwise, we have a valid list to process
            break;
        }
    }
    // Account for the same race condition, but with a shrinking slot_count
    slots.truncate(slot_count as usize);
    Ok(slots.into_iter().map(Slot::new).collect())
}

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn get_slots_with_initialized_token(ctx: &Pkcs11) -> Result<Vec<Slot>> {
    let slots = ctx.get_slots_with_token()?;

    slots
        .into_iter()
        .filter_map(|slot| match ctx.get_token_info(slot) {
            Ok(token_info) => {
                if token_info.token_initialized() {
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
        Ok(TokenInfo::from(token_info))
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
        Ok(MechanismInfo::from(mechanism_info))
    }
}
