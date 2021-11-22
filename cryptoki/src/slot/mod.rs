// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
// Depending on the target, CK_SLOT_ID is not u64
#![allow(clippy::useless_conversion)]
#![allow(trivial_numeric_casts)]

//! Slot and token types

mod flags;
use crate::error::{Error, Result};
use crate::string_from_blank_padded;
use crate::types::{Flags, Ulong, Version};
use cryptoki_sys::{
    CKF_HW_SLOT, CKF_REMOVABLE_DEVICE, CKF_TOKEN_PRESENT, CK_SLOT_ID, CK_SLOT_INFO, CK_TOKEN_INFO,
};
pub use flags::*;
use std::convert::{TryFrom, TryInto};
use std::fmt::Formatter;
use std::ops::Deref;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Type identifying a slot
pub struct Slot {
    slot_id: CK_SLOT_ID,
}

impl std::fmt::LowerHex for Slot {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let val = self.slot_id;

        std::fmt::LowerHex::fmt(&val, f)
    }
}

impl std::fmt::UpperHex for Slot {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let val = self.slot_id;

        std::fmt::UpperHex::fmt(&val, f)
    }
}

impl Slot {
    pub(crate) fn new(slot_id: CK_SLOT_ID) -> Slot {
        Slot { slot_id }
    }

    /// Underlying ID used for a slot
    pub fn id(&self) -> u64 {
        self.slot_id as u64
    }
}

impl TryFrom<u64> for Slot {
    type Error = Error;

    fn try_from(slot_id: u64) -> Result<Self> {
        Ok(Self {
            slot_id: slot_id.try_into()?,
        })
    }
}

impl TryFrom<u32> for Slot {
    type Error = Error;

    fn try_from(slot_id: u32) -> Result<Self> {
        Ok(Self {
            slot_id: slot_id.try_into()?,
        })
    }
}

impl From<Slot> for usize {
    fn from(slot: Slot) -> Self {
        slot.slot_id as usize
    }
}

impl From<Slot> for CK_SLOT_ID {
    fn from(slot: Slot) -> Self {
        slot.slot_id
    }
}

impl std::fmt::Display for Slot {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.slot_id)
    }
}

/// Contains information about the slot
#[derive(Debug, Clone)]
pub struct SlotInfo {
    slot_description: String,
    manufacturer_id: String,
    flags: SlotFlags,
    hardware_version: Version,
    firmware_version: Version,
}

impl SlotInfo {
    /// Returns the slot description
    pub fn slot_description(&self) -> &str {
        &self.slot_description
    }

    /// Returns the manufacturer ID
    pub fn manufacturer_id(&self) -> &str {
        &self.manufacturer_id
    }

    /// Gets value of [`CKF_TOKEN_PRESENT`]
    pub fn token_present(&self) -> bool {
        self.flags.flag(CKF_TOKEN_PRESENT)
    }

    /// Gets value of [`CKF_REMOVABLE_DEVICE`]
    pub fn removable_device(&self) -> bool {
        self.flags.flag(CKF_REMOVABLE_DEVICE)
    }

    /// Gets value of [`CKF_HW_SLOT`]
    pub fn hardware_slot(&self) -> bool {
        self.flags.flag(CKF_HW_SLOT)
    }

    /// Returns the hardware version
    pub fn hardware_version(&self) -> Version {
        self.hardware_version
    }

    /// Returns the firmware version
    pub fn firmware_version(&self) -> Version {
        self.firmware_version
    }
}

impl From<CK_SLOT_INFO> for SlotInfo {
    fn from(val: CK_SLOT_INFO) -> Self {
        Self {
            slot_description: string_from_blank_padded(&val.slotDescription),
            manufacturer_id: string_from_blank_padded(&val.manufacturerID),
            flags: val.flags.into(),
            hardware_version: val.hardwareVersion.into(),
            firmware_version: val.firmwareVersion.into(),
        }
    }
}

/// Contains information about a token
#[derive(Debug, Clone, Copy, Default)]
pub struct TokenInfo {
    val: CK_TOKEN_INFO,
}

impl TokenInfo {
    pub(crate) fn new(val: CK_TOKEN_INFO) -> Self {
        Self { val }
    }

    /// Returns the firmware version
    pub fn firmware_version(&self) -> Version {
        self.val.firmwareVersion.into()
    }

    /// Returns the free private memory
    pub fn free_private_memory(&self) -> Ulong {
        self.val.ulFreePrivateMemory.into()
    }

    /// Returns the free public memory
    pub fn free_public_memory(&self) -> Ulong {
        self.val.ulFreePublicMemory.into()
    }

    /// Returns the hardware version
    pub fn hardware_version(&self) -> Version {
        self.val.hardwareVersion.into()
    }

    /// Returns the label of the token
    pub fn label(&self) -> String {
        string_from_blank_padded(&self.val.label)
    }

    /// Returns the ID of the device manufacturer
    pub fn manufacturer_id(&self) -> String {
        string_from_blank_padded(&self.val.manufacturerID)
    }

    /// Returns the max PIN length
    pub fn max_pin_length(&self) -> Ulong {
        self.val.ulMaxPinLen.into()
    }

    /// Returns the max session count
    pub fn max_session_count(&self) -> Ulong {
        self.val.ulMaxSessionCount.into()
    }

    /// Returns the max r/w session count
    pub fn max_rw_session_count(&self) -> Ulong {
        self.val.ulMaxRwSessionCount.into()
    }

    /// Returns the min PIN length
    pub fn min_pin_length(&self) -> Ulong {
        self.val.ulMinPinLen.into()
    }

    /// Returns the model of the token
    pub fn model(&self) -> String {
        string_from_blank_padded(&self.val.model)
    }

    /// Returns the r/w session count
    pub fn rw_session_count(&self) -> Ulong {
        self.val.ulRwSessionCount.into()
    }

    /// Returns the character-string serial number of the device
    pub fn serial_number(&self) -> String {
        string_from_blank_padded(&self.val.serialNumber)
    }

    /// Returns current session count
    pub fn session_count(&self) -> Ulong {
        self.val.ulSessionCount.into()
    }

    /// Returns the total private memory
    pub fn total_private_memory(&self) -> Ulong {
        self.val.ulTotalPrivateMemory.into()
    }

    /// Returns the total public memory
    pub fn total_public_memory(&self) -> Ulong {
        self.val.ulTotalPublicMemory.into()
    }

    /// Returns the UTC Time of the token
    pub fn utc_time(&self) -> String {
        // UTC time is not blank padded as it has the format YYYYMMDDhhmmssxx where
        // x is the '0' character
        String::from_utf8_lossy(&self.val.utcTime)
            .trim_end()
            .to_string()
    }

    /// Returns the Token's flags
    pub fn flags(&self) -> TokenFlags {
        self.val.flags.into()
    }
}

impl Deref for TokenInfo {
    type Target = CK_TOKEN_INFO;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

impl From<TokenInfo> for CK_TOKEN_INFO {
    fn from(token_info: TokenInfo) -> Self {
        *token_info
    }
}
