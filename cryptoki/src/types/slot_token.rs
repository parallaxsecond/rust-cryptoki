// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
// Depending on the target, CK_SLOT_ID is not u64
#![allow(clippy::useless_conversion)]
#![allow(trivial_numeric_casts)]

//! Slot and token types

use crate::types::Flags;
use crate::{Error, Result};
use cryptoki_sys::{CK_SLOT_ID, CK_TOKEN_INFO};
use std::convert::{TryFrom, TryInto};
use std::ops::Deref;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Type identifying a slot
pub struct Slot {
    slot_id: CK_SLOT_ID,
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

impl From<Slot> for CK_SLOT_ID {
    fn from(slot: Slot) -> Self {
        slot.slot_id
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

    /// Returns the ID of the device manufacturer
    pub fn get_manufacturer_id(&self) -> String {
        String::from_utf8_lossy(&self.val.manufacturerID)
            .trim_end()
            .to_string()
    }

    /// Returns the character-string serial number of the device
    pub fn get_serial_number(&self) -> String {
        String::from_utf8_lossy(&self.val.serialNumber)
            .trim_end()
            .to_string()
    }

    /// Returns the Token's flags
    pub fn get_flags(&self) -> Flags {
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
