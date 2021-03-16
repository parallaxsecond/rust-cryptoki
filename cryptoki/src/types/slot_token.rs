// Depending on the target, CK_SLOT_ID is not u64
#![allow(clippy::useless_conversion)]
#![allow(trivial_numeric_casts)]

//! Slot and token types

use crate::{Error, Result};
use cryptoki_sys::CK_SLOT_ID;
use std::convert::{TryFrom, TryInto};

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
