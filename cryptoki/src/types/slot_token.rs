//! Slot and token types

use cryptoki_sys::CK_SLOT_ID;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Type identifying a slot
pub struct Slot {
    slot_id: u64,
}

impl Slot {
    pub(crate) fn new(slot_id: CK_SLOT_ID) -> Slot {
        Slot { slot_id }
    }

    /// Underlying ID used for a slot
    pub fn id(&self) -> u64 {
        self.slot_id
    }

    /// It is sometimes useful to create a Slot instance from a specific slot ID. If the slot_id
    /// does not correspond to any slot, methods using it will fail safely.
    /// Prefer using the Slot and Token Management methods to be sure to have valid slots to work
    /// with.
    pub fn from_u64(slot_id: u64) -> Self {
        Slot { slot_id }
    }
}
