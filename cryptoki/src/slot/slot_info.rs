// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! PKCS11 Slot info and associated flags

use crate::flag::{CkFlags, FlagBit};
use crate::{string_from_blank_padded, types::Version};
use cryptoki_sys::*;
use std::fmt::{self, Debug, Display, Formatter};

/// Collection of flags defined for [`CK_SLOT_INFO`]
const TOKEN_PRESENT: FlagBit<SlotInfo> = FlagBit::new(CKF_TOKEN_PRESENT);
const REMOVABLE_DEVICE: FlagBit<SlotInfo> = FlagBit::new(CKF_REMOVABLE_DEVICE);
const HW_SLOT: FlagBit<SlotInfo> = FlagBit::new(CKF_HW_SLOT);

impl Debug for CkFlags<SlotInfo> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Flags")
            .field("token_present", &(self.contains(TOKEN_PRESENT)))
            .field("removable_device", &(self.contains(REMOVABLE_DEVICE)))
            .field("hw_slot", &(self.contains(HW_SLOT)))
            .finish()
    }
}

impl Display for CkFlags<SlotInfo> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut set = f.debug_set();
        if self.contains(TOKEN_PRESENT) {
            let _ = set.entry(&"Token Present");
        }
        if self.contains(REMOVABLE_DEVICE) {
            let _ = set.entry(&"Removable Device");
        }
        if self.contains(HW_SLOT) {
            let _ = set.entry(&"Hardware Slot");
        }
        set.finish()
    }
}

/// Information about a slot
#[derive(Debug, Clone)]
pub struct SlotInfo {
    slot_description: String,
    manufacturer_id: String,
    flags: CkFlags<Self>,
    hardware_version: Version,
    firmware_version: Version,
}

impl SlotInfo {
    /// String description of the slot
    ///
    /// **[Conformance](crate#conformance-notes):**
    /// This string is maximally 64 bytes (*not* chars) as UTF-8
    pub fn slot_description(&self) -> &str {
        &self.slot_description
    }

    /// ID of the slot manufacturer
    ///
    /// **[Conformance](crate#conformance-notes):**
    /// This string is maximally 32 bytes (*not* chars) as UTF-8
    pub fn manufacturer_id(&self) -> &str {
        &self.manufacturer_id
    }

    /// True if a token is in the slot (e.g., a device is in the reader).
    ///
    /// **[Conformance](crate#conformance-notes):**
    /// If this slot does not represent a removable device, a token is *always*
    /// considered to be present. That is, `slot.removable device() == false`
    /// implies `slot.token_present() == true`.
    pub fn token_present(&self) -> bool {
        self.flags.contains(TOKEN_PRESENT)
    }

    /// True if the reader supports removable devices.
    ///
    /// **[Conformance](crate#conformance-notes):**
    /// For a given slot, this flag *never* changes
    pub fn removable_device(&self) -> bool {
        self.flags.contains(REMOVABLE_DEVICE)
    }

    /// True if the slot is a hardware slot, as opposed to a software slot
    /// implementing a "soft token"
    pub fn hardware_slot(&self) -> bool {
        self.flags.contains(HW_SLOT)
    }

    /// Version number of the slot's hardware
    pub fn hardware_version(&self) -> Version {
        self.hardware_version
    }

    /// Version number of the slot's firmware
    pub fn firmware_version(&self) -> Version {
        self.firmware_version
    }
}

#[doc(hidden)]
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
