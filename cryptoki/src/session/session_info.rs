// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Session info

use crate::{
    flag::{CkFlags, FlagBit},
    slot::Slot,
};
use cryptoki_sys::*;
use std::fmt::{self, Debug, Formatter};

use super::SessionState;

const RW_SESSION: FlagBit<SessionInfo> = FlagBit::new(CKF_RW_SESSION);
const SERIAL_SESSION: FlagBit<SessionInfo> = FlagBit::new(CKF_SERIAL_SESSION);

impl Debug for CkFlags<SessionInfo> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Flags")
            .field("rw_session", &(self.contains(RW_SESSION)))
            .field("serial_session", &(self.contains(SERIAL_SESSION)))
            .finish()
    }
}

/// Provides information about a session
#[derive(Copy, Clone, Debug)]
pub struct SessionInfo {
    slot_id: Slot,
    state: SessionState,
    flags: CkFlags<Self>,
    device_error: u64,
}

impl SessionInfo {
    /// ID of the slot that interfaces the token
    pub fn slot_id(&self) -> Slot {
        self.slot_id
    }

    /// The state of the session
    pub fn session_state(&self) -> SessionState {
        self.state
    }

    /// True if the session has R/W access to token objects, and false if access
    /// is read-only
    pub fn read_write(&self) -> bool {
        self.flags.contains(RW_SESSION)
    }

    /// An error code defined by the cryptographic device (used for errors not
    /// covered by PKCS#11)
    pub fn device_error(&self) -> u64 {
        self.device_error
    }
}

#[doc(hidden)]
impl From<CK_SESSION_INFO> for SessionInfo {
    fn from(val: CK_SESSION_INFO) -> Self {
        #[allow(trivial_numeric_casts)]
        let device_error = val.ulDeviceError as u64;
        Self {
            slot_id: Slot::new(val.slotID),
            state: val.state.into(),
            flags: CkFlags::from(val.flags),
            device_error,
        }
    }
}
