// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Session info

use crate::error::{Error, Result};
use crate::flag::{CkFlags, FlagBit};
use crate::slot::Slot;
use cryptoki_sys::*;
use std::convert::{TryFrom, TryInto};
use std::fmt::{self, Debug, Formatter};

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
impl TryFrom<CK_SESSION_INFO> for SessionInfo {
    type Error = Error;
    fn try_from(val: CK_SESSION_INFO) -> Result<Self> {
        #[allow(trivial_numeric_casts)]
        let device_error = val.ulDeviceError as u64;
        Ok(Self {
            slot_id: Slot::new(val.slotID),
            state: val.state.try_into()?,
            flags: CkFlags::from(val.flags),
            device_error,
        })
    }
}

/// The current state of the session which describes access to token and session
/// obects based on user type and login status
#[derive(Debug, Copy, Clone)]
pub enum SessionState {
    /// The session has read-only access to public token objects and R/W access
    /// to to public session objects
    RoPublic,
    /// A normal user has been authenticated to the token.
    /// The session has read-only access to all public and private token objects
    /// The session has R/W access to all public and private session objects
    RoUser,
    /// The session has read/write access to all public objects
    RwPublic,
    /// A normal user has been authenticated to the token.
    /// The session has read/write access to all objects
    RwUser,
    /// A security officer (SO) user has been authenticated to the token.
    /// The session has R/W access only to public token objects. The SO
    /// can set the normal user's PIN.
    RwSecurityOfficer,
}

#[doc(hidden)]
impl TryFrom<CK_STATE> for SessionState {
    type Error = Error;
    fn try_from(value: CK_STATE) -> Result<Self> {
        match value {
            CKS_RO_PUBLIC_SESSION => Ok(Self::RoPublic),
            CKS_RO_USER_FUNCTIONS => Ok(Self::RoUser),
            CKS_RW_PUBLIC_SESSION => Ok(Self::RwPublic),
            CKS_RW_USER_FUNCTIONS => Ok(Self::RwUser),
            CKS_RW_SO_FUNCTIONS => Ok(Self::RwSecurityOfficer),
            _ => Err(Error::InvalidValue),
        }
    }
}
