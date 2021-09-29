// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Session types

use crate::types::slot_token::Slot;
use crate::types::{SessionFlags, Ulong};
use crate::Pkcs11;
use cryptoki_sys::*;
use log::error;
use std::convert::TryInto;
use std::fmt::Formatter;
use std::ops::Deref;

/// Type that identifies a session
///
/// It will automatically get closed (and logout) on drop.
/// Session does not implement Sync to prevent the same Session instance to be used from multiple
/// threads. A Session needs to be created in its own thread or to be passed by ownership to
/// another thread.
#[derive(Debug)]
pub struct Session<'a> {
    handle: CK_SESSION_HANDLE,
    client: &'a Pkcs11,
    // Slot to know the token this session was opened on
    slot: Slot,
    // This is not used but to prevent Session to automatically implement Send and Sync
    _guard: *mut u32,
}

impl std::fmt::Display for Session<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.handle)
    }
}

impl std::fmt::LowerHex for Session<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:08x}", self.handle)
    }
}

impl std::fmt::UpperHex for Session<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:08X}", self.handle)
    }
}

// Session does not implement Sync to prevent the same Session instance to be used from multiple
// threads.
unsafe impl<'a> Send for Session<'a> {}

impl<'a> Session<'a> {
    pub(crate) fn new(handle: CK_SESSION_HANDLE, client: &'a Pkcs11, slot: Slot) -> Self {
        Session {
            handle,
            client,
            slot,
            _guard: std::ptr::null_mut::<u32>(),
        }
    }

    pub(crate) fn handle(&self) -> CK_SESSION_HANDLE {
        self.handle
    }

    pub(crate) fn client(&self) -> &Pkcs11 {
        self.client
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.close_private() {
            error!("Failed to close session: {}", e);
        }
    }
}

/// Types of PKCS11 users
#[derive(Copy, Clone, Debug)]
pub enum UserType {
    /// Security Officer
    So,
    /// User
    User,
    /// Context Specific
    ContextSpecific,
}

impl From<UserType> for CK_USER_TYPE {
    fn from(user_type: UserType) -> CK_USER_TYPE {
        match user_type {
            UserType::So => CKU_SO,
            UserType::User => CKU_USER,
            UserType::ContextSpecific => CKU_CONTEXT_SPECIFIC,
        }
    }
}

/// Represents the state of a session
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SessionState {
    val: CK_STATE,
}

impl SessionState {
    /// Read-only public session
    pub const RO_PUBLIC_SESSION: SessionState = SessionState {
        val: CKS_RO_PUBLIC_SESSION,
    };

    /// Read-only user access
    pub const RO_USER_FUNCTIONS: SessionState = SessionState {
        val: CKS_RO_USER_FUNCTIONS,
    };

    /// Read/write public session
    pub const RW_PUBLIC_SESSION: SessionState = SessionState {
        val: CKS_RW_PUBLIC_SESSION,
    };

    /// Read/write user access
    pub const RW_USER_FUNCTIONS: SessionState = SessionState {
        val: CKS_RW_USER_FUNCTIONS,
    };

    /// Read/write SO access
    pub const RW_SO_FUNCTIONS: SessionState = SessionState {
        val: CKS_RW_SO_FUNCTIONS,
    };

    /// Stringifies the value of a [CK_STATE]
    pub(crate) fn stringify(state: CK_STATE) -> &'static str {
        match state {
            CKS_RO_PUBLIC_SESSION => stringify!(CKS_RO_PUBLIC_SESSION),
            CKS_RO_USER_FUNCTIONS => stringify!(CKS_RO_USER_FUNCTIONS),
            CKS_RW_PUBLIC_SESSION => stringify!(CKS_RW_PUBLIC_SESSION),
            CKS_RW_USER_FUNCTIONS => stringify!(CKS_RW_USER_FUNCTIONS),
            CKS_RW_SO_FUNCTIONS => stringify!(CKS_RW_SO_FUNCTIONS),
            _ => "Unknown state value",
        }
    }
}

impl Deref for SessionState {
    type Target = CK_STATE;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

impl From<SessionState> for CK_STATE {
    fn from(session_state: SessionState) -> Self {
        *session_state
    }
}

impl From<CK_STATE> for SessionState {
    fn from(val: CK_STATE) -> Self {
        Self { val }
    }
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", SessionState::stringify(self.val))
    }
}

/// Type identifying the session information
#[derive(Copy, Clone, Debug)]
pub struct SessionInfo {
    val: CK_SESSION_INFO,
}

impl SessionInfo {
    pub(crate) fn new(val: CK_SESSION_INFO) -> Self {
        Self { val }
    }

    /// Returns an error code defined by the cryptographic device
    pub fn device_error(&self) -> Ulong {
        self.val.ulDeviceError.into()
    }

    /// Returns the flags for this session
    pub fn flags(&self) -> SessionFlags {
        self.val.flags.into()
    }

    /// Returns the state of the session
    pub fn session_state(&self) -> SessionState {
        self.val.state.into()
    }

    /// Returns the slot the session is on
    pub fn slot_id(&self) -> Slot {
        // The unwrap should not fail as `slotID` is a `CK_SLOT_ID ` which is the same type as
        // `slot_id` within the `Slot` structure
        self.val.slotID.try_into().unwrap()
    }
}
