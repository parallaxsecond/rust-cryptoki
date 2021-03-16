//! Session types

use crate::types::slot_token::Slot;
use crate::Pkcs11;
use cryptoki_sys::*;
use log::error;

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

    pub(crate) fn slot(&self) -> Slot {
        self.slot
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        // logout is ignored if the session is not logged in
        if let Err(e) = self.logout() {
            error!("Failed to logout session: {}", e);
        }

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
