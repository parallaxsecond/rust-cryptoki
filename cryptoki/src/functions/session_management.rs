// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Session management functions

use crate::get_pkcs11;
use crate::types::function::Rv;
use crate::types::session::{Session, SessionInfo, UserType};
use crate::types::slot_token::Slot;
use crate::types::SessionFlags;
use crate::Pkcs11;
use crate::Result;
use cryptoki_sys::{CK_SESSION_HANDLE, CK_SESSION_INFO};
use std::convert::TryInto;

impl Pkcs11 {
    fn open_session(&self, slot_id: Slot, flags: SessionFlags) -> Result<CK_SESSION_HANDLE> {
        let mut session_handle = 0;

        unsafe {
            Rv::from(get_pkcs11!(self, C_OpenSession)(
                slot_id.try_into()?,
                flags.into(),
                // TODO: abstract those types or create new functions for callbacks
                std::ptr::null_mut(),
                None,
                &mut session_handle,
            ))
            .into_result()?;
        }
        Ok(session_handle)
    }

    /// Open a new session with no callback set
    pub fn open_session_no_callback(&self, slot_id: Slot, flags: SessionFlags) -> Result<Session> {
        Ok(Session::new(self.open_session(slot_id, flags)?, self))
    }

    /// Opens a new management session on a token
    ///
    /// The purpose of a management session is to hold the state of all sessions opened on a token
    /// by the running application.  This allows threads to open their own session, already at the
    /// desired state set by the management session.
    ///
    /// # Arguments
    ///
    /// * `slot_id` - The slot to open the session on
    /// * `flags` - The flags for the session
    /// * `user_type` - The type of user to login
    /// * `pin` - The PIN to use, or `None` if a separate authentication path exists
    ///
    /// # Errors
    ///
    /// If the session fails to open, the typical [`Error::Pkcs11`] will return.  If a management
    /// session already exists for the token, then [`Error::ManagementSessionExists`] will be
    /// returned.
    pub fn open_management_session(
        &self,
        slot_id: Slot,
        flags: SessionFlags,
        user_type: UserType,
        pin: Option<&str>,
    ) -> Result<()> {
        let mut map = self
            .management_sessions
            .lock()
            .map_err(|_e| crate::Error::MutexPoisonError)?;
        if let std::collections::hash_map::Entry::Vacant(_) = map.entry(slot_id) {
            let session_handle = self.open_session(slot_id, flags)?;
            let (pin, pin_len) = match pin {
                Some(pin) => (pin.as_ptr() as *mut u8, pin.len()),
                None => (std::ptr::null_mut(), 0),
            };
            unsafe {
                Rv::from(get_pkcs11!(self, C_Login)(
                    session_handle,
                    user_type.into(),
                    pin,
                    pin_len.try_into()?,
                ))
                .into_result()
                .map_err(|e| {
                    // Close the session if we can't login and return the resulting error
                    // Not using `get_pkcs11` here because the macro uses a '?' which is not
                    // allowed in a closure that does not return a Result.
                    // Justification for unwrap -> If C_CloseSession doesn't exist, the
                    // library is frankly unusable.
                    let _ = self.function_list.C_CloseSession.unwrap()(session_handle);
                    e
                })?;
            }

            let _ = map.insert(slot_id, session_handle);
            Ok(())
        } else {
            Err(crate::Error::ManagementSessionExists)
        }
    }

    /// Closes the management session on the slot
    ///
    /// # Errors
    ///
    /// If the session fails to close, the typical [`Error::Pkcs11`] will return.  If a management
    /// session does not exist on this token, then [`Error::ManagementSessionDoesNotExist`] will
    /// be returned.
    ///
    /// Even if the close session call fails, the value will still be removed from the map
    pub fn close_management_session(&self, slot_id: Slot) -> Result<()> {
        let mut map = self
            .management_sessions
            .lock()
            .map_err(|_e| crate::Error::MutexPoisonError)?;
        let session_handle = map
            .remove(&slot_id)
            .ok_or(crate::Error::ManagementSessionDoesNotExist)?;
        unsafe { Rv::from(get_pkcs11!(self, C_CloseSession)(session_handle)).into_result() }
    }
}

impl<'a> Session<'a> {
    /// Close a session
    /// This will be called on drop as well.
    pub fn close(&self) {}

    pub(crate) fn close_private(&self) -> Result<()> {
        unsafe { Rv::from(get_pkcs11!(self.client(), C_CloseSession)(self.handle())).into_result() }
    }

    /// Log a session in.
    ///
    /// # Arguments
    ///
    /// * `user_type` - The type of user to log in as
    /// * `pin` - The PIN to use, or `None` if you wish to use the protected authentication path
    ///
    /// _NOTE: By passing `None` into `login`, you must ensure that the
    /// [CKF_PROTECTED_AUTHENTICATION_PATH] flag is set in the `TokenFlags`._
    pub fn login(&self, user_type: UserType, pin: Option<&str>) -> Result<()> {
        let (pin, pin_len) = match pin {
            Some(pin) => (pin.as_ptr() as *mut u8, pin.len()),
            None => (std::ptr::null_mut(), 0),
        };
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_Login)(
                self.handle(),
                user_type.into(),
                pin,
                pin_len.try_into()?,
            ))
            .into_result()
        }
    }

    /// Log a session out
    pub fn logout(&self) -> Result<()> {
        unsafe { Rv::from(get_pkcs11!(self.client(), C_Logout)(self.handle())).into_result() }
    }

    /// Returns the information about a session
    pub fn get_session_info(&self) -> Result<SessionInfo> {
        let mut session_info = CK_SESSION_INFO::default();
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_GetSessionInfo)(
                self.handle(),
                &mut session_info,
            ))
            .into_result()?;
            Ok(SessionInfo::new(session_info))
        }
    }
}
