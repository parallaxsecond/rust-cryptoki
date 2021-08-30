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
use cryptoki_sys::CK_SESSION_INFO;
use std::convert::TryInto;

impl Pkcs11 {
    /// Open a new session with no callback set
    pub fn open_session_no_callback(&self, slot_id: Slot, flags: SessionFlags) -> Result<Session> {
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

        Ok(Session::new(session_handle, self, slot_id))
    }
}

impl<'a> Session<'a> {
    /// Close a session
    /// This will be called on drop as well.
    pub fn close(&self) {}

    pub(crate) fn close_private(&self) -> Result<()> {
        unsafe { Rv::from(get_pkcs11!(self.client(), C_CloseSession)(self.handle())).into_result() }
    }

    /// Log a session in
    ///
    /// Do not fail if the user is already logged in. It happens if another session on the same slot
    /// has already called the log in operation. Record the login call and only log out when there
    /// aren't anymore sessions requiring log in state.
    pub fn login(&self, user_type: UserType) -> Result<()> {
        self.client().login(self, user_type)
    }

    /// Log a session out
    ///
    /// Will also be called on drop.
    pub fn logout(&self) -> Result<()> {
        self.client().logout(self)
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
