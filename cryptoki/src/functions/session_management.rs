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
