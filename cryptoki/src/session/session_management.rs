// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Session management functions

use crate::error::{Result, Rv};
use crate::session::{Session, SessionInfo, UserType};
use cryptoki_sys::CK_SESSION_INFO;
use std::convert::TryInto;

impl Session<'_> {
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
