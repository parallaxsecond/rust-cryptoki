// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Session management functions

use crate::error::{Result, Rv};
use crate::session::{Session, SessionInfo, UserType};
use cryptoki_sys::CK_SESSION_INFO;
use std::convert::{TryFrom, TryInto};

// See public docs on close() in parent mod.rs
#[inline(always)]
pub(super) fn close_private(session: &Session) -> Result<()> {
    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_CloseSession)(
            session.handle(),
        ))
        .into_result()
    }
}

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn login(session: &Session, user_type: UserType, pin: Option<&str>) -> Result<()> {
    let (pin, pin_len) = match pin {
        Some(pin) => (pin.as_ptr() as *mut u8, pin.len()),
        None => (std::ptr::null_mut(), 0),
    };
    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_Login)(
            session.handle(),
            user_type.into(),
            pin,
            pin_len.try_into()?,
        ))
        .into_result()
    }
}

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn login_with_raw(session: &Session, user_type: UserType, pin: &[u8]) -> Result<()> {
    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_Login)(
            session.handle(),
            user_type.into(),
            pin.as_ptr() as *mut u8,
            pin.len().try_into()?,
        ))
        .into_result()
    }
}

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn logout(session: &Session) -> Result<()> {
    unsafe { Rv::from(get_pkcs11!(session.client(), C_Logout)(session.handle())).into_result() }
}

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn get_session_info(session: &Session) -> Result<SessionInfo> {
    let mut session_info = CK_SESSION_INFO::default();
    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_GetSessionInfo)(
            session.handle(),
            &mut session_info,
        ))
        .into_result()?;
        SessionInfo::try_from(session_info)
    }
}
