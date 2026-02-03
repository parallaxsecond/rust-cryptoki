// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Slot and token management functions

use crate::context::Function;
use crate::error::{Error, Result, Rv};
use crate::session::Session;
use crate::types::Credential;
use std::convert::TryInto;

impl Session {
    /// Initialize the normal user's PIN for a token.
    ///
    /// This uses the provided credential as the new user PIN. Credentials that
    /// include a username are rejected.
    ///
    /// # Examples
    /// ```no_run
    /// # use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    /// # use cryptoki::session::UserType;
    /// # use cryptoki::types::{AuthPin, Credential};
    /// # fn example(pkcs11: Pkcs11, slot: cryptoki::slot::Slot) -> cryptoki::error::Result<()> {
    /// let so_pin = AuthPin::new("so-pin".into());
    /// let user_pin = AuthPin::new("user-pin".into());
    ///
    /// let session = pkcs11.open_rw_session(slot)?;
    /// session.login(UserType::So, &so_pin)?;
    /// session.init_pin(&user_pin)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Using a protected authentication path:
    /// ```no_run
    /// # use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    /// # use cryptoki::session::UserType;
    /// # use cryptoki::types::{AuthPin, Credential};
    /// # fn example(pkcs11: Pkcs11, slot: cryptoki::slot::Slot) -> cryptoki::error::Result<()> {
    /// // The token must advertise CKF_PROTECTED_AUTHENTICATION_PATH.
    /// let so_pin = AuthPin::new("so-pin".into());
    /// let session = pkcs11.open_rw_session(slot)?;
    /// session.login(UserType::So, &so_pin)?;
    /// session.init_pin(Credential::protected_authentication_path())?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Using a non-UTF8 PIN:
    /// ```no_run
    /// # use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    /// # use cryptoki::session::UserType;
    /// # use cryptoki::types::{AuthPin, Credential, RawAuthPin};
    /// # fn example(pkcs11: Pkcs11, slot: cryptoki::slot::Slot) -> cryptoki::error::Result<()> {
    /// let so_pin = AuthPin::new("so-pin".into());
    /// let raw_pin = RawAuthPin::from(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    ///
    /// let session = pkcs11.open_rw_session(slot)?;
    /// session.login(UserType::So, &so_pin)?;
    /// session.init_pin(&raw_pin)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn init_pin<'a, C>(&self, credential: C) -> Result<()>
    where
        C: Into<Credential<'a>>,
    {
        let credential = credential.into();
        if credential.username().is_some() {
            return Err(Error::UsernameNotExpected("init_pin"));
        }
        let (pin, pin_len) = credential.pin_ptr_len();

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_InitPIN)(
                self.handle(),
                pin,
                pin_len.try_into()?,
            ))
            .into_result(Function::InitPIN)
        }
    }

    /// Change the PIN of the currently logged in user, or of `CKU_USER` if no user
    /// is logged in.
    ///
    /// Credentials that include a username are rejected.
    ///
    /// # Examples
    /// ```no_run
    /// # use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    /// # use cryptoki::session::UserType;
    /// # use cryptoki::types::{AuthPin, Credential};
    /// # fn example(pkcs11: Pkcs11, slot: cryptoki::slot::Slot) -> cryptoki::error::Result<()> {
    /// let old_pin = AuthPin::new("old-pin".into());
    /// let new_pin = AuthPin::new("new-pin".into());
    ///
    /// let session = pkcs11.open_rw_session(slot)?;
    /// session.login(UserType::User, Credential::pin(&old_pin))?;
    /// session.set_pin(Credential::pin(&old_pin), Credential::pin(&new_pin))?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_pin<'a, C, D>(&self, old_credential: C, new_credential: D) -> Result<()>
    where
        C: Into<Credential<'a>>,
        D: Into<Credential<'a>>,
    {
        let old_credential = old_credential.into();
        let new_credential = new_credential.into();

        if old_credential.username().is_some() || new_credential.username().is_some() {
            return Err(Error::UsernameNotExpected("set_pin"));
        }

        let (old_pin, old_pin_len) = old_credential.pin_ptr_len();
        let (new_pin, new_pin_len) = new_credential.pin_ptr_len();

        let old_pin_len = cryptoki_sys::CK_ULONG::try_from(old_pin_len)?;
        let new_pin_len = cryptoki_sys::CK_ULONG::try_from(new_pin_len)?;

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_SetPIN)(
                self.handle(),
                old_pin,
                old_pin_len,
                new_pin,
                new_pin_len,
            ))
            .into_result(Function::SetPIN)
        }
    }
}
