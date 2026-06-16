// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Session management functions

use crate::context::Function;
use crate::error::{Error, Result, Rv, RvError};
use crate::session::{CloseOnDrop, Session, SessionInfo, UserType};
use crate::types::{Credential, RawAuthPin};

#[cfg(doc)]
use cryptoki_sys::CKF_PROTECTED_AUTHENTICATION_PATH;
use cryptoki_sys::CK_SESSION_INFO;
use log::error;
use std::convert::{TryFrom, TryInto};

impl Drop for Session {
    fn drop(&mut self) {
        if self.close_on_drop == CloseOnDrop::DoNotClose || self.closed.get() {
            return;
        }

        match self.close_inner() {
            Err(Error::Pkcs11(RvError::SessionClosed, Function::CloseSession)) => (), // the session has already been closed: ignore.
            Ok(()) => (),
            Err(err) => {
                error!("Failed to close session: {err}");
            }
        }
    }
}

impl Session {
    /// Log a session in.
    ///
    /// # Arguments
    ///
    /// * `user_type` - The type of user to log in as
    /// * `credential` - The credential to use
    ///
    /// `user_type` can be one of the variants of the [`UserType`] enum.
    /// `credential` can be:
    /// - A reference to an [`crate::types::AuthPin`] (for UTF-8 PINs)
    /// - A reference to a [`crate::types::RawAuthPin`] (for non-UTF-8 PINs)
    /// - [`Credential::ProtectedAuthenticationPath`] to use the token's
    ///   protected authentication path (e.g. a pinpad)
    /// - A [`Credential`] constructed with a username and pin (UTF-8 or non-UTF-8) [`Credential::PinWithUser`] or
    ///   [`Credential::RawPinWithUser`], for use with V3.0 `C_LoginUser`
    /// - `None::<&AuthPin>` or `None::<&RawAuthPin>` as a shorthand for
    ///   [`Credential::ProtectedAuthenticationPath`]
    /// - A `Credential` constructed with a username
    ///   [`Credential::ProtectedAuthenticationPathWithUser`], for use with V3.0 `C_LoginUser`
    ///
    /// _NOTE: By passing [`Credential::ProtectedAuthenticationPath`] or [`Credential::ProtectedAuthenticationPathWithUser`], you must ensure that the
    /// [CKF_PROTECTED_AUTHENTICATION_PATH] flag is set in the `TokenFlags`._
    ///
    /// # Examples
    ///
    /// Typical uses:
    /// ```no_run
    /// # use cryptoki::session::UserType;
    /// # use cryptoki::types::{AuthPin, Credential};
    /// # fn example(session: &cryptoki::session::Session) -> cryptoki::error::Result<()> {
    /// // The new way, using credential:
    ///
    /// session.login(UserType::User, Credential::pin(&AuthPin::new("user-pin".into())))?;
    ///
    /// // the simplest case: &AuthPin
    /// let pin = AuthPin::new("user-pin".into());
    /// session.login(UserType::User, &pin)?;
    /// //
    /// // Using the Credential type directly
    /// session.login(UserType::User, Credential::pin(&pin))?;
    /// //
    /// // Using None to indicate protected authentication path
    /// session.login(UserType::User, None::<&AuthPin>)?;
    /// //
    /// // The same using the Credential type directly
    /// session.login(UserType::User, Credential::protected_authentication_path())?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Classic UTF-8 password:
    /// ```no_run
    /// # use cryptoki::session::UserType;
    /// # use cryptoki::types::{AuthPin, Credential};
    /// # fn example(session: &cryptoki::session::Session) -> cryptoki::error::Result<()> {
    /// let pin = AuthPin::new("user-pin".into());
    /// session.login(UserType::User, Credential::pin(&pin))?;
    /// let credential = Credential::pin(&pin);
    /// session.login(UserType::User, credential)?; // explicit Credential variable
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// UTF-8 password + username:
    /// ```no_run
    /// # use cryptoki::session::UserType;
    /// # use cryptoki::types::{AuthPin, Credential};
    /// # fn example(session: &cryptoki::session::Session) -> cryptoki::error::Result<()> {
    /// let pin = AuthPin::new("user-pin".into());
    /// session.login(UserType::User, Credential::pin_with_user(&pin, "alice"))?;
    /// let credential = Credential::pin_with_user(&pin, "alice");
    /// session.login(UserType::User, credential)?; // explicit Credential variable
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Non-UTF8 PIN (invalid UTF-8 sequence):
    /// ```no_run
    /// # use cryptoki::session::UserType;
    /// # use cryptoki::types::{Credential, RawAuthPin};
    /// # fn example(session: &cryptoki::session::Session) -> cryptoki::error::Result<()> {
    /// let raw_pin = RawAuthPin::from(vec![0xFF, 0xFE, 0xFD]);
    /// session.login(UserType::User, Credential::raw_pin(&raw_pin))?;
    /// let credential = Credential::raw_pin(&raw_pin);
    /// session.login(UserType::User, credential)?; // explicit Credential variable
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Non-UTF8 PIN + username:
    /// ```no_run
    /// # use cryptoki::session::UserType;
    /// # use cryptoki::types::{Credential, RawAuthPin};
    /// # fn example(session: &cryptoki::session::Session) -> cryptoki::error::Result<()> {
    /// let raw_pin = RawAuthPin::from(vec![0xFF, 0xFE, 0xFD]);
    /// session.login(UserType::User, Credential::raw_pin_with_user(&raw_pin, "alice"))?;
    /// let credential = Credential::raw_pin_with_user(&raw_pin, "alice");
    /// session.login(UserType::User, credential)?; // explicit Credential variable
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Protected authentication path:
    /// ```no_run
    /// # use cryptoki::session::UserType;
    /// # use cryptoki::types::Credential;
    /// # fn example(session: &cryptoki::session::Session) -> cryptoki::error::Result<()> {
    /// // The token must advertise CKF_PROTECTED_AUTHENTICATION_PATH.
    /// session.login(UserType::User, Credential::protected_authentication_path())?;
    /// let credential = Credential::protected_authentication_path();
    /// session.login(UserType::User, credential)?; // explicit Credential variable
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Protected authentication path + username:
    /// ```no_run
    /// # use cryptoki::session::UserType;
    /// # use cryptoki::types::Credential;
    /// # fn example(session: &cryptoki::session::Session) -> cryptoki::error::Result<()> {
    /// // The token must advertise CKF_PROTECTED_AUTHENTICATION_PATH.
    /// session.login(
    ///     UserType::User,
    ///     Credential::protected_authentication_path_with_user("alice"),
    /// )?;
    /// let credential = Credential::protected_authentication_path_with_user("alice");
    /// session.login(UserType::User, credential)?; // explicit Credential variable
    /// # Ok(())
    /// # }
    /// ```
    pub fn login<'a, C>(&self, user_type: UserType, credential: C) -> Result<()>
    where
        C: Into<Credential<'a>>,
    {
        let credential = credential.into();
        let (pin, pin_len) = credential.pin_ptr_len();

        if let Some(username) = credential.username() {
            let pin_len: cryptoki_sys::CK_ULONG = pin_len.try_into()?;
            let username_len: cryptoki_sys::CK_ULONG = username.len().try_into()?;
            unsafe {
                Rv::from(get_pkcs11!(self.client(), C_LoginUser)(
                    self.handle(),
                    user_type.into(),
                    pin,
                    pin_len,
                    username.as_ptr() as *mut u8,
                    username_len,
                ))
                .into_result(Function::LoginUser)
            }
        } else {
            unsafe {
                Rv::from(get_pkcs11!(self.client(), C_Login)(
                    self.handle(),
                    user_type.into(),
                    pin,
                    pin_len.try_into()?,
                ))
                .into_result(Function::Login)
            }
        }
    }

    /// Logs a session in using a raw PIN (non UTF-8 bytes).
    ///
    /// This is a compatibility helper that forwards to [`Session::login`].
    #[deprecated(note = "Use Session::login(UserType, Credential::raw_pin(&pin)) instead")]
    pub fn login_with_raw(&self, user_type: UserType, pin: &RawAuthPin) -> Result<()> {
        self.login(user_type, Credential::raw_pin(pin))
    }

    /// Log a session out
    pub fn logout(&self) -> Result<()> {
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_Logout)(self.handle()))
                .into_result(Function::Logout)
        }
    }

    /// Returns the information about a session
    pub fn get_session_info(&self) -> Result<SessionInfo> {
        let mut session_info = CK_SESSION_INFO::default();
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_GetSessionInfo)(
                self.handle(),
                &mut session_info,
            ))
            .into_result(Function::GetSessionInfo)?;
            SessionInfo::try_from(session_info)
        }
    }

    // Helper function to be able to close a session only taking a reference.
    // This is used in the Drop trait function which only takes a reference as input.
    pub(super) fn close_inner(&self) -> Result<()> {
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_CloseSession)(self.handle()))
                .into_result(Function::CloseSession)?;
        }
        self.closed.set(true);
        Ok(())
    }
}
