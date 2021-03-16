// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Rust PKCS11 new abstraction
//!
//! The items in the new module only expose idiomatic and safe Rust types and functions to
//! interface with the PKCS11 API. All the PKCS11 items might not be implemented but everything
//! that is implemented is safe.
//!
//! The modules under `new` follow the structure of the PKCS11 document version 2.40 available [here](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html).

// This list comes from
// https://github.com/rust-unofficial/patterns/blob/master/anti_patterns/deny-warnings.md
#![deny(bad_style,
       const_err,
       dead_code,
       improper_ctypes,
       non_shorthand_field_patterns,
       no_mangle_generic_items,
       overflowing_literals,
       path_statements ,
       patterns_in_fns_without_body,
       private_in_public,
       unconditional_recursion,
       unused,
       unused_allocation,
       unused_comparisons,
       unused_parens,
       while_true,
       missing_debug_implementations,
       missing_copy_implementations,
       missing_docs,
       // Useful to cast to raw pointers
       //trivial_casts,
       trivial_numeric_casts,
       unused_extern_crates,
       unused_import_braces,
       unused_qualifications,
       unused_results)]

pub mod functions;
pub mod objects;
pub mod types;

use crate::types::function::{Rv, RvError};
use crate::types::session::{Session, UserType};
use crate::types::slot_token::Slot;
use derivative::Derivative;
use log::error;
use secrecy::{ExposeSecret, Secret, SecretVec};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::ffi::CString;
use std::fmt;
use std::mem;
use std::path::Path;
use std::sync::{Mutex, RwLock};

/// Directly get the PKCS #11 operation from the context structure and check for null pointers.
#[macro_export]
macro_rules! get_pkcs11 {
    ($pkcs11:expr, $func_name:ident) => {
        ($pkcs11
            .function_list
            .$func_name
            .ok_or(crate::Error::NullFunctionPointer)?)
    };
}

/// Main PKCS11 context. Should usually be unique per application.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Pkcs11 {
    // Even if this field is never read, it is needed for the pointers in function_list to remain
    // valid.
    #[derivative(Debug = "ignore")]
    _pkcs11_lib: cryptoki_sys::Pkcs11,
    function_list: cryptoki_sys::_CK_FUNCTION_LIST,
    // Handle of sessions currently logged in per slot. This is used for logging in and out.
    logged_sessions: Mutex<HashMap<Slot, HashSet<cryptoki_sys::CK_SESSION_HANDLE>>>,
    // Pin per slot, will be used for login. Ideally this should also be filtered by user type.
    #[derivative(Debug = "ignore")]
    pins: RwLock<HashMap<Slot, SecretVec<u8>>>,
}

impl Pkcs11 {
    /// Instantiate a new context from the path of a PKCS11 dynamic llibrary implementation.
    pub fn new<P>(filename: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        unsafe {
            let pkcs11_lib =
                cryptoki_sys::Pkcs11::new(filename.as_ref()).map_err(Error::LibraryLoading)?;
            let mut list = mem::MaybeUninit::uninit();

            Rv::from(pkcs11_lib.C_GetFunctionList(list.as_mut_ptr())).into_result()?;

            let list_ptr = *list.as_ptr();

            Ok(Pkcs11 {
                _pkcs11_lib: pkcs11_lib,
                function_list: *list_ptr,
                logged_sessions: Mutex::new(HashMap::new()),
                pins: RwLock::new(HashMap::new()),
            })
        }
    }

    /// Set the PIN used when logging in sessions.
    /// The pin set is the one that is going to be use with all user type specified when logging in.
    /// It needs to be changed before calling login with a different user type.
    pub fn set_pin(&self, slot: Slot, pin: &str) -> Result<()> {
        let _ = self
            .pins
            .write()
            .expect("Pins lock poisoned")
            .insert(slot, Secret::new(CString::new(pin)?.into_bytes()));
        Ok(())
    }

    /// Clear the pin store.
    /// Ignore if the pin was not set previously on the slot. Note that the pin will be cleared
    /// anyway on drop.
    pub fn clear_pin(&self, slot: Slot) {
        // The removed pin will be zeroized on drop as it is a SecretVec
        let _ = self.pins.write().expect("Pins lock poisoned").remove(&slot);
    }

    // Do not fail if the user is already logged in. It happens if another session on the same slot
    // has already called the log in operation. Record the login call and only log out when there
    // aren't anymore sessions requiring log in state.
    fn login(&self, session: &Session, user_type: UserType) -> Result<()> {
        let pins = self.pins.read().expect("Pins lock poisoned");
        let pin = pins
            .get(&session.slot())
            .ok_or(Error::PinNotSet)?
            .expose_secret();

        let mut logged_sessions = self
            .logged_sessions
            .lock()
            .expect("Logged sessions mutex poisoned!");

        match unsafe {
            Rv::from(get_pkcs11!(self, C_Login)(
                session.handle(),
                user_type.into(),
                pin.as_ptr() as *mut u8,
                pin.len().try_into()?,
            ))
        } {
            Rv::Ok | Rv::Error(RvError::UserAlreadyLoggedIn) => {
                if let Some(session_handles) = logged_sessions.get_mut(&session.slot()) {
                    // It might already been present in if this session already tried to log in.
                    let _ = session_handles.insert(session.handle());
                } else {
                    let mut new_set = HashSet::new();
                    let _ = new_set.insert(session.handle());
                    let _ = logged_sessions.insert(session.slot(), new_set);
                }
                Ok(())
            }
            Rv::Error(err) => Err(err.into()),
        }
    }

    fn logout(&self, session: &Session) -> Result<()> {
        let mut logged_sessions = self
            .logged_sessions
            .lock()
            .expect("Logged sessions mutex poisoned!");

        // A non-logged in session might call this method.

        if let Some(session_handles) = logged_sessions.get_mut(&session.slot()) {
            if session_handles.contains(&session.handle()) {
                if session_handles.len() == 1 {
                    // Only this session is logged in, we can logout.
                    unsafe {
                        Rv::from(get_pkcs11!(self, C_Logout)(session.handle())).into_result()?;
                    }
                }
                let _ = session_handles.remove(&session.handle());
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
/// Main error type
pub enum Error {
    /// Any error that happens during library loading of the PKCS#11 module is encompassed under
    /// this error. It is a direct forward of the underlying error from libloading.
    LibraryLoading(libloading::Error),

    /// All PKCS#11 functions that return non-zero translate to this error.
    Pkcs11(RvError),

    /// This error marks a feature that is not yet supported by the PKCS11 Rust abstraction layer.
    NotSupported,

    /// Error happening while converting types
    TryFromInt(std::num::TryFromIntError),

    /// Error when converting a slice to an array
    TryFromSlice(std::array::TryFromSliceError),

    /// Error with nul characters in Strings
    NulError(std::ffi::NulError),

    /// Calling a PKCS11 function that is a NULL function pointer.
    NullFunctionPointer,

    /// The value is not one of those expected.
    InvalidValue,

    /// The PIN was not set before logging in.
    PinNotSet,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::LibraryLoading(e) => write!(f, "libloading error ({})", e),
            Error::Pkcs11(e) => write!(f, "PKCS11 error: {}", e),
            Error::NotSupported => write!(f, "Feature not supported"),
            Error::TryFromInt(e) => write!(f, "Conversion between integers failed ({})", e),
            Error::TryFromSlice(e) => write!(f, "Error converting slice to array ({})", e),
            Error::NulError(e) => write!(f, "An interior nul byte was found ({})", e),
            Error::NullFunctionPointer => write!(f, "Calling a NULL function pointer"),
            Error::InvalidValue => write!(f, "The value is not one of the expected options"),
            Error::PinNotSet => write!(f, "Pin has not been set before trying to log in"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::LibraryLoading(e) => Some(e),
            Error::TryFromInt(e) => Some(e),
            Error::TryFromSlice(e) => Some(e),
            Error::NulError(e) => Some(e),
            Error::Pkcs11(_)
            | Error::NotSupported
            | Error::NullFunctionPointer
            | Error::PinNotSet
            | Error::InvalidValue => None,
        }
    }
}

impl From<libloading::Error> for Error {
    fn from(err: libloading::Error) -> Error {
        Error::LibraryLoading(err)
    }
}

impl From<std::num::TryFromIntError> for Error {
    fn from(err: std::num::TryFromIntError) -> Error {
        Error::TryFromInt(err)
    }
}

impl From<std::array::TryFromSliceError> for Error {
    fn from(err: std::array::TryFromSliceError) -> Error {
        Error::TryFromSlice(err)
    }
}

impl From<std::ffi::NulError> for Error {
    fn from(err: std::ffi::NulError) -> Error {
        Error::NulError(err)
    }
}

impl From<std::convert::Infallible> for Error {
    fn from(_err: std::convert::Infallible) -> Error {
        unreachable!()
    }
}

impl Drop for Pkcs11 {
    fn drop(&mut self) {
        if let Err(e) = self.finalize_private() {
            error!("Failed to finalize: {}", e);
        }
    }
}

/// Main Result type
pub type Result<T> = core::result::Result<T, Error>;
