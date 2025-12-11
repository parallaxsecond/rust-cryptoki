// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Session types

use crate::context::Pkcs11;

use crate::error::Result;
use cryptoki_sys::*;
use std::fmt::Formatter;
use std::marker::PhantomData;
use std::sync::Arc;

mod decryption;
mod digesting;
mod encapsulation;
mod encryption;
mod key_management;
mod message_decryption;
mod message_encryption;
mod object_management;
mod random;
mod session_info;
mod session_management;
mod signing_macing;
mod slot_token_management;
mod validation;

pub use object_management::ObjectHandleIterator;
pub use session_info::{SessionInfo, SessionState};
pub use validation::ValidationFlagsType;

/// A wrapper type that contains a reference or an owned value.
///
/// This wrapper type implements clone by wrapping the owned value in
/// an `Arc`.
#[derive(Clone)]
pub enum MaybeOwned<'a, T>
where
    T: ?Sized,
{
    /// A reference to the thing.
    Ref(&'a T),
    /// An owned value.
    Arc(Arc<T>),
}

impl<'a, T> AsRef<T> for MaybeOwned<'a, T>
where
    T: ?Sized,
{
    fn as_ref(&self) -> &T {
        match self {
            MaybeOwned::Ref(thing) => thing,
            MaybeOwned::Arc(ref thing) => thing,
        }
    }
}

impl<'a, T> std::fmt::Debug for MaybeOwned<'a, T>
where
    T: std::fmt::Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.as_ref().fmt(f)
    }
}

impl<T> From<T> for MaybeOwned<'static, T> {
    fn from(thing: T) -> MaybeOwned<'static, T> {
        MaybeOwned::Arc(Arc::new(thing))
    }
}

impl<T> From<Arc<T>> for MaybeOwned<'static, T> {
    fn from(thing: Arc<T>) -> MaybeOwned<'static, T> {
        MaybeOwned::Arc(thing)
    }
}

impl<'a, T> From<&'a T> for MaybeOwned<'a, T> {
    fn from(thing: &'a T) -> MaybeOwned<'a, T> {
        MaybeOwned::Ref(thing)
    }
}

/// Type that identifies a session
///
/// It will automatically get closed (and logout) on drop.
/// Session does not implement Sync to prevent the same Session instance to be used from multiple
/// threads. A Session needs to be created in its own thread or to be passed by ownership to
/// another thread.
#[derive(Debug)]
pub struct Session<'a> {
    handle: CK_SESSION_HANDLE,
    client: MaybeOwned<'a, Pkcs11>,
    // This is not used but to prevent Session to automatically implement Send and Sync
    _guard: PhantomData<*mut u32>,
}

impl<'a> std::fmt::Display for Session<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.handle)
    }
}

impl<'a> std::fmt::LowerHex for Session<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:08x}", self.handle)
    }
}

impl<'a> std::fmt::UpperHex for Session<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:08X}", self.handle)
    }
}

impl<'a> Session<'a> {
    pub(crate) fn new(
        handle: CK_SESSION_HANDLE,
        client: impl Into<MaybeOwned<'a, Pkcs11>>,
    ) -> Self {
        Session {
            handle,
            client: client.into(),
            _guard: PhantomData,
        }
    }
}

impl<'a> Session<'a> {
    /// Close a session
    /// This will be called on drop as well.
    pub fn close(self) -> Result<()> {
        self.close_inner()
    }

    /// Get the raw handle of the session.
    pub fn handle(&self) -> CK_SESSION_HANDLE {
        self.handle
    }

    pub(crate) fn client(&self) -> &Pkcs11 {
        match self.client {
            MaybeOwned::Ref(pkcs11) => pkcs11,
            MaybeOwned::Arc(ref pkcs11) => pkcs11,
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
    /// Vendor extension
    VendorExtension(u32),
}

impl From<UserType> for CK_USER_TYPE {
    // Mask lint for n.into() on 32-bit systems.
    #![allow(clippy::useless_conversion)]
    fn from(user_type: UserType) -> CK_USER_TYPE {
        match user_type {
            UserType::So => CKU_SO,
            UserType::User => CKU_USER,
            UserType::ContextSpecific => CKU_CONTEXT_SPECIFIC,
            UserType::VendorExtension(n) => n.into(),
        }
    }
}
