// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Session types

use crate::context::Pkcs11;
use crate::error::Result;
use crate::mechanism::Mechanism;
use crate::object::{Attribute, AttributeInfo, AttributeType, ObjectHandle};
use crate::slot::Slot;
use crate::types::Ulong;

use cryptoki_sys::*;
use log::error;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt::Formatter;
use std::ops::Deref;
use std::sync::Arc;

mod decryption;
mod encryption;
mod flags;
mod key_management;
mod object_management;
mod random;
mod session_management;
mod signing_macing;
mod slot_token_management;

pub use flags::*;

/// Type that identifies a session
///
/// It will automatically get closed (and logout) on drop.
/// Session does not implement Sync to prevent the same Session instance to be used from multiple
/// threads. A Session needs to be created in its own thread or to be passed by ownership to
/// another thread.
#[derive(Debug)]
pub struct Session {
    handle: CK_SESSION_HANDLE,
    client: Arc<Pkcs11>,
    // This is not used but to prevent Session to automatically implement Send and Sync
    _guard: *mut u32,
}

impl std::fmt::Display for Session {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.handle)
    }
}

impl std::fmt::LowerHex for Session {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:08x}", self.handle)
    }
}

impl std::fmt::UpperHex for Session {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:08X}", self.handle)
    }
}

// Session does not implement Sync to prevent the same Session instance to be used from multiple
// threads.
unsafe impl Send for Session {}

impl Session {
    pub(crate) fn new(handle: CK_SESSION_HANDLE, client: Arc<Pkcs11>) -> Self {
        Session {
            handle,
            client,
            _guard: std::ptr::null_mut::<u32>(),
        }
    }
}

impl Session {
    /// Initialize the normal user's pin for a token
    pub fn init_pin(&self, pin: &str) -> Result<()> {
        slot_token_management::init_pin(self, pin)
    }

    /// Changes the PIN of either the currently logged in user or of the `CKU_USER` if no user is
    /// logged in.
    pub fn set_pin(&self, old_pin: &str, new_pin: &str) -> Result<()> {
        slot_token_management::set_pin(self, old_pin, new_pin)
    }

    /// Close a session
    /// This will be called on drop as well.
    pub fn close(self) {}

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
        session_management::login(self, user_type, pin)
    }

    /// Log a session out
    pub fn logout(&self) -> Result<()> {
        session_management::logout(self)
    }

    /// Returns the information about a session
    pub fn get_session_info(&self) -> Result<SessionInfo> {
        session_management::get_session_info(self)
    }

    /// Search for session objects matching a template
    pub fn find_objects(&self, template: &[Attribute]) -> Result<Vec<ObjectHandle>> {
        object_management::find_objects(self, template)
    }

    /// Create a new object
    pub fn create_object(&self, template: &[Attribute]) -> Result<ObjectHandle> {
        object_management::create_object(self, template)
    }

    /// Destroy an object
    pub fn destroy_object(&self, object: ObjectHandle) -> Result<()> {
        object_management::destroy_object(self, object)
    }

    /// Get the attribute info of an object: if the attribute is present and its size.
    ///
    /// # Arguments
    ///
    /// * `object` - The [ObjectHandle] used to reference the object
    /// * `attributes` - The list of attributes to get the information of
    ///
    /// # Returns
    ///
    /// This function will return a Vector of [AttributeInfo] enums that will either contain
    /// the size of the requested attribute, [AttributeInfo::TypeInvalid] if the attribute is not a
    /// valid type for the object, or [AttributeInfo::Sensitive] if the requested attribute is
    /// sensitive and will not be returned to the user.
    ///
    /// The list of returned attributes is 1-to-1 matched with the provided vector of attribute
    /// types.  If you wish, you may create a hash table simply by:
    ///
    /// ```no_run
    /// use cryptoki::context::Pkcs11;
    /// use cryptoki::context::CInitializeArgs;
    /// use cryptoki::object::AttributeType;
    /// use cryptoki::session::UserType;
    /// use cryptoki::session::SessionFlags;
    /// use std::collections::HashMap;
    /// use std::env;
    ///
    /// let pkcs11 = Pkcs11::new(
    ///         env::var("PKCS11_SOFTHSM2_MODULE")
    ///             .unwrap_or_else(|_| "/usr/local/lib/softhsm/libsofthsm2.so".to_string()),
    ///     )
    ///     .unwrap();
    ///
    /// pkcs11.initialize(CInitializeArgs::OsThreads).unwrap();
    /// let slot = pkcs11.get_slots_with_token().unwrap().remove(0);
    /// let mut flags = SessionFlags::new();
    /// let _ = flags.set_rw_session(true).set_serial_session(true);
    ///
    /// let session = pkcs11.open_session_no_callback(slot, flags).unwrap();
    /// session.login(UserType::User, Some("fedcba"));
    ///
    /// let empty_attrib= vec![];
    /// if let Some(object) = session.find_objects(&empty_attrib).unwrap().get(0) {
    ///     let attribute_types = vec![
    ///         AttributeType::Token,
    ///         AttributeType::Private,
    ///         AttributeType::Modulus,
    ///         AttributeType::KeyType,
    ///         AttributeType::Verify,];
    ///
    ///     let attribute_info = session.get_attribute_info(*object, &attribute_types).unwrap();
    ///
    ///     let hash = attribute_types
    ///         .iter()
    ///         .zip(attribute_info.iter())
    ///         .collect::<HashMap<_, _>>();
    /// }
    /// ```
    ///
    /// Alternatively, you can call [Session::get_attribute_info_map], found below.
    pub fn get_attribute_info(
        &self,
        object: ObjectHandle,
        attributes: &[AttributeType],
    ) -> Result<Vec<AttributeInfo>> {
        object_management::get_attribute_info(self, object, attributes)
    }

    /// Get the attribute info of an object: if the attribute is present and its size.
    ///
    /// # Arguments
    ///
    /// * `object` - The [ObjectHandle] used to reference the object
    /// * `attributes` - The list of attributes to get the information of
    ///
    /// # Returns
    ///
    /// This function will return a HashMap of [AttributeType] and [AttributeInfo] enums that will
    /// either contain the size of the requested attribute, [AttributeInfo::TypeInvalid] if the
    /// attribute is not a valid type for the object, or [AttributeInfo::Sensitive] if the requested
    /// attribute is sensitive and will not be returned to the user.
    pub fn get_attribute_info_map(
        &self,
        object: ObjectHandle,
        attributes: Vec<AttributeType>,
    ) -> Result<HashMap<AttributeType, AttributeInfo>> {
        object_management::get_attribute_info_map(self, object, attributes)
    }

    /// Get the attributes values of an object.
    /// Ignore the unavailable one. One has to call the get_attribute_info method to check which
    /// ones are unavailable.
    pub fn get_attributes(
        &self,
        object: ObjectHandle,
        attributes: &[AttributeType],
    ) -> Result<Vec<Attribute>> {
        object_management::get_attributes(self, object, attributes)
    }

    /// Single-part encryption operation
    pub fn encrypt(
        &self,
        mechanism: &Mechanism,
        key: ObjectHandle,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        encryption::encrypt(self, mechanism, key, data)
    }

    /// Single-part decryption operation
    pub fn decrypt(
        &self,
        mechanism: &Mechanism,
        key: ObjectHandle,
        encrypted_data: &[u8],
    ) -> Result<Vec<u8>> {
        decryption::decrypt(self, mechanism, key, encrypted_data)
    }

    /// Sign data in single-part
    pub fn sign(&self, mechanism: &Mechanism, key: ObjectHandle, data: &[u8]) -> Result<Vec<u8>> {
        signing_macing::sign(self, mechanism, key, data)
    }

    /// Verify data in single-part
    pub fn verify(
        &self,
        mechanism: &Mechanism,
        key: ObjectHandle,
        data: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        signing_macing::verify(self, mechanism, key, data, signature)
    }

    /// Generate a secret key
    pub fn generate_key(
        &self,
        mechanism: &Mechanism,
        template: &[Attribute],
    ) -> Result<ObjectHandle> {
        key_management::generate_key(self, mechanism, template)
    }

    /// Generate a public/private key pair
    pub fn generate_key_pair(
        &self,
        mechanism: &Mechanism,
        pub_key_template: &[Attribute],
        priv_key_template: &[Attribute],
    ) -> Result<(ObjectHandle, ObjectHandle)> {
        key_management::generate_key_pair(self, mechanism, pub_key_template, priv_key_template)
    }

    /// Derives a key from a base key
    pub fn derive_key(
        &self,
        mechanism: &Mechanism,
        base_key: ObjectHandle,
        template: &[Attribute],
    ) -> Result<ObjectHandle> {
        key_management::derive_key(self, mechanism, base_key, template)
    }

    /// Wrap key
    pub fn wrap_key(
        &self,
        mechanism: &Mechanism,
        wrapping_key: ObjectHandle,
        key: ObjectHandle,
    ) -> Result<Vec<u8>> {
        key_management::wrap_key(self, mechanism, wrapping_key, key)
    }

    /// Unwrap previously wrapped key
    pub fn unwrap_key(
        &self,
        mechanism: &Mechanism,
        unwrapping_key: ObjectHandle,
        wrapped_key: &[u8],
        template: &[Attribute],
    ) -> Result<ObjectHandle> {
        key_management::unwrap_key(self, mechanism, unwrapping_key, wrapped_key, template)
    }

    /// Generates a random number and sticks it in a slice
    ///
    /// # Arguments
    ///
    /// * `random_slice` - The slice to stick the random data into.  The length of the slice represents
    /// the number of bytes to obtain from the RBG
    pub fn generate_random_slice(&self, random_data: &mut [u8]) -> Result<()> {
        random::generate_random_slice(self, random_data)
    }

    /// Generates random data and returns it as a Vec<u8>.  The length of the returned Vector will
    /// be the amount of random requested, which is `random_len`.
    pub fn generate_random_vec(&self, random_len: u32) -> Result<Vec<u8>> {
        random::generate_random_vec(self, random_len)
    }

    /// Seeds the RNG
    pub fn seed_random(&self, seed: &[u8]) -> Result<()> {
        random::seed_random(self, seed)
    }

    pub(crate) fn handle(&self) -> CK_SESSION_HANDLE {
        self.handle
    }

    pub(crate) fn client(&self) -> &Pkcs11 {
        &*self.client
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Err(e) = session_management::close_private(self) {
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

/// Represents the state of a session
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SessionState {
    val: CK_STATE,
}

impl SessionState {
    /// Read-only public session
    pub const RO_PUBLIC_SESSION: SessionState = SessionState {
        val: CKS_RO_PUBLIC_SESSION,
    };

    /// Read-only user access
    pub const RO_USER_FUNCTIONS: SessionState = SessionState {
        val: CKS_RO_USER_FUNCTIONS,
    };

    /// Read/write public session
    pub const RW_PUBLIC_SESSION: SessionState = SessionState {
        val: CKS_RW_PUBLIC_SESSION,
    };

    /// Read/write user access
    pub const RW_USER_FUNCTIONS: SessionState = SessionState {
        val: CKS_RW_USER_FUNCTIONS,
    };

    /// Read/write SO access
    pub const RW_SO_FUNCTIONS: SessionState = SessionState {
        val: CKS_RW_SO_FUNCTIONS,
    };

    /// Stringifies the value of a [CK_STATE]
    pub(crate) fn stringify(state: CK_STATE) -> &'static str {
        match state {
            CKS_RO_PUBLIC_SESSION => stringify!(CKS_RO_PUBLIC_SESSION),
            CKS_RO_USER_FUNCTIONS => stringify!(CKS_RO_USER_FUNCTIONS),
            CKS_RW_PUBLIC_SESSION => stringify!(CKS_RW_PUBLIC_SESSION),
            CKS_RW_USER_FUNCTIONS => stringify!(CKS_RW_USER_FUNCTIONS),
            CKS_RW_SO_FUNCTIONS => stringify!(CKS_RW_SO_FUNCTIONS),
            _ => "Unknown state value",
        }
    }
}

impl Deref for SessionState {
    type Target = CK_STATE;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

impl From<SessionState> for CK_STATE {
    fn from(session_state: SessionState) -> Self {
        *session_state
    }
}

impl From<CK_STATE> for SessionState {
    fn from(val: CK_STATE) -> Self {
        Self { val }
    }
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", SessionState::stringify(self.val))
    }
}

/// Type identifying the session information
#[derive(Copy, Clone, Debug)]
pub struct SessionInfo {
    val: CK_SESSION_INFO,
}

impl SessionInfo {
    pub(crate) fn new(val: CK_SESSION_INFO) -> Self {
        Self { val }
    }

    /// Returns an error code defined by the cryptographic device
    pub fn device_error(&self) -> Ulong {
        self.val.ulDeviceError.into()
    }

    /// Returns the flags for this session
    pub fn flags(&self) -> SessionFlags {
        self.val.flags.into()
    }

    /// Returns the state of the session
    pub fn session_state(&self) -> SessionState {
        self.val.state.into()
    }

    /// Returns the slot the session is on
    pub fn slot_id(&self) -> Slot {
        // The unwrap should not fail as `slotID` is a `CK_SLOT_ID ` which is the same type as
        // `slot_id` within the `Slot` structure
        self.val.slotID.try_into().unwrap()
    }
}
