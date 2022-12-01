// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Session types

use crate::context::Pkcs11;
use crate::error::Result;
use crate::mechanism::Mechanism;
use crate::object::{Attribute, AttributeInfo, AttributeType, ObjectHandle};

use cryptoki_sys::*;
use log::error;
use std::collections::HashMap;
use std::fmt::Formatter;
use std::marker::PhantomData;

mod decryption;
mod encryption;
mod key_management;
mod object_management;
mod random;
mod session_info;
mod session_management;
mod signing_macing;
mod slot_token_management;

pub use object_management::FindObjects;
pub use session_info::{SessionInfo, SessionState};

/// Type that identifies a session
///
/// It will automatically get closed (and logout) on drop.
/// Session does not implement Sync to prevent the same Session instance to be used from multiple
/// threads. A Session needs to be created in its own thread or to be passed by ownership to
/// another thread.
#[derive(Debug)]
pub struct Session {
    handle: CK_SESSION_HANDLE,
    client: Pkcs11,
    // This is not used but to prevent Session to automatically implement Send and Sync
    _guard: PhantomData<*mut u32>,
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
    pub(crate) fn new(handle: CK_SESSION_HANDLE, client: Pkcs11) -> Self {
        Session {
            handle,
            client,
            _guard: PhantomData,
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

    /// Logs a session in using a slice of raw bytes as a PIN. Some dongle drivers allow
    /// non UTF-8 characters in the PIN and as a result, we aren't guaranteed that we can
    /// pass in a UTF-8 string to login. Therefore, it's useful to be able to pass in raw bytes
    /// rather than convert a UTF-8 string to bytes.
    ///
    /// # Arguments
    ///
    /// * `user_type` - The type of user to log in as
    /// * `pin` - The PIN to use
    ///
    /// _NOTE: By passing `None` into `login`, you must ensure that the
    /// [CKF_PROTECTED_AUTHENTICATION_PATH] flag is set in the `TokenFlags`._
    pub fn login_with_raw(&self, user_type: UserType, pin: &[u8]) -> Result<()> {
        session_management::login_with_raw(self, user_type, pin)
    }

    /// Log a session out
    pub fn logout(&self) -> Result<()> {
        session_management::logout(self)
    }

    /// Returns the information about a session
    pub fn get_session_info(&self) -> Result<SessionInfo> {
        session_management::get_session_info(self)
    }

    /// Search for token and session objects matching a template
    pub fn find_objects(&mut self, template: &[Attribute]) -> Result<Vec<ObjectHandle>> {
        object_management::find_objects(self, template)
    }

    /// Initiate a search for token and session objects matching a template
    ///
    /// # Arguments
    ///
    /// * `template` - The list of attributes to match
    ///
    /// # Returns
    ///
    /// This function returns a [FindObjects], which represents an ongoing search.  The
    /// lifetime of this search is tied to a mutable borrow of the session, so that there
    /// may only be one search per session at once.  When the [FindObjects] is dropped,
    /// the search is ended.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use cryptoki::error::Result;
    /// use cryptoki::object::{Attribute, AttributeType};
    /// use cryptoki::session::Session;
    ///
    /// const BATCH_SIZE: usize = 10;
    ///
    /// fn print_object_labels(session: &mut Session, template: &[Attribute]) -> Result<()> {
    ///     // Initiate the search.
    ///     let mut search = session.find_objects_init(template)?;
    ///
    ///     // Iterate over batches of results, while find_next returns a non-empty batch
    ///     while let ref objects @ [_, ..] = search.find_next(BATCH_SIZE)?[..] {
    ///         // Iterate over objects in the batch.
    ///         for &object in objects {
    ///             // Look up the label for the object.  We can't use `session` directly here,
    ///             // since it's mutably borrowed by search.  Instead, use `search.session()`.
    ///             let attrs = search.session().get_attributes(object, &[AttributeType::Label])?;
    ///             if let Some(Attribute::Label(label)) = attrs.get(0) {
    ///                 println!("Found object: {}", String::from_utf8_lossy(&label));
    ///             }
    ///         }
    ///     }
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn find_objects_init<'a>(&'a mut self, template: &[Attribute]) -> Result<FindObjects<'a>> {
        object_management::find_objects_init(self, template)
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
    /// use std::collections::HashMap;
    /// use std::env;
    ///
    /// let mut pkcs11 = Pkcs11::new(
    ///         env::var("PKCS11_SOFTHSM2_MODULE")
    ///             .unwrap_or_else(|_| "/usr/local/lib/softhsm/libsofthsm2.so".to_string()),
    ///     )
    ///     .unwrap();
    ///
    /// pkcs11.initialize(CInitializeArgs::OsThreads).unwrap();
    /// let slot = pkcs11.get_slots_with_token().unwrap().remove(0);
    ///
    /// let mut session = pkcs11.open_ro_session(slot).unwrap();
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
        &self.client
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
