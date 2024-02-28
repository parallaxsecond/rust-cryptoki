// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use cryptoki::{
    error::Result,
    mechanism::Mechanism,
    object::{Attribute, AttributeType, ObjectHandle},
    session::{Session, UserType},
    types::AuthPin,
};

pub use cryptoki;

pub mod ecdsa;
pub mod rng;
pub mod rsa;
pub mod x509;

pub trait SessionLike {
    fn create_object(&self, template: &[Attribute]) -> Result<ObjectHandle>;
    fn find_objects(&self, template: &[Attribute]) -> Result<Vec<ObjectHandle>>;
    fn get_attributes(
        &self,
        object: ObjectHandle,
        attributes: &[AttributeType],
    ) -> Result<Vec<Attribute>>;
    fn update_attributes(&self, object: ObjectHandle, template: &[Attribute]) -> Result<()>;
    fn sign(&self, mechanism: &Mechanism, key: ObjectHandle, data: &[u8]) -> Result<Vec<u8>>;
    fn generate_random_slice(&self, random_data: &mut [u8]) -> Result<()>;
    fn wrap_key(
        &self,
        mechanism: &Mechanism,
        wrapping_key: ObjectHandle,
        key: ObjectHandle,
    ) -> Result<Vec<u8>>;
    fn login(&self, user_type: UserType, pin: Option<&AuthPin>) -> Result<()>;
    fn logout(&self) -> Result<()>;
}

impl SessionLike for Session {
    fn create_object(&self, template: &[Attribute]) -> Result<ObjectHandle> {
        Session::create_object(self, template)
    }
    fn find_objects(&self, template: &[Attribute]) -> Result<Vec<ObjectHandle>> {
        Session::find_objects(self, template)
    }
    fn get_attributes(
        &self,
        object: ObjectHandle,
        attributes: &[AttributeType],
    ) -> Result<Vec<Attribute>> {
        Session::get_attributes(self, object, attributes)
    }
    fn update_attributes(&self, object: ObjectHandle, template: &[Attribute]) -> Result<()> {
        Session::update_attributes(self, object, template)
    }

    fn sign(&self, mechanism: &Mechanism, key: ObjectHandle, data: &[u8]) -> Result<Vec<u8>> {
        Session::sign(self, mechanism, key, data)
    }
    fn generate_random_slice(&self, random_data: &mut [u8]) -> Result<()> {
        Session::generate_random_slice(self, random_data)
    }
    fn wrap_key(
        &self,
        mechanism: &Mechanism,
        wrapping_key: ObjectHandle,
        key: ObjectHandle,
    ) -> Result<Vec<u8>> {
        Session::wrap_key(self, mechanism, wrapping_key, key)
    }
    fn login(&self, user_type: UserType, pin: Option<&AuthPin>) -> Result<()> {
        Session::login(self, user_type, pin)
    }
    fn logout(&self) -> Result<()> {
        Session::logout(self)
    }
}

impl<'s> SessionLike for &'s Session {
    fn create_object(&self, template: &[Attribute]) -> Result<ObjectHandle> {
        Session::create_object(self, template)
    }
    fn find_objects(&self, template: &[Attribute]) -> Result<Vec<ObjectHandle>> {
        Session::find_objects(self, template)
    }
    fn get_attributes(
        &self,
        object: ObjectHandle,
        attributes: &[AttributeType],
    ) -> Result<Vec<Attribute>> {
        Session::get_attributes(self, object, attributes)
    }
    fn update_attributes(&self, object: ObjectHandle, template: &[Attribute]) -> Result<()> {
        Session::update_attributes(self, object, template)
    }

    fn sign(&self, mechanism: &Mechanism, key: ObjectHandle, data: &[u8]) -> Result<Vec<u8>> {
        Session::sign(self, mechanism, key, data)
    }
    fn generate_random_slice(&self, random_data: &mut [u8]) -> Result<()> {
        Session::generate_random_slice(self, random_data)
    }
    fn wrap_key(
        &self,
        mechanism: &Mechanism,
        wrapping_key: ObjectHandle,
        key: ObjectHandle,
    ) -> Result<Vec<u8>> {
        Session::wrap_key(self, mechanism, wrapping_key, key)
    }
    fn login(&self, user_type: UserType, pin: Option<&AuthPin>) -> Result<()> {
        Session::login(self, user_type, pin)
    }
    fn logout(&self) -> Result<()> {
        Session::logout(self)
    }
}

pub trait CryptokiImport {
    fn put_key<S: SessionLike>(
        &self,
        session: &S,
        template: impl Into<Vec<Attribute>>,
    ) -> Result<ObjectHandle>;
}
