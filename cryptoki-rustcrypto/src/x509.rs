// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use cryptoki::object::{Attribute, AttributeType, CertificateType, ObjectClass, ObjectHandle};
use thiserror::Error;
use x509_cert::{
    certificate::{CertificateInner, Profile},
    der::{Decode, Encode},
};

use crate::SessionLike;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Cryptoki error: {0}")]
    Cryptoki(#[from] cryptoki::error::Error),

    #[error("Missing attribute: {0}")]
    MissingAttribute(AttributeType),

    #[error(transparent)]
    Der(#[from] x509_cert::der::Error),

    #[error("No such certificate found")]
    MissingCert,
}

pub trait CertPkcs11 {
    fn pkcs11_store<S: SessionLike, T: Into<Vec<Attribute>>>(
        &self,
        session: &S,
        base_template: T,
    ) -> Result<ObjectHandle, Error>;

    fn pkcs11_load<S: SessionLike, T: Into<Vec<Attribute>>>(
        session: &S,
        template: T,
    ) -> Result<Self, Error>
    where
        Self: Sized;
}

impl<P> CertPkcs11 for CertificateInner<P>
where
    P: Profile,
{
    fn pkcs11_store<S: SessionLike, T: Into<Vec<Attribute>>>(
        &self,
        session: &S,
        base_template: T,
    ) -> Result<ObjectHandle, Error> {
        let mut template = base_template.into();
        template.push(Attribute::Class(ObjectClass::CERTIFICATE));
        template.push(Attribute::CertificateType(CertificateType::X_509));
        template.push(Attribute::Token(true));
        template.push(Attribute::Value(self.to_der()?));
        if !self.tbs_certificate.subject.is_empty() {
            template.push(Attribute::Subject(self.tbs_certificate.subject.to_der()?));
        }

        Ok(session.create_object(&template)?)
    }

    fn pkcs11_load<S: SessionLike, T: Into<Vec<Attribute>>>(
        session: &S,
        template: T,
    ) -> Result<Self, Error> {
        let mut template = template.into();
        template.push(Attribute::Class(ObjectClass::CERTIFICATE));
        template.push(Attribute::CertificateType(CertificateType::X_509));

        let certs = session.find_objects(&template)?;
        if let Some(cert) = certs.first() {
            let attributes = session.get_attributes(*cert, &[AttributeType::Value])?;

            let mut value = None;
            for attribute in attributes {
                match attribute {
                    Attribute::Value(v) if value.is_none() => {
                        value = Some(v);
                    }
                    _ => {}
                }
            }

            let value = value.ok_or(Error::MissingAttribute(AttributeType::Value))?;

            let cert = Self::from_der(&value)?;

            Ok(cert)
        } else {
            Err(Error::MissingCert)
        }
    }
}
