// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use cryptoki::{
    mechanism::{
        rsa::{PkcsMgfType, PkcsPssParams},
        Mechanism, MechanismType,
    },
    object::{Attribute, AttributeType, KeyType, ObjectClass},
};
use der::oid::AssociatedOid;
use rsa::{BigUint, RsaPublicKey};
use signature::digest::Digest;
use std::convert::TryInto;
use thiserror::Error;

use crate::SessionLike;

pub mod pkcs1v15;
pub mod pss;

pub fn read_key<S: SessionLike>(
    session: &S,
    template: impl Into<Vec<Attribute>>,
) -> Result<RsaPublicKey, Error> {
    let mut template: Vec<Attribute> = template.into();
    template.push(Attribute::Class(ObjectClass::PUBLIC_KEY));
    template.push(Attribute::KeyType(KeyType::RSA));

    let keys = session.find_objects(&template)?;
    if let Some(key) = keys.first() {
        let attribute_priv = session.get_attributes(
            *key,
            &[AttributeType::Modulus, AttributeType::PublicExponent],
        )?;

        let mut modulus = None;
        let mut public_exponent = None;

        for attribute in attribute_priv {
            match attribute {
                Attribute::Modulus(m) if modulus.is_none() => {
                    modulus = Some(m.clone());
                }
                Attribute::PublicExponent(e) if public_exponent.is_none() => {
                    public_exponent = Some(e.clone());
                }
                _ => {}
            }
        }

        let modulus = modulus
            .ok_or(Error::MissingAttribute(AttributeType::Modulus))
            .map(|v| BigUint::from_bytes_be(v.as_slice()))?;
        let public_exponent = public_exponent
            .ok_or(Error::MissingAttribute(AttributeType::PublicExponent))
            .map(|v| BigUint::from_bytes_be(v.as_slice()))?;

        Ok(RsaPublicKey::new(modulus, public_exponent)?)
    } else {
        Err(Error::MissingKey)
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Cryptoki error: {0}")]
    Cryptoki(#[from] cryptoki::error::Error),

    #[error("Private key missing attribute: {0}")]
    MissingAttribute(AttributeType),

    #[error("RSA error: {0}")]
    Rsa(#[from] rsa::Error),

    #[error("Key not found")]
    MissingKey,
}

pub trait DigestSigning: Digest + AssociatedOid {
    fn pkcs_mechanism() -> Mechanism<'static>;

    fn pss_mechanism() -> Mechanism<'static>;
}

macro_rules! impl_digest_signing {
    ($d:ty, $pkcs_mech:ident, $pss_mech:ident, $mt:ident, $mgf:ident) => {
        impl DigestSigning for $d {
            fn pkcs_mechanism() -> Mechanism<'static> {
                Mechanism::$pkcs_mech
            }

            fn pss_mechanism() -> Mechanism<'static> {
                Mechanism::$pss_mech(PkcsPssParams {
                    hash_alg: MechanismType::$mt,
                    mgf: PkcsMgfType::$mgf,
                    // Safety:
                    // the output_size of an hash function will not go over 2^32,
                    // this unwrap is safe.
                    s_len: Self::output_size().try_into().unwrap(),
                })
            }
        }
    };
}

impl_digest_signing!(sha1::Sha1, Sha1RsaPkcs, Sha1RsaPkcsPss, SHA1, MGF1_SHA1);
impl_digest_signing!(
    sha2::Sha256,
    Sha256RsaPkcs,
    Sha256RsaPkcsPss,
    SHA256,
    MGF1_SHA256
);
impl_digest_signing!(
    sha2::Sha384,
    Sha384RsaPkcs,
    Sha384RsaPkcsPss,
    SHA384,
    MGF1_SHA384
);
impl_digest_signing!(
    sha2::Sha512,
    Sha512RsaPkcs,
    Sha512RsaPkcsPss,
    SHA512,
    MGF1_SHA512
);
