// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use cryptoki::mechanism::{
    rsa::{PkcsMgfType, PkcsPssParams},
    Mechanism, MechanismType,
};
use cryptoki::object::AttributeType;
use der::oid::AssociatedOid;
use signature::digest::Digest;
use std::convert::TryInto;
use thiserror::Error;

pub mod pkcs1v15;

pub mod pss;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Cryptoki error: {0}")]
    Cryptoki(#[from] cryptoki::error::Error),

    #[error("Private key missing attribute: {0}")]
    MissingAttribute(AttributeType),

    #[error("RSA error: {0}")]
    Rsa(#[from] rsa::Error),
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
