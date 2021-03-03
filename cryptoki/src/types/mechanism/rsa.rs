//! RSA mechanism types

use crate::types::mechanism::{Mechanism, MechanismType};
use crate::types::Ulong;
use crate::{Error, Result};
use cryptoki_sys::*;
use log::error;
use std::convert::TryFrom;
use std::ffi::c_void;
use std::ops::Deref;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
/// Message Generation Function (MGF) applied to a message block when formatting a message block
/// for the PKCS #1 OAEP encryption scheme or the PKCS #1 PSS signature scheme.
pub struct PkcsMgfType {
    val: CK_RSA_PKCS_MGF_TYPE,
}

impl PkcsMgfType {
    /// MGF1 SHA-1
    pub const MGF1_SHA1: PkcsMgfType = PkcsMgfType { val: CKG_MGF1_SHA1 };
    /// MGF1 SHA-224
    pub const MGF1_SHA224: PkcsMgfType = PkcsMgfType {
        val: CKG_MGF1_SHA224,
    };
    /// MGF1 SHA-256
    pub const MGF1_SHA256: PkcsMgfType = PkcsMgfType {
        val: CKG_MGF1_SHA256,
    };
    /// MGF1 SHA-384
    pub const MGF1_SHA384: PkcsMgfType = PkcsMgfType {
        val: CKG_MGF1_SHA384,
    };
    /// MGF1 SHA-512
    pub const MGF1_SHA512: PkcsMgfType = PkcsMgfType {
        val: CKG_MGF1_SHA512,
    };
}

impl Deref for PkcsMgfType {
    type Target = CK_RSA_PKCS_MGF_TYPE;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

impl From<PkcsMgfType> for CK_RSA_PKCS_MGF_TYPE {
    fn from(mgf_type: PkcsMgfType) -> Self {
        *mgf_type
    }
}

impl TryFrom<CK_RSA_PKCS_MGF_TYPE> for PkcsMgfType {
    type Error = Error;

    fn try_from(mgf_type: CK_RSA_PKCS_MGF_TYPE) -> Result<Self> {
        match mgf_type {
            CKG_MGF1_SHA1 => Ok(PkcsMgfType::MGF1_SHA1),
            CKG_MGF1_SHA224 => Ok(PkcsMgfType::MGF1_SHA224),
            CKG_MGF1_SHA256 => Ok(PkcsMgfType::MGF1_SHA256),
            CKG_MGF1_SHA384 => Ok(PkcsMgfType::MGF1_SHA384),
            CKG_MGF1_SHA512 => Ok(PkcsMgfType::MGF1_SHA512),
            other => {
                error!(
                    "Mask Generation Function type {} is not one of the valid values.",
                    other
                );
                Err(Error::InvalidValue)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
/// Source of the encoding parameter when formatting a message block for the PKCS #1 OAEP
/// encryption scheme
pub struct PkcsOaepSourceType {
    val: CK_RSA_PKCS_OAEP_SOURCE_TYPE,
}

impl PkcsOaepSourceType {
    /// Array of CK_BYTE containing the value of the encoding parameter. If the parameter is
    /// empty, pSourceData must be NULL and ulSourceDataLen must be zero.
    pub const DATA_SPECIFIED: PkcsOaepSourceType = PkcsOaepSourceType {
        val: CKZ_DATA_SPECIFIED,
    };
}

impl Deref for PkcsOaepSourceType {
    type Target = CK_RSA_PKCS_OAEP_SOURCE_TYPE;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

impl From<PkcsOaepSourceType> for CK_RSA_PKCS_OAEP_SOURCE_TYPE {
    fn from(pkcs_oaep_source_type: PkcsOaepSourceType) -> Self {
        *pkcs_oaep_source_type
    }
}

impl TryFrom<CK_RSA_PKCS_OAEP_SOURCE_TYPE> for PkcsOaepSourceType {
    type Error = Error;

    fn try_from(pkcs_oaep_source_type: CK_RSA_PKCS_OAEP_SOURCE_TYPE) -> Result<Self> {
        match pkcs_oaep_source_type {
            CKZ_DATA_SPECIFIED => Ok(PkcsOaepSourceType::DATA_SPECIFIED),
            other => {
                error!("OAEP source type {} is not one of the valid values.", other);
                Err(Error::InvalidValue)
            }
        }
    }
}

/// Parameters of the RsaPkcsPss mechanism
#[derive(Debug, Clone)]
#[repr(C)]
pub struct PkcsPssParams {
    /// hash algorithm used in the PSS encoding; if the signature mechanism does not include
    /// message hashing, then this value must be the mechanism used by the application to generate
    /// the message hash; if the signature mechanism includes hashing, then this value must match
    /// the hash algorithm indicated by the signature mechanism
    pub hash_alg: MechanismType,
    /// mask generation function to use on the encoded block
    pub mgf: PkcsMgfType,
    /// length, in bytes, of the salt value used in the PSS encoding; typical values are the length
    /// of the message hash and zero
    pub s_len: Ulong,
}

impl From<PkcsPssParams> for Mechanism {
    fn from(pkcs_pss_params: PkcsPssParams) -> Self {
        Mechanism::RsaPkcsPss(pkcs_pss_params)
    }
}

/// Parameters of the RsaPkcsOaep mechanism
#[derive(Debug, Clone)]
#[repr(C)]
pub struct PkcsOaepParams {
    /// mechanism ID of the message digest algorithm used to calculate the digest of the encoding
    /// parameter
    pub hash_alg: MechanismType,
    /// mask generation function to use on the encoded block
    pub mgf: PkcsMgfType,
    /// source of the encoding parameter
    pub source: PkcsOaepSourceType,
    /// data used as the input for the encoding parameter source
    pub source_data: *const c_void,
    /// length of the encoding parameter source input
    pub source_data_len: Ulong,
}

impl From<PkcsOaepParams> for Mechanism {
    fn from(pkcs_oaep_params: PkcsOaepParams) -> Self {
        Mechanism::RsaPkcsOaep(pkcs_oaep_params)
    }
}

#[cfg(feature = "psa-crypto-conversions")]
#[allow(deprecated)]
impl PkcsMgfType {
    /// Convert a PSA Crypto Hash algorithm to a MGF type
    pub fn from_psa_crypto_hash(alg: psa_crypto::types::algorithm::Hash) -> Result<Self> {
        use psa_crypto::types::algorithm::Hash;

        match alg {
            Hash::Sha1 => Ok(PkcsMgfType::MGF1_SHA1),
            Hash::Sha224 => Ok(PkcsMgfType::MGF1_SHA224),
            Hash::Sha256 => Ok(PkcsMgfType::MGF1_SHA256),
            Hash::Sha384 => Ok(PkcsMgfType::MGF1_SHA384),
            Hash::Sha512 => Ok(PkcsMgfType::MGF1_SHA512),
            alg => {
                error!("{:?} is not a supported MGF1 algorithm", alg);
                Err(Error::NotSupported)
            }
        }
    }
}
