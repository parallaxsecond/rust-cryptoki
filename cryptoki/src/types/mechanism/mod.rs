// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Data types for mechanisms

pub mod elliptic_curve;
pub mod rsa;

use crate::types::{MechanismFlags, Ulong};
use crate::Error;
use cryptoki_sys::*;
use log::error;
use std::convert::{TryFrom, TryInto};
use std::ffi::c_void;
use std::ops::Deref;
use std::ptr::null_mut;

#[derive(Copy, Debug, Clone, PartialEq, Eq)]
// transparent so that a vector of MechanismType should have the same layout than a vector of
// CK_MECHANISM_TYPE.
/// Type of a mechanism
#[repr(transparent)]
pub struct MechanismType {
    val: CK_MECHANISM_TYPE,
}

impl MechanismType {
    // RSA
    /// PKCS #1 RSA key pair generation mechanism
    pub const RSA_PKCS_KEY_PAIR_GEN: MechanismType = MechanismType {
        val: CKM_RSA_PKCS_KEY_PAIR_GEN,
    };
    /// Multi-purpose mechanism based on the RSA public-key cryptosystem and the block formats
    /// initially defined in PKCS #1 v1.5
    pub const RSA_PKCS: MechanismType = MechanismType { val: CKM_RSA_PKCS };
    /// Mechanism based on the RSA public-key cryptosystem and the PSS block format defined in PKCS
    /// #1
    pub const RSA_PKCS_PSS: MechanismType = MechanismType {
        val: CKM_RSA_PKCS_PSS,
    };
    /// Multi-purpose mechanism based on the RSA public-key cryptosystem and the OAEP block format
    /// defined in PKCS #1
    pub const RSA_PKCS_OAEP: MechanismType = MechanismType {
        val: CKM_RSA_PKCS_OAEP,
    };

    // DES
    /// DES3
    /// Note that DES3 is deprecated. See https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf section 2, p. 6.
    pub const DES3_KEY_GEN: MechanismType = MechanismType {
        val: CKM_DES3_KEY_GEN,
    };
    /// DES3 ECB
    /// Note that DES3 is deprecated. See https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf section 2, p. 6.
    pub const DES3_ECB: MechanismType = MechanismType { val: CKM_DES3_ECB };

    // ECC
    /// EC key pair generation mechanism
    pub const ECC_KEY_PAIR_GEN: MechanismType = MechanismType {
        val: CKM_EC_KEY_PAIR_GEN,
    };
    /// EC edwards key pair generation mechanism
    pub const ECC_EDWARDS_KEY_PAIR_GEN: MechanismType = MechanismType {
        val: CKM_EC_EDWARDS_KEY_PAIR_GEN,
    };
    /// EC montgomery key pair generation mechanism
    pub const ECC_MONTGOMERY_KEY_PAIR_GEN: MechanismType = MechanismType {
        val: CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    };

    /// ECDH key derivation mechanism
    pub const ECDH1_DERIVE: MechanismType = MechanismType {
        val: CKM_ECDH1_DERIVE,
    };

    /// ECDSA mechanism
    pub const ECDSA: MechanismType = MechanismType { val: CKM_ECDSA };

    // SHA-n
    /// SHA-1 mechanism
    pub const SHA1: MechanismType = MechanismType { val: CKM_SHA_1 };
    /// SHA-256 mechanism
    pub const SHA256: MechanismType = MechanismType { val: CKM_SHA256 };
    /// SHA-384 mechanism
    pub const SHA384: MechanismType = MechanismType { val: CKM_SHA384 };
    /// SHA-512 mechanism
    pub const SHA512: MechanismType = MechanismType { val: CKM_SHA512 };

    // SHAn-RSA-PKCS
    /// SHA256-RSA-PKCS mechanism
    pub const SHA256_RSA_PKCS: MechanismType = MechanismType {
        val: CKM_SHA256_RSA_PKCS,
    };
    /// SHA384-RSA-PKCS mechanism
    pub const SHA384_RSA_PKCS: MechanismType = MechanismType {
        val: CKM_SHA384_RSA_PKCS,
    };
    /// SHA512-RSA-PKCS mechanism
    pub const SHA512_RSA_PKCS: MechanismType = MechanismType {
        val: CKM_SHA512_RSA_PKCS,
    };
}

impl Deref for MechanismType {
    type Target = CK_MECHANISM_TYPE;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

impl From<MechanismType> for CK_MECHANISM_TYPE {
    fn from(mechanism_type: MechanismType) -> Self {
        *mechanism_type
    }
}

impl TryFrom<CK_MECHANISM_TYPE> for MechanismType {
    type Error = Error;

    fn try_from(mechanism_type: CK_MECHANISM_TYPE) -> Result<Self, Self::Error> {
        match mechanism_type {
            CKM_RSA_PKCS_KEY_PAIR_GEN => Ok(MechanismType::RSA_PKCS_KEY_PAIR_GEN),
            CKM_RSA_PKCS => Ok(MechanismType::RSA_PKCS),
            CKM_RSA_PKCS_PSS => Ok(MechanismType::RSA_PKCS_PSS),
            CKM_RSA_PKCS_OAEP => Ok(MechanismType::RSA_PKCS_OAEP),
            CKM_SHA_1 => Ok(MechanismType::SHA1),
            CKM_SHA256 => Ok(MechanismType::SHA256),
            CKM_SHA384 => Ok(MechanismType::SHA384),
            CKM_SHA512 => Ok(MechanismType::SHA512),
            CKM_DES3_KEY_GEN => Ok(MechanismType::DES3_KEY_GEN),
            CKM_DES3_ECB => Ok(MechanismType::DES3_ECB),
            CKM_EC_KEY_PAIR_GEN => Ok(MechanismType::ECC_KEY_PAIR_GEN),
            CKM_EC_EDWARDS_KEY_PAIR_GEN => Ok(MechanismType::ECC_EDWARDS_KEY_PAIR_GEN),
            CKM_EC_MONTGOMERY_KEY_PAIR_GEN => Ok(MechanismType::ECC_MONTGOMERY_KEY_PAIR_GEN),
            CKM_ECDH1_DERIVE => Ok(MechanismType::ECDH1_DERIVE),
            CKM_ECDSA => Ok(MechanismType::ECDSA),
            CKM_SHA256_RSA_PKCS => Ok(MechanismType::SHA256_RSA_PKCS),
            CKM_SHA384_RSA_PKCS => Ok(MechanismType::SHA384_RSA_PKCS),
            CKM_SHA512_RSA_PKCS => Ok(MechanismType::SHA512_RSA_PKCS),
            other => {
                error!("Mechanism type {} is not supported.", other);
                Err(Error::NotSupported)
            }
        }
    }
}

#[derive(Copy, Debug, Clone)]
#[non_exhaustive]
/// Type defining a specific mechanism and its parameters
pub enum Mechanism {
    // RSA
    /// PKCS #1 RSA key pair generation mechanism
    RsaPkcsKeyPairGen,
    /// Multi-purpose mechanism based on the RSA public-key cryptosystem and the block formats
    /// initially defined in PKCS #1 v1.5
    RsaPkcs,
    /// Mechanism based on the RSA public-key cryptosystem and the PSS block format defined in PKCS
    /// #1
    RsaPkcsPss(rsa::PkcsPssParams),
    /// Multi-purpose mechanism based on the RSA public-key cryptosystem and the OAEP block format
    /// defined in PKCS #1
    RsaPkcsOaep(rsa::PkcsOaepParams),

    // DES
    /// DES3
    Des3KeyGen,
    /// DES3 ECB
    Des3Ecb,

    // ECC
    /// EC key pair generation
    EccKeyPairGen,
    /// EC edwards key pair generation
    EccEdwardsKeyPairGen,
    /// EC montgomery key pair generation
    EccMontgomeryKeyPairGen,
    /// ECDH
    Ecdh1Derive(elliptic_curve::Ecdh1DeriveParams),
    /// ECDSA mechanism
    Ecdsa,

    // SHA-n
    /// SHA-1 mechanism
    Sha1,
    /// SHA-256 mechanism
    Sha256,
    /// SHA-384 mechanism
    Sha384,
    /// SHA-512 mechanism
    Sha512,

    // SHAn-RSA-PKCS
    /// SHA256-RSA-PKCS mechanism
    Sha256RsaPkcs,
    /// SHA384-RSA-PKCS mechanism
    Sha384RsaPkcs,
    /// SHA512-RSA-PKCS mechanism
    Sha512RsaPkcs,
}

impl Mechanism {
    /// Get the type of a mechanism
    pub fn mechanism_type(&self) -> MechanismType {
        match self {
            Mechanism::RsaPkcsKeyPairGen => MechanismType::RSA_PKCS_KEY_PAIR_GEN,
            Mechanism::RsaPkcs => MechanismType::RSA_PKCS,
            Mechanism::RsaPkcsPss(_) => MechanismType::RSA_PKCS_PSS,
            Mechanism::RsaPkcsOaep(_) => MechanismType::RSA_PKCS_OAEP,

            Mechanism::Des3KeyGen => MechanismType::DES3_KEY_GEN,
            Mechanism::Des3Ecb => MechanismType::DES3_ECB,

            Mechanism::EccKeyPairGen => MechanismType::ECC_KEY_PAIR_GEN,
            Mechanism::EccEdwardsKeyPairGen => MechanismType::ECC_EDWARDS_KEY_PAIR_GEN,
            Mechanism::EccMontgomeryKeyPairGen => MechanismType::ECC_MONTGOMERY_KEY_PAIR_GEN,
            Mechanism::Ecdh1Derive(_) => MechanismType::ECDH1_DERIVE,
            Mechanism::Ecdsa => MechanismType::ECDSA,

            Mechanism::Sha1 => MechanismType::SHA1,
            Mechanism::Sha256 => MechanismType::SHA256,
            Mechanism::Sha384 => MechanismType::SHA384,
            Mechanism::Sha512 => MechanismType::SHA512,

            Mechanism::Sha256RsaPkcs => MechanismType::SHA256_RSA_PKCS,
            Mechanism::Sha384RsaPkcs => MechanismType::SHA384_RSA_PKCS,
            Mechanism::Sha512RsaPkcs => MechanismType::SHA512_RSA_PKCS,
        }
    }
}

impl From<&Mechanism> for CK_MECHANISM {
    fn from(mech: &Mechanism) -> Self {
        let mechanism = mech.mechanism_type().into();
        match mech {
            Mechanism::RsaPkcsPss(params) => CK_MECHANISM {
                mechanism,
                pParameter: params as *const _ as *mut c_void,
                ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>()
                    .try_into()
                    .expect("usize can not fit in CK_ULONG"),
            },
            Mechanism::RsaPkcsOaep(params) => CK_MECHANISM {
                mechanism,
                pParameter: params as *const _ as *mut c_void,
                ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>()
                    .try_into()
                    .expect("usize can not fit in CK_ULONG"),
            },
            Mechanism::Ecdh1Derive(params) => CK_MECHANISM {
                mechanism,
                pParameter: params as *const _ as *mut c_void,
                ulParameterLen: std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>()
                    .try_into()
                    .expect("usize can not fit in CK_ULONG"),
            },
            // Mechanisms without parameters
            Mechanism::RsaPkcsKeyPairGen
            | Mechanism::RsaPkcs
            | Mechanism::Sha1
            | Mechanism::Sha256
            | Mechanism::Sha384
            | Mechanism::Sha512
            | Mechanism::Des3KeyGen
            | Mechanism::Des3Ecb
            | Mechanism::EccKeyPairGen
            | Mechanism::EccEdwardsKeyPairGen
            | Mechanism::EccMontgomeryKeyPairGen
            | Mechanism::Ecdsa
            | Mechanism::Sha256RsaPkcs
            | Mechanism::Sha384RsaPkcs
            | Mechanism::Sha512RsaPkcs => CK_MECHANISM {
                mechanism,
                pParameter: null_mut(),
                ulParameterLen: 0,
            },
        }
    }
}

#[cfg(feature = "psa-crypto-conversions")]
#[allow(deprecated)]
impl TryFrom<psa_crypto::types::algorithm::Algorithm> for Mechanism {
    type Error = Error;

    fn try_from(alg: psa_crypto::types::algorithm::Algorithm) -> Result<Self, Self::Error> {
        use psa_crypto::types::algorithm::{
            Algorithm, AsymmetricEncryption, AsymmetricSignature, Hash, SignHash,
        };

        match alg {
            Algorithm::Hash(Hash::Sha1) => Ok(Mechanism::Sha1),
            Algorithm::Hash(Hash::Sha256) => Ok(Mechanism::Sha256),
            Algorithm::Hash(Hash::Sha384) => Ok(Mechanism::Sha384),
            Algorithm::Hash(Hash::Sha512) => Ok(Mechanism::Sha512),
            Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign { .. })
            | Algorithm::AsymmetricEncryption(AsymmetricEncryption::RsaPkcs1v15Crypt { .. }) => {
                Ok(Mechanism::RsaPkcs)
            }
            Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPss {
                hash_alg: SignHash::Specific(hash_alg),
            }) => Ok(Mechanism::RsaPkcsPss(rsa::PkcsPssParams {
                hash_alg: Mechanism::try_from(Algorithm::from(hash_alg))?.mechanism_type(),
                mgf: rsa::PkcsMgfType::from_psa_crypto_hash(hash_alg)?,
                s_len: hash_alg.hash_length().try_into()?,
            })),
            Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa { .. }) => {
                Ok(Mechanism::Ecdsa)
            }
            Algorithm::AsymmetricEncryption(AsymmetricEncryption::RsaOaep { hash_alg }) => {
                Ok(Mechanism::RsaPkcsOaep(rsa::PkcsOaepParams {
                    hash_alg: Mechanism::try_from(Algorithm::from(hash_alg))?.mechanism_type(),
                    mgf: rsa::PkcsMgfType::from_psa_crypto_hash(hash_alg)?,
                    source: rsa::PkcsOaepSourceType::DATA_SPECIFIED,
                    source_data: std::ptr::null(),
                    source_data_len: 0.into(),
                }))
            }
            alg => {
                error!("{:?} is not a supported algorithm", alg);
                Err(Error::NotSupported)
            }
        }
    }
}

/// Contains information about a mechanism
#[derive(Debug, Clone, Copy, Default)]
pub struct MechanismInfo {
    val: CK_MECHANISM_INFO,
}

impl MechanismInfo {
    pub(crate) fn new(val: CK_MECHANISM_INFO) -> Self {
        Self { val }
    }

    /// Returns the minimum key size for this mechanism.
    pub fn min_key_size(&self) -> Ulong {
        self.val.ulMinKeySize.into()
    }

    /// Returns the maximum key size for this mechanism.
    pub fn max_key_size(&self) -> Ulong {
        self.val.ulMaxKeySize.into()
    }

    /// Returns the flags for this mechanism.
    pub fn flags(&self) -> MechanismFlags {
        self.val.flags.into()
    }
}

impl Deref for MechanismInfo {
    type Target = CK_MECHANISM_INFO;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

impl From<MechanismInfo> for CK_MECHANISM_INFO {
    fn from(mechanism_info: MechanismInfo) -> Self {
        *mechanism_info
    }
}
