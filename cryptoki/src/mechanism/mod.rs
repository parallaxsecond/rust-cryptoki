// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Data types for mechanisms

pub mod elliptic_curve;
mod flags;
pub mod rsa;
pub use flags::*;

use crate::error::Error;
use crate::types::Ulong;
use cryptoki_sys::*;
use log::error;
use std::convert::{TryFrom, TryInto};
use std::ffi::c_void;
use std::fmt::Formatter;
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
    // AES
    /// AES key generation mechanism
    pub const AES_KEY_GEN: MechanismType = MechanismType {
        val: CKM_AES_KEY_GEN,
    };

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
    /// Note that DES3 is deprecated. See <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf> section 2, p. 6.
    pub const DES3_KEY_GEN: MechanismType = MechanismType {
        val: CKM_DES3_KEY_GEN,
    };
    /// DES3 ECB
    /// Note that DES3 is deprecated. See <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf> section 2, p. 6.
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

    pub(crate) fn stringify(mech: CK_MECHANISM_TYPE) -> String {
        match mech {
            CKM_RSA_PKCS_KEY_PAIR_GEN => String::from(stringify!(CKM_RSA_PKCS_KEY_PAIR_GEN)),
            CKM_RSA_PKCS => String::from(stringify!(CKM_RSA_PKCS)),
            CKM_RSA_9796 => String::from(stringify!(CKM_RSA_9796)),
            CKM_RSA_X_509 => String::from(stringify!(CKM_RSA_X_509)),
            CKM_MD2_RSA_PKCS => String::from(stringify!(CKM_MD2_RSA_PKCS)),
            CKM_MD5_RSA_PKCS => String::from(stringify!(CKM_MD5_RSA_PKCS)),
            CKM_SHA1_RSA_PKCS => String::from(stringify!(CKM_SHA1_RSA_PKCS)),
            CKM_RIPEMD128_RSA_PKCS => String::from(stringify!(CKM_RIPEMD128_RSA_PKCS)),
            CKM_RIPEMD160_RSA_PKCS => String::from(stringify!(CKM_RIPEMD160_RSA_PKCS)),
            CKM_RSA_PKCS_OAEP => String::from(stringify!(CKM_RSA_PKCS_OAEP)),
            CKM_RSA_X9_31_KEY_PAIR_GEN => String::from(stringify!(CKM_RSA_X9_31_KEY_PAIR_GEN)),
            CKM_RSA_X9_31 => String::from(stringify!(CKM_RSA_X9_31)),
            CKM_SHA1_RSA_X9_31 => String::from(stringify!(CKM_SHA1_RSA_X9_31)),
            CKM_RSA_PKCS_PSS => String::from(stringify!(CKM_RSA_PKCS_PSS)),
            CKM_SHA1_RSA_PKCS_PSS => String::from(stringify!(CKM_SHA1_RSA_PKCS_PSS)),
            CKM_DSA_KEY_PAIR_GEN => String::from(stringify!(CKM_DSA_KEY_PAIR_GEN)),
            CKM_DSA => String::from(stringify!(CKM_DSA)),
            CKM_DSA_SHA1 => String::from(stringify!(CKM_DSA_SHA1)),
            CKM_DSA_SHA224 => String::from(stringify!(CKM_DSA_SHA224)),
            CKM_DSA_SHA256 => String::from(stringify!(CKM_DSA_SHA256)),
            CKM_DSA_SHA384 => String::from(stringify!(CKM_DSA_SHA384)),
            CKM_DSA_SHA512 => String::from(stringify!(CKM_DSA_SHA512)),
            CKM_DH_PKCS_KEY_PAIR_GEN => String::from(stringify!(CKM_DH_PKCS_KEY_PAIR_GEN)),
            CKM_DH_PKCS_DERIVE => String::from(stringify!(CKM_DH_PKCS_DERIVE)),
            CKM_X9_42_DH_KEY_PAIR_GEN => String::from(stringify!(CKM_X9_42_DH_KEY_PAIR_GEN)),
            CKM_X9_42_DH_DERIVE => String::from(stringify!(CKM_X9_42_DH_DERIVE)),
            CKM_X9_42_DH_HYBRID_DERIVE => String::from(stringify!(CKM_X9_42_DH_HYBRID_DERIVE)),
            CKM_X9_42_MQV_DERIVE => String::from(stringify!(CKM_X9_42_MQV_DERIVE)),
            CKM_SHA256_RSA_PKCS => String::from(stringify!(CKM_SHA256_RSA_PKCS)),
            CKM_SHA384_RSA_PKCS => String::from(stringify!(CKM_SHA384_RSA_PKCS)),
            CKM_SHA512_RSA_PKCS => String::from(stringify!(CKM_SHA512_RSA_PKCS)),
            CKM_SHA256_RSA_PKCS_PSS => String::from(stringify!(CKM_SHA256_RSA_PKCS_PSS)),
            CKM_SHA384_RSA_PKCS_PSS => String::from(stringify!(CKM_SHA384_RSA_PKCS_PSS)),
            CKM_SHA512_RSA_PKCS_PSS => String::from(stringify!(CKM_SHA512_RSA_PKCS_PSS)),
            CKM_SHA512_224 => String::from(stringify!(CKM_SHA512_224)),
            CKM_SHA512_224_HMAC => String::from(stringify!(CKM_SHA512_224_HMAC)),
            CKM_SHA512_224_HMAC_GENERAL => String::from(stringify!(CKM_SHA512_224_HMAC_GENERAL)),
            CKM_SHA512_224_KEY_DERIVATION => {
                String::from(stringify!(CKM_SHA512_224_KEY_DERIVATION))
            }
            CKM_SHA512_256 => String::from(stringify!(CKM_SHA512_256)),
            CKM_SHA512_256_HMAC => String::from(stringify!(CKM_SHA512_256_HMAC)),
            CKM_SHA512_256_HMAC_GENERAL => String::from(stringify!(CKM_SHA512_256_HMAC_GENERAL)),
            CKM_SHA512_256_KEY_DERIVATION => {
                String::from(stringify!(CKM_SHA512_256_KEY_DERIVATION))
            }
            CKM_SHA512_T => String::from(stringify!(CKM_SHA512_T)),
            CKM_SHA512_T_HMAC => String::from(stringify!(CKM_SHA512_T_HMAC)),
            CKM_SHA512_T_HMAC_GENERAL => String::from(stringify!(CKM_SHA512_T_HMAC_GENERAL)),
            CKM_SHA512_T_KEY_DERIVATION => String::from(stringify!(CKM_SHA512_T_KEY_DERIVATION)),
            CKM_RC2_KEY_GEN => String::from(stringify!(CKM_RC2_KEY_GEN)),
            CKM_RC2_ECB => String::from(stringify!(CKM_RC2_ECB)),
            CKM_RC2_CBC => String::from(stringify!(CKM_RC2_CBC)),
            CKM_RC2_MAC => String::from(stringify!(CKM_RC2_MAC)),
            CKM_RC2_MAC_GENERAL => String::from(stringify!(CKM_RC2_MAC_GENERAL)),
            CKM_RC2_CBC_PAD => String::from(stringify!(CKM_RC2_CBC_PAD)),
            CKM_RC4_KEY_GEN => String::from(stringify!(CKM_RC4_KEY_GEN)),
            CKM_RC4 => String::from(stringify!(CKM_RC4)),
            CKM_DES_KEY_GEN => String::from(stringify!(CKM_DES_KEY_GEN)),
            CKM_DES_ECB => String::from(stringify!(CKM_DES_ECB)),
            CKM_DES_CBC => String::from(stringify!(CKM_DES_CBC)),
            CKM_DES_MAC => String::from(stringify!(CKM_DES_MAC)),
            CKM_DES_MAC_GENERAL => String::from(stringify!(CKM_DES_MAC_GENERAL)),
            CKM_DES_CBC_PAD => String::from(stringify!(CKM_DES_CBC_PAD)),
            CKM_DES2_KEY_GEN => String::from(stringify!(CKM_DES2_KEY_GEN)),
            CKM_DES3_KEY_GEN => String::from(stringify!(CKM_DES3_KEY_GEN)),
            CKM_DES3_ECB => String::from(stringify!(CKM_DES3_ECB)),
            CKM_DES3_CBC => String::from(stringify!(CKM_DES3_CBC)),
            CKM_DES3_MAC => String::from(stringify!(CKM_DES3_MAC)),
            CKM_DES3_MAC_GENERAL => String::from(stringify!(CKM_DES3_MAC_GENERAL)),
            CKM_DES3_CBC_PAD => String::from(stringify!(CKM_DES3_CBC_PAD)),
            CKM_DES3_CMAC_GENERAL => String::from(stringify!(CKM_DES3_CMAC_GENERAL)),
            CKM_DES3_CMAC => String::from(stringify!(CKM_DES3_CMAC)),
            CKM_CDMF_KEY_GEN => String::from(stringify!(CKM_CDMF_KEY_GEN)),
            CKM_CDMF_ECB => String::from(stringify!(CKM_CDMF_ECB)),
            CKM_CDMF_CBC => String::from(stringify!(CKM_CDMF_CBC)),
            CKM_CDMF_MAC => String::from(stringify!(CKM_CDMF_MAC)),
            CKM_CDMF_MAC_GENERAL => String::from(stringify!(CKM_CDMF_MAC_GENERAL)),
            CKM_CDMF_CBC_PAD => String::from(stringify!(CKM_CDMF_CBC_PAD)),
            CKM_DES_OFB64 => String::from(stringify!(CKM_DES_OFB64)),
            CKM_DES_OFB8 => String::from(stringify!(CKM_DES_OFB8)),
            CKM_DES_CFB64 => String::from(stringify!(CKM_DES_CFB64)),
            CKM_DES_CFB8 => String::from(stringify!(CKM_DES_CFB8)),
            CKM_MD2 => String::from(stringify!(CKM_MD2)),
            CKM_MD2_HMAC => String::from(stringify!(CKM_MD2_HMAC)),
            CKM_MD2_HMAC_GENERAL => String::from(stringify!(CKM_MD2_HMAC_GENERAL)),
            CKM_MD5 => String::from(stringify!(CKM_MD5)),
            CKM_MD5_HMAC => String::from(stringify!(CKM_MD5_HMAC)),
            CKM_MD5_HMAC_GENERAL => String::from(stringify!(CKM_MD5_HMAC_GENERAL)),
            CKM_SHA_1 => String::from(stringify!(CKM_SHA_1)),
            CKM_SHA_1_HMAC => String::from(stringify!(CKM_SHA_1_HMAC)),
            CKM_SHA_1_HMAC_GENERAL => String::from(stringify!(CKM_SHA_1_HMAC_GENERAL)),
            CKM_RIPEMD128 => String::from(stringify!(CKM_RIPEMD128)),
            CKM_RIPEMD128_HMAC => String::from(stringify!(CKM_RIPEMD128_HMAC)),
            CKM_RIPEMD128_HMAC_GENERAL => String::from(stringify!(CKM_RIPEMD128_HMAC_GENERAL)),
            CKM_RIPEMD160 => String::from(stringify!(CKM_RIPEMD160)),
            CKM_RIPEMD160_HMAC => String::from(stringify!(CKM_RIPEMD160_HMAC)),
            CKM_RIPEMD160_HMAC_GENERAL => String::from(stringify!(CKM_RIPEMD160_HMAC_GENERAL)),
            CKM_SHA256 => String::from(stringify!(CKM_SHA256)),
            CKM_SHA256_HMAC => String::from(stringify!(CKM_SHA256_HMAC)),
            CKM_SHA256_HMAC_GENERAL => String::from(stringify!(CKM_SHA256_HMAC_GENERAL)),
            CKM_SHA384 => String::from(stringify!(CKM_SHA384)),
            CKM_SHA384_HMAC => String::from(stringify!(CKM_SHA384_HMAC)),
            CKM_SHA384_HMAC_GENERAL => String::from(stringify!(CKM_SHA384_HMAC_GENERAL)),
            CKM_SHA512 => String::from(stringify!(CKM_SHA512)),
            CKM_SHA512_HMAC => String::from(stringify!(CKM_SHA512_HMAC)),
            CKM_SHA512_HMAC_GENERAL => String::from(stringify!(CKM_SHA512_HMAC_GENERAL)),
            CKM_SECURID_KEY_GEN => String::from(stringify!(CKM_SECURID_KEY_GEN)),
            CKM_SECURID => String::from(stringify!(CKM_SECURID)),
            CKM_HOTP_KEY_GEN => String::from(stringify!(CKM_HOTP_KEY_GEN)),
            CKM_HOTP => String::from(stringify!(CKM_HOTP)),
            CKM_ACTI => String::from(stringify!(CKM_ACTI)),
            CKM_ACTI_KEY_GEN => String::from(stringify!(CKM_ACTI_KEY_GEN)),
            CKM_CAST_KEY_GEN => String::from(stringify!(CKM_CAST_KEY_GEN)),
            CKM_CAST_ECB => String::from(stringify!(CKM_CAST_ECB)),
            CKM_CAST_CBC => String::from(stringify!(CKM_CAST_CBC)),
            CKM_CAST_MAC => String::from(stringify!(CKM_CAST_MAC)),
            CKM_CAST_MAC_GENERAL => String::from(stringify!(CKM_CAST_MAC_GENERAL)),
            CKM_CAST_CBC_PAD => String::from(stringify!(CKM_CAST_CBC_PAD)),
            CKM_CAST3_KEY_GEN => String::from(stringify!(CKM_CAST3_KEY_GEN)),
            CKM_CAST3_ECB => String::from(stringify!(CKM_CAST3_ECB)),
            CKM_CAST3_CBC => String::from(stringify!(CKM_CAST3_CBC)),
            CKM_CAST3_MAC => String::from(stringify!(CKM_CAST3_MAC)),
            CKM_CAST3_MAC_GENERAL => String::from(stringify!(CKM_CAST3_MAC_GENERAL)),
            CKM_CAST3_CBC_PAD => String::from(stringify!(CKM_CAST3_CBC_PAD)),
            CKM_CAST128_KEY_GEN => String::from(stringify!(CKM_CAST128_KEY_GEN)),
            CKM_CAST128_ECB => String::from(stringify!(CKM_CAST128_ECB)),
            CKM_CAST128_CBC => String::from(stringify!(CKM_CAST128_CBC)),
            CKM_CAST128_MAC => String::from(stringify!(CKM_CAST128_MAC)),
            CKM_CAST128_MAC_GENERAL => String::from(stringify!(CKM_CAST128_MAC_GENERAL)),
            CKM_CAST128_CBC_PAD => String::from(stringify!(CKM_CAST128_CBC_PAD)),
            CKM_RC5_KEY_GEN => String::from(stringify!(CKM_RC5_KEY_GEN)),
            CKM_RC5_ECB => String::from(stringify!(CKM_RC5_ECB)),
            CKM_RC5_CBC => String::from(stringify!(CKM_RC5_CBC)),
            CKM_RC5_MAC => String::from(stringify!(CKM_RC5_MAC)),
            CKM_RC5_MAC_GENERAL => String::from(stringify!(CKM_RC5_MAC_GENERAL)),
            CKM_RC5_CBC_PAD => String::from(stringify!(CKM_RC5_CBC_PAD)),
            CKM_IDEA_KEY_GEN => String::from(stringify!(CKM_IDEA_KEY_GEN)),
            CKM_IDEA_ECB => String::from(stringify!(CKM_IDEA_ECB)),
            CKM_IDEA_CBC => String::from(stringify!(CKM_IDEA_CBC)),
            CKM_IDEA_MAC => String::from(stringify!(CKM_IDEA_MAC)),
            CKM_IDEA_MAC_GENERAL => String::from(stringify!(CKM_IDEA_MAC_GENERAL)),
            CKM_IDEA_CBC_PAD => String::from(stringify!(CKM_IDEA_CBC_PAD)),
            CKM_GENERIC_SECRET_KEY_GEN => String::from(stringify!(CKM_GENERIC_SECRET_KEY_GEN)),
            CKM_CONCATENATE_BASE_AND_KEY => String::from(stringify!(CKM_CONCATENATE_BASE_AND_KEY)),
            CKM_CONCATENATE_BASE_AND_DATA => {
                String::from(stringify!(CKM_CONCATENATE_BASE_AND_DATA))
            }
            CKM_CONCATENATE_DATA_AND_BASE => {
                String::from(stringify!(CKM_CONCATENATE_DATA_AND_BASE))
            }
            CKM_XOR_BASE_AND_DATA => String::from(stringify!(CKM_XOR_BASE_AND_DATA)),
            CKM_EXTRACT_KEY_FROM_KEY => String::from(stringify!(CKM_EXTRACT_KEY_FROM_KEY)),
            CKM_SSL3_PRE_MASTER_KEY_GEN => String::from(stringify!(CKM_SSL3_PRE_MASTER_KEY_GEN)),
            CKM_SSL3_MASTER_KEY_DERIVE => String::from(stringify!(CKM_SSL3_MASTER_KEY_DERIVE)),
            CKM_SSL3_KEY_AND_MAC_DERIVE => String::from(stringify!(CKM_SSL3_KEY_AND_MAC_DERIVE)),
            CKM_SSL3_MASTER_KEY_DERIVE_DH => {
                String::from(stringify!(CKM_SSL3_MASTER_KEY_DERIVE_DH))
            }
            CKM_TLS_PRE_MASTER_KEY_GEN => String::from(stringify!(CKM_TLS_PRE_MASTER_KEY_GEN)),
            CKM_TLS_MASTER_KEY_DERIVE => String::from(stringify!(CKM_TLS_MASTER_KEY_DERIVE)),
            CKM_TLS_KEY_AND_MAC_DERIVE => String::from(stringify!(CKM_TLS_KEY_AND_MAC_DERIVE)),
            CKM_TLS_MASTER_KEY_DERIVE_DH => String::from(stringify!(CKM_TLS_MASTER_KEY_DERIVE_DH)),
            CKM_TLS_PRF => String::from(stringify!(CKM_TLS_PRF)),
            CKM_SSL3_MD5_MAC => String::from(stringify!(CKM_SSL3_MD5_MAC)),
            CKM_SSL3_SHA1_MAC => String::from(stringify!(CKM_SSL3_SHA1_MAC)),
            CKM_MD5_KEY_DERIVATION => String::from(stringify!(CKM_MD5_KEY_DERIVATION)),
            CKM_MD2_KEY_DERIVATION => String::from(stringify!(CKM_MD2_KEY_DERIVATION)),
            CKM_SHA1_KEY_DERIVATION => String::from(stringify!(CKM_SHA1_KEY_DERIVATION)),
            CKM_SHA256_KEY_DERIVATION => String::from(stringify!(CKM_SHA256_KEY_DERIVATION)),
            CKM_SHA384_KEY_DERIVATION => String::from(stringify!(CKM_SHA384_KEY_DERIVATION)),
            CKM_SHA512_KEY_DERIVATION => String::from(stringify!(CKM_SHA512_KEY_DERIVATION)),
            CKM_PBE_MD2_DES_CBC => String::from(stringify!(CKM_PBE_MD2_DES_CBC)),
            CKM_PBE_MD5_DES_CBC => String::from(stringify!(CKM_PBE_MD5_DES_CBC)),
            CKM_PBE_MD5_CAST_CBC => String::from(stringify!(CKM_PBE_MD5_CAST_CBC)),
            CKM_PBE_MD5_CAST3_CBC => String::from(stringify!(CKM_PBE_MD5_CAST3_CBC)),
            CKM_PBE_MD5_CAST128_CBC => String::from(stringify!(CKM_PBE_MD5_CAST128_CBC)),
            CKM_PBE_SHA1_CAST128_CBC => String::from(stringify!(CKM_PBE_SHA1_CAST128_CBC)),
            CKM_PBE_SHA1_RC4_128 => String::from(stringify!(CKM_PBE_SHA1_RC4_128)),
            CKM_PBE_SHA1_RC4_40 => String::from(stringify!(CKM_PBE_SHA1_RC4_40)),
            CKM_PBE_SHA1_DES3_EDE_CBC => String::from(stringify!(CKM_PBE_SHA1_DES3_EDE_CBC)),
            CKM_PBE_SHA1_DES2_EDE_CBC => String::from(stringify!(CKM_PBE_SHA1_DES2_EDE_CBC)),
            CKM_PBE_SHA1_RC2_128_CBC => String::from(stringify!(CKM_PBE_SHA1_RC2_128_CBC)),
            CKM_PBE_SHA1_RC2_40_CBC => String::from(stringify!(CKM_PBE_SHA1_RC2_40_CBC)),
            CKM_PKCS5_PBKD2 => String::from(stringify!(CKM_PKCS5_PBKD2)),
            CKM_PBA_SHA1_WITH_SHA1_HMAC => String::from(stringify!(CKM_PBA_SHA1_WITH_SHA1_HMAC)),
            CKM_WTLS_PRE_MASTER_KEY_GEN => String::from(stringify!(CKM_WTLS_PRE_MASTER_KEY_GEN)),
            CKM_WTLS_MASTER_KEY_DERIVE => String::from(stringify!(CKM_WTLS_MASTER_KEY_DERIVE)),
            CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC => {
                String::from(stringify!(CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC))
            }
            CKM_WTLS_PRF => String::from(stringify!(CKM_WTLS_PRF)),
            CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE => {
                String::from(stringify!(CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE))
            }
            CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE => {
                String::from(stringify!(CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE))
            }
            CKM_TLS10_MAC_SERVER => String::from(stringify!(CKM_TLS10_MAC_SERVER)),
            CKM_TLS10_MAC_CLIENT => String::from(stringify!(CKM_TLS10_MAC_CLIENT)),
            CKM_TLS12_MAC => String::from(stringify!(CKM_TLS12_MAC)),
            CKM_TLS12_KDF => String::from(stringify!(CKM_TLS12_KDF)),
            CKM_TLS12_MASTER_KEY_DERIVE => String::from(stringify!(CKM_TLS12_MASTER_KEY_DERIVE)),
            CKM_TLS12_KEY_AND_MAC_DERIVE => String::from(stringify!(CKM_TLS12_KEY_AND_MAC_DERIVE)),
            CKM_TLS12_MASTER_KEY_DERIVE_DH => {
                String::from(stringify!(CKM_TLS12_MASTER_KEY_DERIVE_DH))
            }
            CKM_TLS12_KEY_SAFE_DERIVE => String::from(stringify!(CKM_TLS12_KEY_SAFE_DERIVE)),
            CKM_TLS_MAC => String::from(stringify!(CKM_TLS_MAC)),
            CKM_TLS_KDF => String::from(stringify!(CKM_TLS_KDF)),
            CKM_KEY_WRAP_LYNKS => String::from(stringify!(CKM_KEY_WRAP_LYNKS)),
            CKM_KEY_WRAP_SET_OAEP => String::from(stringify!(CKM_KEY_WRAP_SET_OAEP)),
            CKM_CMS_SIG => String::from(stringify!(CKM_CMS_SIG)),
            CKM_KIP_DERIVE => String::from(stringify!(CKM_KIP_DERIVE)),
            CKM_KIP_WRAP => String::from(stringify!(CKM_KIP_WRAP)),
            CKM_KIP_MAC => String::from(stringify!(CKM_KIP_MAC)),
            CKM_CAMELLIA_KEY_GEN => String::from(stringify!(CKM_CAMELLIA_KEY_GEN)),
            CKM_CAMELLIA_CTR => String::from(stringify!(CKM_CAMELLIA_CTR)),
            CKM_ARIA_KEY_GEN => String::from(stringify!(CKM_ARIA_KEY_GEN)),
            CKM_ARIA_ECB => String::from(stringify!(CKM_ARIA_ECB)),
            CKM_ARIA_CBC => String::from(stringify!(CKM_ARIA_CBC)),
            CKM_ARIA_MAC => String::from(stringify!(CKM_ARIA_MAC)),
            CKM_ARIA_MAC_GENERAL => String::from(stringify!(CKM_ARIA_MAC_GENERAL)),
            CKM_ARIA_CBC_PAD => String::from(stringify!(CKM_ARIA_CBC_PAD)),
            CKM_ARIA_ECB_ENCRYPT_DATA => String::from(stringify!(CKM_ARIA_ECB_ENCRYPT_DATA)),
            CKM_ARIA_CBC_ENCRYPT_DATA => String::from(stringify!(CKM_ARIA_CBC_ENCRYPT_DATA)),
            CKM_SEED_KEY_GEN => String::from(stringify!(CKM_SEED_KEY_GEN)),
            CKM_SEED_ECB => String::from(stringify!(CKM_SEED_ECB)),
            CKM_SEED_CBC => String::from(stringify!(CKM_SEED_CBC)),
            CKM_SEED_MAC => String::from(stringify!(CKM_SEED_MAC)),
            CKM_SEED_MAC_GENERAL => String::from(stringify!(CKM_SEED_MAC_GENERAL)),
            CKM_SEED_CBC_PAD => String::from(stringify!(CKM_SEED_CBC_PAD)),
            CKM_SEED_ECB_ENCRYPT_DATA => String::from(stringify!(CKM_SEED_ECB_ENCRYPT_DATA)),
            CKM_SEED_CBC_ENCRYPT_DATA => String::from(stringify!(CKM_SEED_CBC_ENCRYPT_DATA)),
            CKM_SKIPJACK_KEY_GEN => String::from(stringify!(CKM_SKIPJACK_KEY_GEN)),
            CKM_SKIPJACK_ECB64 => String::from(stringify!(CKM_SKIPJACK_ECB64)),
            CKM_SKIPJACK_CBC64 => String::from(stringify!(CKM_SKIPJACK_CBC64)),
            CKM_SKIPJACK_OFB64 => String::from(stringify!(CKM_SKIPJACK_OFB64)),
            CKM_SKIPJACK_CFB64 => String::from(stringify!(CKM_SKIPJACK_CFB64)),
            CKM_SKIPJACK_CFB32 => String::from(stringify!(CKM_SKIPJACK_CFB32)),
            CKM_SKIPJACK_CFB16 => String::from(stringify!(CKM_SKIPJACK_CFB16)),
            CKM_SKIPJACK_CFB8 => String::from(stringify!(CKM_SKIPJACK_CFB8)),
            CKM_SKIPJACK_WRAP => String::from(stringify!(CKM_SKIPJACK_WRAP)),
            CKM_SKIPJACK_PRIVATE_WRAP => String::from(stringify!(CKM_SKIPJACK_PRIVATE_WRAP)),
            CKM_SKIPJACK_RELAYX => String::from(stringify!(CKM_SKIPJACK_RELAYX)),
            CKM_KEA_KEY_PAIR_GEN => String::from(stringify!(CKM_KEA_KEY_PAIR_GEN)),
            CKM_KEA_KEY_DERIVE => String::from(stringify!(CKM_KEA_KEY_DERIVE)),
            CKM_FORTEZZA_TIMESTAMP => String::from(stringify!(CKM_FORTEZZA_TIMESTAMP)),
            CKM_BATON_KEY_GEN => String::from(stringify!(CKM_BATON_KEY_GEN)),
            CKM_BATON_ECB128 => String::from(stringify!(CKM_BATON_ECB128)),
            CKM_BATON_ECB96 => String::from(stringify!(CKM_BATON_ECB96)),
            CKM_BATON_CBC128 => String::from(stringify!(CKM_BATON_CBC128)),
            CKM_BATON_COUNTER => String::from(stringify!(CKM_BATON_COUNTER)),
            CKM_BATON_SHUFFLE => String::from(stringify!(CKM_BATON_SHUFFLE)),
            CKM_BATON_WRAP => String::from(stringify!(CKM_BATON_WRAP)),
            CKM_EC_KEY_PAIR_GEN => String::from(stringify!(CKM_EC_KEY_PAIR_GEN)),
            CKM_ECDSA => String::from(stringify!(CKM_ECDSA)),
            CKM_ECDSA_SHA1 => String::from(stringify!(CKM_ECDSA_SHA1)),
            CKM_ECDSA_SHA224 => String::from(stringify!(CKM_ECDSA_SHA224)),
            CKM_ECDSA_SHA256 => String::from(stringify!(CKM_ECDSA_SHA256)),
            CKM_ECDSA_SHA384 => String::from(stringify!(CKM_ECDSA_SHA384)),
            CKM_ECDSA_SHA512 => String::from(stringify!(CKM_ECDSA_SHA512)),
            CKM_ECDH1_DERIVE => String::from(stringify!(CKM_ECDH1_DERIVE)),
            CKM_ECDH1_COFACTOR_DERIVE => String::from(stringify!(CKM_ECDH1_COFACTOR_DERIVE)),
            CKM_ECMQV_DERIVE => String::from(stringify!(CKM_ECMQV_DERIVE)),
            CKM_ECDH_AES_KEY_WRAP => String::from(stringify!(CKM_ECDH_AES_KEY_WRAP)),
            CKM_RSA_AES_KEY_WRAP => String::from(stringify!(CKM_RSA_AES_KEY_WRAP)),
            CKM_JUNIPER_KEY_GEN => String::from(stringify!(CKM_JUNIPER_KEY_GEN)),
            CKM_JUNIPER_ECB128 => String::from(stringify!(CKM_JUNIPER_ECB128)),
            CKM_JUNIPER_CBC128 => String::from(stringify!(CKM_JUNIPER_CBC128)),
            CKM_JUNIPER_COUNTER => String::from(stringify!(CKM_JUNIPER_COUNTER)),
            CKM_JUNIPER_SHUFFLE => String::from(stringify!(CKM_JUNIPER_SHUFFLE)),
            CKM_JUNIPER_WRAP => String::from(stringify!(CKM_JUNIPER_WRAP)),
            CKM_FASTHASH => String::from(stringify!(CKM_FASTHASH)),
            CKM_AES_KEY_GEN => String::from(stringify!(CKM_AES_KEY_GEN)),
            CKM_AES_ECB => String::from(stringify!(CKM_AES_ECB)),
            CKM_AES_CBC => String::from(stringify!(CKM_AES_CBC)),
            CKM_AES_MAC => String::from(stringify!(CKM_AES_MAC)),
            CKM_AES_MAC_GENERAL => String::from(stringify!(CKM_AES_MAC_GENERAL)),
            CKM_AES_CBC_PAD => String::from(stringify!(CKM_AES_CBC_PAD)),
            CKM_AES_CTR => String::from(stringify!(CKM_AES_CTR)),
            CKM_AES_GCM => String::from(stringify!(CKM_AES_GCM)),
            CKM_AES_CCM => String::from(stringify!(CKM_AES_CCM)),
            CKM_AES_CTS => String::from(stringify!(CKM_AES_CTS)),
            CKM_AES_CMAC => String::from(stringify!(CKM_AES_CMAC)),
            CKM_AES_CMAC_GENERAL => String::from(stringify!(CKM_AES_CMAC_GENERAL)),
            CKM_AES_XCBC_MAC => String::from(stringify!(CKM_AES_XCBC_MAC)),
            CKM_AES_XCBC_MAC_96 => String::from(stringify!(CKM_AES_XCBC_MAC_96)),
            CKM_AES_GMAC => String::from(stringify!(CKM_AES_GMAC)),
            CKM_BLOWFISH_KEY_GEN => String::from(stringify!(CKM_BLOWFISH_KEY_GEN)),
            CKM_BLOWFISH_CBC => String::from(stringify!(CKM_BLOWFISH_CBC)),
            CKM_TWOFISH_KEY_GEN => String::from(stringify!(CKM_TWOFISH_KEY_GEN)),
            CKM_TWOFISH_CBC => String::from(stringify!(CKM_TWOFISH_CBC)),
            CKM_BLOWFISH_CBC_PAD => String::from(stringify!(CKM_BLOWFISH_CBC_PAD)),
            CKM_TWOFISH_CBC_PAD => String::from(stringify!(CKM_TWOFISH_CBC_PAD)),
            CKM_DES_ECB_ENCRYPT_DATA => String::from(stringify!(CKM_DES_ECB_ENCRYPT_DATA)),
            CKM_DES_CBC_ENCRYPT_DATA => String::from(stringify!(CKM_DES_CBC_ENCRYPT_DATA)),
            CKM_DES3_ECB_ENCRYPT_DATA => String::from(stringify!(CKM_DES3_ECB_ENCRYPT_DATA)),
            CKM_DES3_CBC_ENCRYPT_DATA => String::from(stringify!(CKM_DES3_CBC_ENCRYPT_DATA)),
            CKM_AES_ECB_ENCRYPT_DATA => String::from(stringify!(CKM_AES_ECB_ENCRYPT_DATA)),
            CKM_AES_CBC_ENCRYPT_DATA => String::from(stringify!(CKM_AES_CBC_ENCRYPT_DATA)),
            CKM_GOSTR3410_KEY_PAIR_GEN => String::from(stringify!(CKM_GOSTR3410_KEY_PAIR_GEN)),
            CKM_GOSTR3410 => String::from(stringify!(CKM_GOSTR3410)),
            CKM_GOSTR3410_WITH_GOSTR3411 => String::from(stringify!(CKM_GOSTR3410_WITH_GOSTR3411)),
            CKM_GOSTR3410_KEY_WRAP => String::from(stringify!(CKM_GOSTR3410_KEY_WRAP)),
            CKM_GOSTR3410_DERIVE => String::from(stringify!(CKM_GOSTR3410_DERIVE)),
            CKM_GOSTR3411 => String::from(stringify!(CKM_GOSTR3411)),
            CKM_GOSTR3411_HMAC => String::from(stringify!(CKM_GOSTR3411_HMAC)),
            CKM_GOST28147_KEY_GEN => String::from(stringify!(CKM_GOST28147_KEY_GEN)),
            CKM_GOST28147_ECB => String::from(stringify!(CKM_GOST28147_ECB)),
            CKM_GOST28147 => String::from(stringify!(CKM_GOST28147)),
            CKM_GOST28147_MAC => String::from(stringify!(CKM_GOST28147_MAC)),
            CKM_GOST28147_KEY_WRAP => String::from(stringify!(CKM_GOST28147_KEY_WRAP)),
            CKM_DSA_PARAMETER_GEN => String::from(stringify!(CKM_DSA_PARAMETER_GEN)),
            CKM_DH_PKCS_PARAMETER_GEN => String::from(stringify!(CKM_DH_PKCS_PARAMETER_GEN)),
            CKM_X9_42_DH_PARAMETER_GEN => String::from(stringify!(CKM_X9_42_DH_PARAMETER_GEN)),
            CKM_DSA_PROBABLISTIC_PARAMETER_GEN => {
                String::from(stringify!(CKM_DSA_PROBABLISTIC_PARAMETER_GEN))
            }
            CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN => {
                String::from(stringify!(CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN))
            }
            CKM_AES_OFB => String::from(stringify!(CKM_AES_OFB)),
            CKM_AES_CFB64 => String::from(stringify!(CKM_AES_CFB64)),
            CKM_AES_CFB8 => String::from(stringify!(CKM_AES_CFB8)),
            CKM_AES_CFB128 => String::from(stringify!(CKM_AES_CFB128)),
            CKM_AES_CFB1 => String::from(stringify!(CKM_AES_CFB1)),
            CKM_VENDOR_DEFINED => String::from(stringify!(CKM_VENDOR_DEFINED)),
            CKM_SHA224 => String::from(stringify!(CKM_SHA224)),
            CKM_SHA224_HMAC => String::from(stringify!(CKM_SHA224_HMAC)),
            CKM_SHA224_HMAC_GENERAL => String::from(stringify!(CKM_SHA224_HMAC_GENERAL)),
            CKM_SHA224_RSA_PKCS => String::from(stringify!(CKM_SHA224_RSA_PKCS)),
            CKM_SHA224_RSA_PKCS_PSS => String::from(stringify!(CKM_SHA224_RSA_PKCS_PSS)),
            CKM_SHA224_KEY_DERIVATION => String::from(stringify!(CKM_SHA224_KEY_DERIVATION)),
            CKM_CAMELLIA_ECB => String::from(stringify!(CKM_CAMELLIA_ECB)),
            CKM_CAMELLIA_CBC => String::from(stringify!(CKM_CAMELLIA_CBC)),
            CKM_CAMELLIA_MAC => String::from(stringify!(CKM_CAMELLIA_MAC)),
            CKM_CAMELLIA_MAC_GENERAL => String::from(stringify!(CKM_CAMELLIA_MAC_GENERAL)),
            CKM_CAMELLIA_CBC_PAD => String::from(stringify!(CKM_CAMELLIA_CBC_PAD)),
            CKM_CAMELLIA_ECB_ENCRYPT_DATA => {
                String::from(stringify!(CKM_CAMELLIA_ECB_ENCRYPT_DATA))
            }
            CKM_CAMELLIA_CBC_ENCRYPT_DATA => {
                String::from(stringify!(CKM_CAMELLIA_CBC_ENCRYPT_DATA))
            }
            CKM_AES_KEY_WRAP => String::from(stringify!(CKM_AES_KEY_WRAP)),
            CKM_AES_KEY_WRAP_PAD => String::from(stringify!(CKM_AES_KEY_WRAP_PAD)),
            CKM_RSA_PKCS_TPM_1_1 => String::from(stringify!(CKM_RSA_PKCS_TPM_1_1)),
            CKM_RSA_PKCS_OAEP_TPM_1_1 => String::from(stringify!(CKM_RSA_PKCS_OAEP_TPM_1_1)),
            CKM_EC_EDWARDS_KEY_PAIR_GEN => String::from(stringify!(CKM_EC_EDWARDS_KEY_PAIR_GEN)),
            CKM_EC_MONTGOMERY_KEY_PAIR_GEN => {
                String::from(stringify!(CKM_EC_MONTGOMERY_KEY_PAIR_GEN))
            }
            _ => format!("unknown {:08x}", mech),
        }
    }
}

impl std::fmt::Display for MechanismType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", MechanismType::stringify(self.val))
    }
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
            CKM_AES_KEY_GEN => Ok(MechanismType::AES_KEY_GEN),
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
    // AES
    /// AES key gen mechanism
    AesKeyGen,
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
            Mechanism::AesKeyGen => MechanismType::AES_KEY_GEN,

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
            Mechanism::AesKeyGen
            | Mechanism::RsaPkcsKeyPairGen
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
