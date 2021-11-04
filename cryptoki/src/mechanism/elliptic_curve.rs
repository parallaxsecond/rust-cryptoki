//! ECDH mechanism types

use crate::error::{Error, Result};
use crate::types::Ulong;
use cryptoki_sys::*;
use log::error;
use std::convert::TryFrom;
use std::ffi::c_void;
use std::ops::Deref;

/// ECDH derivation parameters.
///
/// The elliptic curve Diffie-Hellman (ECDH) key derivation mechanism
/// is a mechanism for key derivation based on the Diffie-Hellman
/// version of the elliptic curve key agreement scheme, as defined in
/// ANSI X9.63, where each party contributes one key pair all using
/// the same EC domain parameters.
///
/// This structure wraps CK_ECDH1_DERIVE_PARAMS structure.
#[derive(Copy, Debug, Clone)]
#[repr(C)]
pub struct Ecdh1DeriveParams {
    /// Key derivation function
    pub kdf: EcKdfType,
    /// Length of the optional shared data used by some of the key
    /// derivation functions
    pub shared_data_len: Ulong,
    /// Address of the optional data or `std::ptr::null()` of there is
    /// no shared data
    pub shared_data: *const c_void,
    /// Length of the other party's public key
    pub public_data_len: Ulong,
    /// Pointer to the other party public key
    pub public_data: *const c_void,
}

/// Key Derivation Function applied to derive keying data from a shared secret.
///
/// The key derivation function will be used by the EC key agreement schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct EcKdfType {
    val: CK_EC_KDF_TYPE,
}

impl EcKdfType {
    /// The null transformation. The derived key value is produced by
    /// taking bytes from the left of the agreed value. The new key
    /// size is limited to the size of the agreed value.
    pub const NULL: EcKdfType = EcKdfType { val: CKD_NULL };
}

impl Deref for EcKdfType {
    type Target = CK_EC_KDF_TYPE;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

impl From<EcKdfType> for CK_EC_KDF_TYPE {
    fn from(ec_kdf_type: EcKdfType) -> Self {
        *ec_kdf_type
    }
}

impl TryFrom<CK_EC_KDF_TYPE> for EcKdfType {
    type Error = Error;

    fn try_from(ec_kdf_type: CK_EC_KDF_TYPE) -> Result<Self> {
        match ec_kdf_type {
            CKD_NULL => Ok(EcKdfType::NULL),
            other => {
                error!(
                    "Key derivation function type {} is not one of the valid values.",
                    other
                );
                Err(Error::InvalidValue)
            }
        }
    }
}
