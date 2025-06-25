//! ECDH mechanism types

use crate::types::Ulong;
use cryptoki_sys::*;
use std::convert::TryInto;
use std::marker::PhantomData;
use std::ptr;

/// ECDH derivation parameters.
///
/// The elliptic curve Diffie-Hellman (ECDH) key derivation mechanism
/// is a mechanism for key derivation based on the Diffie-Hellman
/// version of the elliptic curve key agreement scheme, as defined in
/// ANSI X9.63, where each party contributes one key pair all using
/// the same EC domain parameters.
///
/// This structure wraps a `CK_ECDH1_DERIVE_PARAMS` structure.
#[derive(Copy, Debug, Clone)]
#[repr(C)]
pub struct Ecdh1DeriveParams<'a> {
    /// Key derivation function
    kdf: CK_EC_KDF_TYPE,
    /// Length of the optional shared data used by some of the key
    /// derivation functions
    shared_data_len: Ulong,
    /// Address of the optional data or `std::ptr::null()` of there is
    /// no shared data
    shared_data: *const u8,
    /// Length of the other party's public key
    public_data_len: Ulong,
    /// Pointer to the other party public key
    public_data: *const u8,
    /// Marker type to ensure we don't outlive shared and public data
    _marker: PhantomData<&'a [u8]>,
}

impl<'a> Ecdh1DeriveParams<'a> {
    /// Construct ECDH derivation parameters.
    ///
    /// # Arguments
    ///
    /// * `kdf` - The key derivation function to use.
    ///
    /// * `public_data` - The other party's public key.  A token MUST be able
    ///   to accept this value encoded as a raw octet string (as per section
    ///   A.5.2 of ANSI X9.62).  A token MAY, in addition, support accepting
    ///   this value as a DER-encoded `ECPoint` (as per section E.6 of ANSI
    ///   X9.62) i.e. the same as a `CKA_EC_POINT` encoding.  The calling
    ///   application is responsible for converting the offered public key to the
    ///   compressed or uncompressed forms of these encodings if the token does
    ///   not support the offered form.
    pub fn new(kdf: EcKdf<'a>, public_data: &'a [u8]) -> Self {
        Self {
            kdf: kdf.kdf_type,
            shared_data_len: kdf
                .shared_data
                .map_or(0, <[u8]>::len)
                .try_into()
                .expect("usize can not fit in CK_ULONG"),
            shared_data: kdf.shared_data.map_or(ptr::null(), <[u8]>::as_ptr),
            public_data_len: public_data
                .len()
                .try_into()
                .expect("usize can not fit in CK_ULONG"),
            public_data: public_data.as_ptr(),
            _marker: PhantomData,
        }
    }
}

/// Key Derivation Function applied to derive keying data from a shared secret.
///
/// The key derivation function will be used by the EC key agreement schemes.
///
/// The lifetime parameter represents the lifetime of the shared data used by
/// the KDF.  In the current version of this crate, only the null KDF is
/// supported, which takes no shared data.  Therefore `'a` can always be inferred
/// `'static`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcKdf<'a> {
    kdf_type: CK_EC_KDF_TYPE,
    shared_data: Option<&'a [u8]>,
}

macro_rules! ansi {
    { $func_name: ident, $algo: ident, $algo_name: literal } => {
        #[doc = "The key derivation function based on "]
        #[doc = $algo_name]
        #[doc = " as defined in the ANSI X9.63 standard. The
                 derived key is produced by concatenating hashes of
                 the shared value followed by 00000001, 00000002,
                 etc. until we find enough bytes to fill the
                 `CKA_VALUE_LEN` of the derived key."]
        pub fn $func_name(shared_data: &'a [u8]) -> Self {
            Self {
                kdf_type: $algo,
                shared_data: Some(shared_data),
            }
        }
    }
}

macro_rules! sp800 {
    { $func_name: ident, $algo: ident, $algo_name: literal } => {
        #[doc = "The key derivation function based on "]
        #[doc = $algo_name]
        #[doc = " as defined in the [NIST SP800-56A standard, revision
                 2](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf),
                 section 5.8.1.1. The derived key is produced by
                 concatenating hashes of 00000001, 00000002,
                 etc. followed by the shared value until we find
                 enough bytes to fill the `CKA_VALUE_LEN` of the
                 derived key."]
        pub fn $func_name(shared_data: &'a [u8]) -> Self {
            Self {
                kdf_type: $algo,
                shared_data: Some(shared_data),
            }
        }
    }
}

impl<'a> EcKdf<'a> {
    /// The null transformation. The derived key value is produced by
    /// taking bytes from the left of the agreed value. The new key
    /// size is limited to the size of the agreed value.
    pub fn null() -> Self {
        Self {
            kdf_type: CKD_NULL,
            shared_data: None,
        }
    }

    ansi!(sha1, CKD_SHA1_KDF, "SHA1");
    ansi!(sha224, CKD_SHA224_KDF, "SHA224");
    ansi!(sha256, CKD_SHA256_KDF, "SHA256");
    ansi!(sha384, CKD_SHA384_KDF, "SHA384");
    ansi!(sha512, CKD_SHA512_KDF, "SHA512");
    ansi!(sha3_224, CKD_SHA3_224_KDF, "SHA3_224");
    ansi!(sha3_256, CKD_SHA3_256_KDF, "SHA3_256");
    ansi!(sha3_384, CKD_SHA3_384_KDF, "SHA3_384");
    ansi!(sha3_512, CKD_SHA3_512_KDF, "SHA3_512");

    sp800!(sha1_sp800, CKD_SHA1_KDF_SP800, "SHA1");
    sp800!(sha224_sp800, CKD_SHA224_KDF_SP800, "SHA224");
    sp800!(sha256_sp800, CKD_SHA256_KDF_SP800, "SHA256");
    sp800!(sha384_sp800, CKD_SHA384_KDF_SP800, "SHA384");
    sp800!(sha512_sp800, CKD_SHA512_KDF_SP800, "SHA512");
    sp800!(sha3_224_sp800, CKD_SHA3_224_KDF_SP800, "SHA3_224");
    sp800!(sha3_256_sp800, CKD_SHA3_256_KDF_SP800, "SHA3_256");
    sp800!(sha3_384_sp800, CKD_SHA3_384_KDF_SP800, "SHA3_384");
    sp800!(sha3_512_sp800, CKD_SHA3_512_KDF_SP800, "SHA3_512");

    // The intention here is to be able to support other methods with
    // shared data, without it being a breaking change, by just adding
    // additional constructors here.
}
