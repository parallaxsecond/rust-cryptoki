// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Mechanism info and associated flags

use cryptoki_sys::*;
use std::fmt::Formatter;

use crate::flag::{CkFlags, FlagBit};
use std::fmt::{self, Debug, Display};

const HW: FlagBit<MechanismInfo> = FlagBit::new(CKF_HW);
const ENCRYPT: FlagBit<MechanismInfo> = FlagBit::new(CKF_ENCRYPT);
const DECRYPT: FlagBit<MechanismInfo> = FlagBit::new(CKF_DECRYPT);
const DIGEST: FlagBit<MechanismInfo> = FlagBit::new(CKF_DIGEST);
const SIGN: FlagBit<MechanismInfo> = FlagBit::new(CKF_SIGN);
const SIGN_RECOVER: FlagBit<MechanismInfo> = FlagBit::new(CKF_SIGN_RECOVER);
const VERIFY: FlagBit<MechanismInfo> = FlagBit::new(CKF_VERIFY);
const VERIFY_RECOVER: FlagBit<MechanismInfo> = FlagBit::new(CKF_VERIFY_RECOVER);
const GENERATE: FlagBit<MechanismInfo> = FlagBit::new(CKF_GENERATE);
const GENERATE_KEY_PAIR: FlagBit<MechanismInfo> = FlagBit::new(CKF_GENERATE_KEY_PAIR);
const WRAP: FlagBit<MechanismInfo> = FlagBit::new(CKF_WRAP);
const UNWRAP: FlagBit<MechanismInfo> = FlagBit::new(CKF_UNWRAP);
const DERIVE: FlagBit<MechanismInfo> = FlagBit::new(CKF_DERIVE);
const EXTENSION: FlagBit<MechanismInfo> = FlagBit::new(CKF_EXTENSION);
const EC_F_P: FlagBit<MechanismInfo> = FlagBit::new(CKF_EC_F_P);
const EC_F_2M: FlagBit<MechanismInfo> = FlagBit::new(CKF_EC_F_2M);
const EC_ECPARAMETERS: FlagBit<MechanismInfo> = FlagBit::new(CKF_EC_ECPARAMETERS);
const EC_NAMEDCURVE: FlagBit<MechanismInfo> = FlagBit::new(CKF_EC_NAMEDCURVE);
const EC_UNCOMPRESS: FlagBit<MechanismInfo> = FlagBit::new(CKF_EC_UNCOMPRESS);
const EC_COMPRESS: FlagBit<MechanismInfo> = FlagBit::new(CKF_EC_COMPRESS);

impl Debug for CkFlags<MechanismInfo> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Flags")
            .field("hw", &(self.contains(HW)))
            .field("encrypt", &(self.contains(ENCRYPT)))
            .field("decrypt", &(self.contains(DECRYPT)))
            .field("digest", &(self.contains(DIGEST)))
            .field("sign", &(self.contains(SIGN)))
            .field("sign_recover", &(self.contains(SIGN_RECOVER)))
            .field("verify", &(self.contains(VERIFY)))
            .field("verify_recover", &(self.contains(VERIFY_RECOVER)))
            .field("generate", &(self.contains(GENERATE)))
            .field("generate_key_pair", &(self.contains(GENERATE_KEY_PAIR)))
            .field("wrap", &(self.contains(WRAP)))
            .field("unwrap", &(self.contains(UNWRAP)))
            .field("derive", &(self.contains(DERIVE)))
            .field("extension", &(self.contains(EXTENSION)))
            .field("ec_f_p", &(self.contains(EC_F_P)))
            .field("ec_f_2m", &(self.contains(EC_F_2M)))
            .field("ec_ecparameters", &(self.contains(EC_ECPARAMETERS)))
            .field("ec_namedcurve", &(self.contains(EC_NAMEDCURVE)))
            .field("ec_uncompress", &(self.contains(EC_UNCOMPRESS)))
            .field("ec_compress", &(self.contains(EC_COMPRESS)))
            .finish()
    }
}

impl Display for CkFlags<MechanismInfo> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut set = f.debug_set();
        if self.contains(HW) {
            let _ = set.entry(&"Hardware");
        } else {
            let _ = set.entry(&"Software");
        }

        if self.contains(ENCRYPT) {
            let _ = set.entry(&"Encrypts");
        }
        if self.contains(DECRYPT) {
            let _ = set.entry(&"Decrypts");
        }
        if self.contains(DIGEST) {
            let _ = set.entry(&"Digests");
        }
        if self.contains(SIGN) {
            let _ = set.entry(&"Signs");
        }
        if self.contains(SIGN_RECOVER) {
            let _ = set.entry(&"Signs into Data");
        }
        if self.contains(VERIFY) {
            let _ = set.entry(&"Verifies");
        }
        if self.contains(VERIFY_RECOVER) {
            let _ = set.entry(&"Verifies from Data");
        }
        if self.contains(GENERATE) {
            let _ = set.entry(&"Generates Keys");
        }
        if self.contains(GENERATE_KEY_PAIR) {
            let _ = set.entry(&"Generates Key Pairs");
        }
        if self.contains(WRAP) {
            let _ = set.entry(&"Wraps Keys");
        }
        if self.contains(UNWRAP) {
            let _ = set.entry(&"Unwraps Keys");
        }
        if self.contains(DERIVE) {
            let _ = set.entry(&"Derives Keyes");
        }
        if self.contains(EXTENSION) {
            let _ = set.entry(&"Flag Extensions");
        }
        if self.contains(EC_F_P) {
            let _ = set.entry(&"Supports ECs Over F_p");
        }
        if self.contains(EC_F_2M) {
            let _ = set.entry(&"Supports ECs Over F_2^m");
        }
        if self.contains(EC_ECPARAMETERS) {
            let _ = set.entry(&"Accepts EC as Parameters");
        }
        if self.contains(EC_NAMEDCURVE) {
            let _ = set.entry(&"Accepts EC by Name");
        }
        if self.contains(EC_UNCOMPRESS) {
            let _ = set.entry(&"Accepts Uncompressed EC Points");
        }
        if self.contains(EC_COMPRESS) {
            let _ = set.entry(&"Accepts Compressed EC Points");
        }
        set.finish()
    }
}

/// Contains information about a mechanism
#[derive(Debug, Clone, Copy, Default)]
pub struct MechanismInfo {
    min_key_size: usize,
    max_key_size: usize,
    flags: CkFlags<Self>,
}

#[doc(hidden)]
impl From<CK_MECHANISM_INFO> for MechanismInfo {
    fn from(val: CK_MECHANISM_INFO) -> Self {
        Self {
            min_key_size: val.ulMinKeySize as usize,
            max_key_size: val.ulMaxKeySize as usize,
            flags: CkFlags::from(val.flags),
        }
    }
}

impl MechanismInfo {
    /// The minimum size of the key for the mechanism
    ///
    /// **[Conformance](crate#conformance-notes):**
    /// Whether this is measured in bits or in bytes is mechanism-dependent
    pub fn min_key_size(&self) -> usize {
        self.min_key_size
    }

    /// The maximum size of the key for the mechanism
    ///
    /// **[Conformance](crate#conformance-notes):**
    /// Whether this is measured in bits or in bytes is mechanism-dependent
    pub fn max_key_size(&self) -> usize {
        self.max_key_size
    }

    /// True if the mechanism is performed by the device; false if the mechanism is performed in software
    pub fn hardware(&self) -> bool {
        self.flags.contains(HW)
    }

    /// True if the mechanism can be used to encrypt data
    ///
    /// See [`Session::encrypt`](crate::session::Session::encrypt)
    pub fn encrypt(&self) -> bool {
        self.flags.contains(ENCRYPT)
    }

    /// True if the mechanism can be used to decrypt encrypted data
    ///
    /// See [`Session::decrypt`](crate::session::Session::decrypt)
    pub fn decrypt(&self) -> bool {
        self.flags.contains(DECRYPT)
    }

    /// True if the mechanism can be used to digest a message
    ///
    // TODO See [`Session::digest`](crate::session::Session::digest)
    pub fn digest(&self) -> bool {
        self.flags.contains(DIGEST)
    }

    /// True if the mechanism can be used to digitally sign data
    ///
    /// See [`Session::sign`](crate::session::Session::sign)
    pub fn sign(&self) -> bool {
        self.flags.contains(SIGN)
    }

    /// True if the mechanism can be used to digitally data which can be recovered from the signature
    ///
    // TODO See [`Session::sign_recover`](crate::session::Session::sign_recover)
    pub fn sign_recover(&self) -> bool {
        self.flags.contains(SIGN_RECOVER)
    }

    /// True if the mechanism can be used to verify a digital signature
    ///
    /// See [`Session::verify`](crate::session::Session::verify)
    pub fn verify(&self) -> bool {
        self.flags.contains(VERIFY)
    }

    /// True if the mechanism can be used to [`verify`](crate::session::Session::verify) a digital signature and recover the signed data
    ///
    // TODO See [`Session::verify_recover`](crate::session::Session::verify_recover)
    pub fn verify_recover(&self) -> bool {
        self.flags.contains(VERIFY_RECOVER)
    }

    /// True if the mechanism can be used to generate a secret key
    ///
    // TODO See [`Session::generate`](crate::session::Session::generate)
    pub fn generate(&self) -> bool {
        self.flags.contains(GENERATE)
    }

    /// True if the mechanism can be used to generate a public/private key pair
    ///
    /// See [`Session::generate_key_pair`](crate::session::Session::generate_key_pair))
    pub fn generate_key_pair(&self) -> bool {
        self.flags.contains(GENERATE_KEY_PAIR)
    }

    /// True if the mechanism can be used to wrap (encrypt) a key
    ///
    // TODO See [`Session::wrap`](crate::session::Session::wrap))
    pub fn wrap(&self) -> bool {
        self.flags.contains(WRAP)
    }

    /// True if the mechanism can be used to unwrap (decrypt) a key
    ///
    // TODO See [`Session::unwrap`](crate::session::Session::unwrap))
    pub fn unwrap(&self) -> bool {
        self.flags.contains(UNWRAP)
    }

    /// True if the mechanism can be used to derive a key from a base key
    ///
    // TODO See [`Session::derive`](crate::session::Session::derive))
    pub fn derive(&self) -> bool {
        self.flags.contains(DERIVE)
    }

    /// True if there is an extension to the flags; false if no extensions
    ///
    /// **[Conformance](crate#conformance-notes):**
    /// This *must* be false for PKCS#11 v2.40
    pub fn extension(&self) -> bool {
        self.flags.contains(EXTENSION)
    }

    /// True if the mechanism can be used to  with elliptic curve domain parameters over ***F<sub>p</sub>***
    ///
    /// **[Conformance](crate#conformance-notes):**
    /// *At least* one of [`ec_f_p`](Self::ec_f_p) and [`ec_f_2m`](Self::ec_f_2m) must be `true`
    pub fn ec_f_p(&self) -> bool {
        self.flags.contains(EC_F_P)
    }

    /// True if the mechanism can be used with elliptic curve domain parameters over ***F<sub>2<sup>m</sup></sub>***
    ///
    /// **[Conformance](crate#conformance-notes):**
    /// *At least* one of [`ec_f_p`](Self::ec_f_p) and [`ec_f_2m`](Self::ec_f_2m) must be `true`
    pub fn ec_f_2m(&self) -> bool {
        self.flags.contains(EC_F_2M)
    }

    /// True if the mechanism supports specifying elliptic curve domain parameters explicitly
    ///
    /// **[Conformance](crate#conformance-notes):**
    /// *At least* one of [`ec_from_parameters`](Self::ec_from_parameters) and [`ec_from_named_curve`](Self::ec_from_named_curve) must be `true`
    pub fn ec_from_parameters(&self) -> bool {
        self.flags.contains(EC_ECPARAMETERS)
    }

    /// True if the mechanism supports specifying elliptic curve domain parameters with a named curve
    ///
    /// **[Conformance](crate#conformance-notes):**
    /// *At least* one of [`ec_from_parameters`](Self::ec_from_parameters) and [`ec_from_named_curve`](Self::ec_from_named_curve) must be `true`
    pub fn ec_from_named_curve(&self) -> bool {
        self.flags.contains(EC_NAMEDCURVE)
    }

    /// True if the mechanism can be used with elliptic curve points in uncompressed form
    ///
    /// **[Conformance](crate#conformance-notes):**
    /// *At least* one of [`ec_uncompressed`](Self::ec_uncompressed) and [`ec_compressed`](Self::ec_compressed) must be `true`
    pub fn ec_uncompressed(&self) -> bool {
        self.flags.contains(EC_UNCOMPRESS)
    }

    /// True if the mechanism can be used with elliptic curve points in compressed form
    ///
    /// **[Conformance](crate#conformance-notes):**
    /// *At least* one of [`ec_uncompressed`](Self::ec_uncompressed) and [`ec_compressed`](Self::ec_compressed) must be `true`
    pub fn ec_compressed(&self) -> bool {
        self.flags.contains(EC_COMPRESS)
    }
}
