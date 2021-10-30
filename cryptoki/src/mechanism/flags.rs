// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! PKCS11 General Data Types

use cryptoki_sys::*;
use std::fmt::Formatter;
use crate::types::Flags;

#[derive(Debug, Default, Clone, Copy)]
/// Collection of flags defined for [`CK_MECHANISM_INFO`]
pub struct MechanismFlags {
    flags: CK_FLAGS,
}

impl Flags for MechanismFlags {
    type FlagType = CK_FLAGS;

    fn flag_value(&self) -> Self::FlagType {
        self.flags
    }

    fn flag(&self, flag: Self::FlagType) -> bool {
        self.flag_value() & flag == flag
    }

    fn set_flag(&mut self, flag: Self::FlagType, b: bool) {
        if b {
            self.flags |= flag;
        } else {
            self.flags &= !flag;
        }
    }

    fn stringify_flag(flag: CK_FLAGS) -> &'static str {
        match flag {
            CKF_HW => std::stringify!(CKF_HW),
            CKF_ENCRYPT => std::stringify!(CKF_ENCRYPT),
            CKF_DECRYPT => std::stringify!(CKF_DECRYPT),
            CKF_DIGEST => std::stringify!(CKF_DIGEST),
            CKF_SIGN => std::stringify!(CKF_SIGN),
            CKF_SIGN_RECOVER => std::stringify!(CKF_SIGN_RECOVER),
            CKF_VERIFY => std::stringify!(CKF_VERIFY),
            CKF_VERIFY_RECOVER => std::stringify!(CKF_VERIFY_RECOVER),
            CKF_GENERATE => std::stringify!(CKF_GENERATE),
            CKF_GENERATE_KEY_PAIR => std::stringify!(CKF_GENERATE_KEY_PAIR),
            CKF_WRAP => std::stringify!(CKF_WRAP),
            CKF_UNWRAP => std::stringify!(CKF_UNWRAP),
            CKF_DERIVE => std::stringify!(CKF_DERIVE),
            CKF_EXTENSION => std::stringify!(CKF_EXTENSION),
            CKF_EC_F_P => std::stringify!(CKF_EC_F_P),
            CKF_EC_NAMEDCURVE => std::stringify!(CKF_EC_NAMEDCURVE),
            CKF_EC_UNCOMPRESS => std::stringify!(CKF_EC_UNCOMPRESS),
            CKF_EC_COMPRESS => std::stringify!(CKF_EC_COMPRESS),
            _ => "Unknown CK_MECHANISM_INFO flag",
        }
    }
}

impl MechanismFlags {
    /// Creates a new instance of `MechanismFlags` with no flags set
    pub fn new() -> Self {
        MechanismFlags::default()
    }

    /// Gets value of [`CKF_HW`]
    pub fn hardware(&self) -> bool {
        self.flag(CKF_HW)
    }

    /// Sets value of [`CKF_HW`]
    pub fn set_hardware(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_HW, b);
        self
    }

    /// Gets value of [`CKF_ENCRYPT`]
    pub fn encrypt(&self) -> bool {
        self.flag(CKF_ENCRYPT)
    }

    /// Sets value of [`CKF_ENCRYPT`]
    pub fn set_encrypt(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_ENCRYPT, b);
        self
    }

    /// Gets value of [`CKF_DECRYPT`]
    pub fn decrypt(&self) -> bool {
        self.flag(CKF_DECRYPT)
    }

    /// Sets value of [`CKF_DECRYPT`]
    pub fn set_decrypt(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_DECRYPT, b);
        self
    }

    /// Gets value of [`CKF_DIGEST`]
    pub fn digest(&self) -> bool {
        self.flag(CKF_DIGEST)
    }

    /// Sets value of [`CKF_DIGEST`]
    pub fn set_digest(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_DIGEST, b);
        self
    }

    /// Gets value of [`CKF_SIGN`]
    pub fn sign(&self) -> bool {
        self.flag(CKF_SIGN)
    }

    /// Sets value of [`CKF_SIGN`]
    pub fn set_sign(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SIGN, b);
        self
    }

    /// Gets value of [`CKF_SIGN_RECOVER`]
    pub fn sign_recover(&self) -> bool {
        self.flag(CKF_SIGN_RECOVER)
    }

    /// Sets value of [`CKF_SIGN_RECOVER`]
    pub fn set_sign_recover(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SIGN_RECOVER, b);
        self
    }

    /// Gets value of [`CKF_VERIFY`]
    pub fn verify(&self) -> bool {
        self.flag(CKF_VERIFY)
    }

    /// Sets value of [`CKF_VERIFY`]
    pub fn set_verify(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_VERIFY, b);
        self
    }

    /// Gets value of [`CKF_VERIFY_RECOVER`]
    pub fn verify_recover(&self) -> bool {
        self.flag(CKF_VERIFY_RECOVER)
    }

    /// Sets value of [`CKF_VERIFY_RECOVER`]
    pub fn set_verify_recover(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_VERIFY_RECOVER, b);
        self
    }

    /// Gets value of [`CKF_GENERATE`]
    pub fn generate(&self) -> bool {
        self.flag(CKF_GENERATE)
    }

    /// Sets value of [`CKF_GENERATE`]
    pub fn set_generate(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_GENERATE, b);
        self
    }

    /// Gets value of [`CKF_GENERATE_KEY_PAIR`]
    pub fn generate_key_pair(&self) -> bool {
        self.flag(CKF_GENERATE_KEY_PAIR)
    }

    /// Sets value of [`CKF_GENERATE_KEY_PAIR`]
    pub fn set_generate_key_pair(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_GENERATE_KEY_PAIR, b);
        self
    }

    /// Gets value of [`CKF_WRAP`]
    pub fn wrap(&self) -> bool {
        self.flag(CKF_WRAP)
    }

    /// Sets value of [`CKF_WRAP`]
    pub fn set_wrap(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_WRAP, b);
        self
    }

    /// Gets value of [`CKF_UNWRAP`]
    pub fn unwrap(&self) -> bool {
        self.flag(CKF_UNWRAP)
    }

    /// Sets value of [`CKF_UNWRAP`]
    pub fn set_unwrap(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_UNWRAP, b);
        self
    }

    /// Gets value of [`CKF_DERIVE`]
    pub fn derive(&self) -> bool {
        self.flag(CKF_DERIVE)
    }

    /// Sets value of [`CKF_DERIVE`]
    pub fn set_derive(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_DERIVE, b);
        self
    }

    /// Gets value of [`CKF_EXTENSION`]
    pub fn extension(&self) -> bool {
        self.flag(CKF_EXTENSION)
    }

    /// Sets value of [`CKF_EXTENSION`]
    pub fn set_extension(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EXTENSION, b);
        self
    }

    /// Gets value of [`CKF_EC_F_P`]
    pub fn ec_f_p(&self) -> bool {
        self.flag(CKF_EC_F_P)
    }

    /// Sets value of [`CKF_EC_F_P`]
    pub fn set_ec_f_p(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EC_F_P, b);
        self
    }

    /// Gets value of [`CKF_EC_NAMEDCURVE`]
    pub fn ec_namedcurve(&self) -> bool {
        self.flag(CKF_EC_NAMEDCURVE)
    }

    /// Sets value of [`CKF_EC_NAMEDCURVE`]
    pub fn set_ec_namedcurve(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EC_NAMEDCURVE, b);
        self
    }

    /// Gets value of [`CKF_EC_UNCOMPRESS`]
    pub fn ec_uncompress(&self) -> bool {
        self.flag(CKF_EC_UNCOMPRESS)
    }

    /// Sets value of [`CKF_EC_UNCOMPRESS`]
    pub fn set_ec_uncompress(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EC_UNCOMPRESS, b);
        self
    }

    /// Gets value of [`CKF_EC_COMPRESS`]
    pub fn ec_compress(&self) -> bool {
        self.flag(CKF_EC_COMPRESS)
    }

    /// Sets value of [`CKF_EC_COMPRESS`]
    pub fn set_ec_compress(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EC_COMPRESS, b);
        self
    }
}

impl std::fmt::Display for MechanismFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let flags = vec![
            CKF_HW,
            CKF_ENCRYPT,
            CKF_DECRYPT,
            CKF_DIGEST,
            CKF_SIGN,
            CKF_SIGN_RECOVER,
            CKF_VERIFY,
            CKF_VERIFY_RECOVER,
            CKF_GENERATE,
            CKF_GENERATE_KEY_PAIR,
            CKF_WRAP,
            CKF_UNWRAP,
            CKF_DERIVE,
            CKF_EXTENSION,
            CKF_EC_F_P,
            CKF_EC_NAMEDCURVE,
            CKF_EC_UNCOMPRESS,
            CKF_EC_COMPRESS,
        ];
        self.stringify_fmt(f, flags)
    }
}

impl From<MechanismFlags> for CK_FLAGS {
    fn from(flags: MechanismFlags) -> Self {
        flags.flags
    }
}

impl From<CK_FLAGS> for MechanismFlags {
    fn from(flags: CK_FLAGS) -> Self {
        Self { flags }
    }
}
