// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! PKCS11 General Data Types

use cryptoki_sys::*;
use std::fmt::Formatter;

use super::MechanismInfo;
use crate::flag::{CkFlags, FlagBit};
use std::fmt::{self, Debug, Display};

pub(crate) const HW: FlagBit<MechanismInfo> = FlagBit::new(CKF_HW);
pub(crate) const ENCRYPT: FlagBit<MechanismInfo> = FlagBit::new(CKF_ENCRYPT);
pub(crate) const DECRYPT: FlagBit<MechanismInfo> = FlagBit::new(CKF_DECRYPT);
pub(crate) const DIGEST: FlagBit<MechanismInfo> = FlagBit::new(CKF_DIGEST);
pub(crate) const SIGN: FlagBit<MechanismInfo> = FlagBit::new(CKF_SIGN);
pub(crate) const SIGN_RECOVER: FlagBit<MechanismInfo> = FlagBit::new(CKF_SIGN_RECOVER);
pub(crate) const VERIFY: FlagBit<MechanismInfo> = FlagBit::new(CKF_VERIFY);
pub(crate) const VERIFY_RECOVER: FlagBit<MechanismInfo> = FlagBit::new(CKF_VERIFY_RECOVER);
pub(crate) const GENERATE: FlagBit<MechanismInfo> = FlagBit::new(CKF_GENERATE);
pub(crate) const GENERATE_KEY_PAIR: FlagBit<MechanismInfo> = FlagBit::new(CKF_GENERATE_KEY_PAIR);
pub(crate) const WRAP: FlagBit<MechanismInfo> = FlagBit::new(CKF_WRAP);
pub(crate) const UNWRAP: FlagBit<MechanismInfo> = FlagBit::new(CKF_UNWRAP);
pub(crate) const DERIVE: FlagBit<MechanismInfo> = FlagBit::new(CKF_DERIVE);
pub(crate) const EXTENSION: FlagBit<MechanismInfo> = FlagBit::new(CKF_EXTENSION);
pub(crate) const EC_F_P: FlagBit<MechanismInfo> = FlagBit::new(CKF_EC_F_P);
pub(crate) const EC_F_2M: FlagBit<MechanismInfo> = FlagBit::new(CKF_EC_F_2M);
pub(crate) const EC_ECPARAMETERS: FlagBit<MechanismInfo> = FlagBit::new(CKF_EC_ECPARAMETERS);
pub(crate) const EC_NAMEDCURVE: FlagBit<MechanismInfo> = FlagBit::new(CKF_EC_NAMEDCURVE);
pub(crate) const EC_UNCOMPRESS: FlagBit<MechanismInfo> = FlagBit::new(CKF_EC_UNCOMPRESS);
pub(crate) const EC_COMPRESS: FlagBit<MechanismInfo> = FlagBit::new(CKF_EC_COMPRESS);

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
