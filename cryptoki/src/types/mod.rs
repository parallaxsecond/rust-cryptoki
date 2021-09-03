// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! PKCS11 General Data Types

pub mod function;
pub mod locking;
pub mod mechanism;
pub mod object;
pub mod session;
pub mod slot_token;

use crate::{string_from_blank_padded, Error, Result};
use cryptoki_sys::*;
use log::error;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt::Formatter;
use std::ops::Deref;

trait Flags: std::fmt::Display {
    type FlagType: Copy;

    fn flag_value(&self) -> Self::FlagType;

    fn flag(&self, flag: Self::FlagType) -> bool;

    fn set_flag(&mut self, flag: Self::FlagType, b: bool);

    fn stringify_flag(flag: Self::FlagType) -> &'static str;

    fn stringify_fmt(&self, f: &mut Formatter<'_>, flags: Vec<Self::FlagType>) -> std::fmt::Result {
        let mut first_done = false;
        for flag in flags.iter() {
            if self.flag(*flag) {
                if first_done {
                    write!(f, ", ")?;
                }
                write!(f, "{}", Self::stringify_flag(*flag))?;
                first_done = true;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy)]
/// Collection of flags defined for [`CK_C_INITIALIZE_ARGS`]
pub struct InitializeFlags {
    flags: CK_FLAGS,
}

impl Flags for InitializeFlags {
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
            CKF_LIBRARY_CANT_CREATE_OS_THREADS => {
                std::stringify!(CKF_LIBRARY_CANT_CREATE_OS_THREADS)
            }
            CKF_OS_LOCKING_OK => std::stringify!(CKF_OS_LOCKING_OK),
            _ => "Unknown CK_C_INITIALIZE_ARGS flag",
        }
    }
}

impl InitializeFlags {
    /// Creates a new instance of `InitializeFlags` with no flags set
    pub fn new() -> Self {
        InitializeFlags::default()
    }

    /// Gets value of [`CKF_LIBRARY_CANT_CREATE_OS_THREADS`]
    pub fn library_cant_create_os_threads(&self) -> bool {
        self.flag(CKF_LIBRARY_CANT_CREATE_OS_THREADS)
    }

    /// Sets value of [`CKF_LIBRARY_CANT_CREATE_OS_THREADS`]
    pub fn set_library_cant_create_os_threads(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_LIBRARY_CANT_CREATE_OS_THREADS, b);
        self
    }

    /// Gets value of [`CKF_OS_LOCKING_OK`]
    pub fn os_locking_ok(&self) -> bool {
        self.flag(CKF_OS_LOCKING_OK)
    }

    /// Sets value of [`CKF_OS_LOCKING_OK`]
    pub fn set_os_locking_ok(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_OS_LOCKING_OK, b);
        self
    }
}

impl std::fmt::Display for InitializeFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let flags = vec![CKF_LIBRARY_CANT_CREATE_OS_THREADS, CKF_OS_LOCKING_OK];
        self.stringify_fmt(f, flags)
    }
}

impl From<InitializeFlags> for CK_FLAGS {
    fn from(flags: InitializeFlags) -> Self {
        flags.flags
    }
}

impl From<CK_FLAGS> for InitializeFlags {
    fn from(flags: CK_FLAGS) -> Self {
        Self { flags }
    }
}

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

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
/// Collection of flags defined for [`CK_SESSION_INFO`]
pub struct SessionFlags {
    flags: CK_FLAGS,
}

impl Flags for SessionFlags {
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

    fn stringify_flag(flag: Self::FlagType) -> &'static str {
        match flag {
            CKF_RW_SESSION => std::stringify!(CKF_RW_SESSION),
            CKF_SERIAL_SESSION => std::stringify!(CKF_SERIAL_SESSION),
            _ => "Unknown session flag",
        }
    }
}

impl SessionFlags {
    /// Creates a new instance of `SessionFlags` with no flags set
    pub fn new() -> Self {
        SessionFlags::default()
    }

    /// Gets value of [`CKF_RW_SESSION`]
    pub fn rw_session(&self) -> bool {
        self.flag(CKF_RW_SESSION)
    }

    /// Sets value of [`CKF_RW_SESSION`]
    pub fn set_rw_session(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_RW_SESSION, b);
        self
    }

    /// Gets value of [`CKF_SERIAL_SESSION`]
    pub fn serial_session(&self) -> bool {
        self.flag(CKF_SERIAL_SESSION)
    }

    /// Sets value of [`CKF_SERIAL_SESSION`]
    pub fn set_serial_session(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SERIAL_SESSION, b);
        self
    }
}

impl std::fmt::Display for SessionFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let flags = vec![CKF_RW_SESSION, CKF_SERIAL_SESSION];
        self.stringify_fmt(f, flags)
    }
}

impl From<SessionFlags> for CK_FLAGS {
    fn from(flags: SessionFlags) -> Self {
        flags.flags
    }
}

impl From<CK_FLAGS> for SessionFlags {
    fn from(flags: CK_FLAGS) -> Self {
        Self { flags }
    }
}

#[derive(Debug, Default, Clone, Copy)]
/// Collection of flags defined for [`CK_SLOT_INFO`]
pub struct SlotFlags {
    flags: CK_FLAGS,
}

impl Flags for SlotFlags {
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

    fn stringify_flag(flag: Self::FlagType) -> &'static str {
        match flag {
            CKF_TOKEN_PRESENT => std::stringify!(CKF_TOKEN_PRESENT),
            CKF_REMOVABLE_DEVICE => std::stringify!(CKF_REMOVABLE_DEVICE),
            CKF_HW_SLOT => std::stringify!(CKF_HW_SLOT),
            _ => "Unknown CK_SLOT_INFO flag",
        }
    }
}

impl SlotFlags {
    /// Creates a new instance of `SlotFlags` with no flags set
    pub fn new() -> Self {
        SlotFlags::default()
    }

    /// Gets value of [`CKF_TOKEN_PRESENT`]
    pub fn token_present(&self) -> bool {
        self.flag(CKF_TOKEN_PRESENT)
    }

    /// Sets value of [`CKF_TOKEN_PRESENT`]
    pub fn set_token_present(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_TOKEN_PRESENT, b);
        self
    }

    /// Gets value of [`CKF_REMOVABLE_DEVICE`]
    pub fn removable_device(&self) -> bool {
        self.flag(CKF_REMOVABLE_DEVICE)
    }

    /// Sets value of [`CKF_REMOVABLE_DEVICE`]
    pub fn set_removable_device(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_REMOVABLE_DEVICE, b);
        self
    }

    /// Gets value of [`CKF_HW_SLOT`]
    pub fn hardware_slot(&self) -> bool {
        self.flag(CKF_HW_SLOT)
    }

    /// Sets value of [`CKF_HW_SLOT`]
    pub fn set_hardware_slot(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_HW_SLOT, b);
        self
    }
}

impl std::fmt::Display for SlotFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let flags = vec![CKF_TOKEN_PRESENT, CKF_REMOVABLE_DEVICE, CKF_HW_SLOT];
        self.stringify_fmt(f, flags)
    }
}

impl From<SlotFlags> for CK_FLAGS {
    fn from(flags: SlotFlags) -> Self {
        flags.flags
    }
}

impl From<CK_FLAGS> for SlotFlags {
    fn from(flags: CK_FLAGS) -> Self {
        Self { flags }
    }
}

#[derive(Debug, Default, Clone, Copy)]
/// Collection of flags defined for [`CK_TOKEN_INFO`]
pub struct TokenFlags {
    flags: CK_FLAGS,
}

impl Flags for TokenFlags {
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

    fn stringify_flag(flag: Self::FlagType) -> &'static str {
        match flag {
            CKF_RNG => std::stringify!(CKF_RNG),
            CKF_WRITE_PROTECTED => std::stringify!(CKF_WRITE_PROTECTED),
            CKF_LOGIN_REQUIRED => std::stringify!(CKF_LOGIN_REQUIRED),
            CKF_USER_PIN_INITIALIZED => std::stringify!(CKF_USER_PIN_INITIALIZED),
            CKF_RESTORE_KEY_NOT_NEEDED => std::stringify!(CKF_RESTORE_KEY_NOT_NEEDED),
            CKF_CLOCK_ON_TOKEN => std::stringify!(CKF_CLOCK_ON_TOKEN),
            CKF_PROTECTED_AUTHENTICATION_PATH => std::stringify!(CKF_PROTECTED_AUTHENTICATION_PATH),
            CKF_DUAL_CRYPTO_OPERATIONS => std::stringify!(CKF_DUAL_CRYPTO_OPERATIONS),
            CKF_TOKEN_INITIALIZED => std::stringify!(CKF_TOKEN_INITIALIZED),
            CKF_SECONDARY_AUTHENTICATION => std::stringify!(CKF_SECONDARY_AUTHENTICATION),
            CKF_USER_PIN_COUNT_LOW => std::stringify!(CKF_USER_PIN_COUNT_LOW),
            CKF_USER_PIN_FINAL_TRY => std::stringify!(CKF_USER_PIN_FINAL_TRY),
            CKF_USER_PIN_LOCKED => std::stringify!(CKF_USER_PIN_LOCKED),
            CKF_USER_PIN_TO_BE_CHANGED => std::stringify!(CKF_USER_PIN_TO_BE_CHANGED),
            CKF_SO_PIN_COUNT_LOW => std::stringify!(CKF_SO_PIN_COUNT_LOW),
            CKF_SO_PIN_FINAL_TRY => std::stringify!(CKF_SO_PIN_FINAL_TRY),
            CKF_SO_PIN_LOCKED => std::stringify!(CKF_SO_PIN_LOCKED),
            CKF_SO_PIN_TO_BE_CHANGED => std::stringify!(CKF_SO_PIN_TO_BE_CHANGED),
            _ => "Unknown CK_TOKEN_INFO flag",
        }
    }
}

impl TokenFlags {
    /// Creates a new instance of `TokenFlags` with no flags set
    pub fn new() -> Self {
        TokenFlags::default()
    }

    /// Gets value of [`CKF_RNG`]
    pub fn random_number_generator(&self) -> bool {
        self.flag(CKF_RNG)
    }

    /// Sets value of [`CKF_RNG`]
    pub fn set_random_number_generator(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_RNG, b);
        self
    }

    /// Gets value of [`CKF_WRITE_PROTECTED`]
    pub fn write_protected(&self) -> bool {
        self.flag(CKF_WRITE_PROTECTED)
    }

    /// Sets value of [`CKF_WRITE_PROTECTED`]
    pub fn set_write_protected(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_WRITE_PROTECTED, b);
        self
    }

    /// Gets value of [`CKF_LOGIN_REQUIRED`]
    pub fn login_required(&self) -> bool {
        self.flag(CKF_LOGIN_REQUIRED)
    }

    /// Sets value of [`CKF_LOGIN_REQUIRED`]
    pub fn set_login_required(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_LOGIN_REQUIRED, b);
        self
    }

    /// Gets value of [`CKF_USER_PIN_INITIALIZED`]
    pub fn user_pin_initialized(&self) -> bool {
        self.flag(CKF_USER_PIN_INITIALIZED)
    }

    /// Sets value of [`CKF_USER_PIN_INITIALIZED`]
    pub fn set_user_pin_initialized(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_USER_PIN_INITIALIZED, b);
        self
    }

    /// Gets value of [`CKF_RESTORE_KEY_NOT_NEEDED`]
    pub fn restore_key_not_needed(&self) -> bool {
        self.flag(CKF_RESTORE_KEY_NOT_NEEDED)
    }

    /// Sets value of [`CKF_RESTORE_KEY_NOT_NEEDED`]
    pub fn set_restore_key_not_needed(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_RESTORE_KEY_NOT_NEEDED, b);
        self
    }

    /// Gets value of [`CKF_CLOCK_ON_TOKEN`]
    pub fn clock_on_token(&self) -> bool {
        self.flag(CKF_CLOCK_ON_TOKEN)
    }

    /// Sets value of [`CKF_CLOCK_ON_TOKEN`]
    pub fn set_clock_on_token(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_CLOCK_ON_TOKEN, b);
        self
    }

    /// Gets value of [`CKF_PROTECTED_AUTHENTICATION_PATH`]
    pub fn protected_authentication_path(&self) -> bool {
        self.flag(CKF_PROTECTED_AUTHENTICATION_PATH)
    }

    /// Sets value of [`CKF_PROTECTED_AUTHENTICATION_PATH`]
    pub fn set_protected_authentication_path(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_PROTECTED_AUTHENTICATION_PATH, b);
        self
    }

    /// Gets value of [`CKF_DUAL_CRYPTO_OPERATIONS`]
    pub fn dual_crypto_operations(&self) -> bool {
        self.flag(CKF_DUAL_CRYPTO_OPERATIONS)
    }

    /// Sets value of [`CKF_DUAL_CRYPTO_OPERATIONS`]
    pub fn set_dual_crypto_operations(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_DUAL_CRYPTO_OPERATIONS, b);
        self
    }

    /// Gets value of [`CKF_TOKEN_INITIALIZED`]
    pub fn token_initialized(&self) -> bool {
        self.flag(CKF_TOKEN_INITIALIZED)
    }

    /// Sets value of [`CKF_TOKEN_INITIALIZED`]
    pub fn set_token_initialized(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_TOKEN_INITIALIZED, b);
        self
    }

    /// Gets value of [`CKF_SECONDARY_AUTHENTICATION`]
    pub fn secondary_authentication(&self) -> bool {
        self.flag(CKF_SECONDARY_AUTHENTICATION)
    }

    /// Sets value of [`CKF_SECONDARY_AUTHENTICATION`]
    pub fn set_secondary_authentication(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SECONDARY_AUTHENTICATION, b);
        self
    }

    /// Gets value of [`CKF_USER_PIN_COUNT_LOW`]
    pub fn user_pin_count_low(&self) -> bool {
        self.flag(CKF_USER_PIN_COUNT_LOW)
    }

    /// Sets value of [`CKF_USER_PIN_COUNT_LOW`]
    pub fn set_user_pin_count_low(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_USER_PIN_COUNT_LOW, b);
        self
    }

    /// Gets value of [`CKF_USER_PIN_FINAL_TRY`]
    pub fn user_pin_final_try(&self) -> bool {
        self.flag(CKF_USER_PIN_FINAL_TRY)
    }

    /// Sets value of [`CKF_USER_PIN_FINAL_TRY`]
    pub fn set_user_pin_final_try(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_USER_PIN_FINAL_TRY, b);
        self
    }

    /// Gets value of [`CKF_USER_PIN_LOCKED`]
    pub fn user_pin_locked(&self) -> bool {
        self.flag(CKF_USER_PIN_LOCKED)
    }

    /// Sets value of [`CKF_USER_PIN_LOCKED`]
    pub fn set_user_pin_locked(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_USER_PIN_LOCKED, b);
        self
    }

    /// Gets value of [`CKF_USER_PIN_TO_BE_CHANGED`]
    pub fn user_pin_to_be_changed(&self) -> bool {
        self.flag(CKF_USER_PIN_TO_BE_CHANGED)
    }

    /// Sets value of [`CKF_USER_PIN_TO_BE_CHANGED`]
    pub fn set_user_pin_to_be_changed(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_USER_PIN_TO_BE_CHANGED, b);
        self
    }

    /// Gets value of [`CKF_SO_PIN_COUNT_LOW`]
    pub fn so_pin_count_low(&self) -> bool {
        self.flag(CKF_SO_PIN_COUNT_LOW)
    }

    /// Sets value of [`CKF_SO_PIN_COUNT_LOW`]
    pub fn set_so_pin_count_low(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SO_PIN_COUNT_LOW, b);
        self
    }

    /// Gets value of [`CKF_SO_PIN_FINAL_TRY`]
    pub fn so_pin_final_try(&self) -> bool {
        self.flag(CKF_SO_PIN_FINAL_TRY)
    }

    /// Sets value of [`CKF_SO_PIN_FINAL_TRY`]
    pub fn set_so_pin_final_try(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SO_PIN_FINAL_TRY, b);
        self
    }

    /// Gets value of [`CKF_SO_PIN_LOCKED`]
    pub fn so_pin_locked(&self) -> bool {
        self.flag(CKF_SO_PIN_LOCKED)
    }

    /// Sets value of [`CKF_SO_PIN_LOCKED`]
    pub fn set_so_pin_locked(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SO_PIN_LOCKED, b);
        self
    }

    /// Gets value of [`CKF_SO_PIN_TO_BE_CHANGED`]
    pub fn so_pin_to_be_changed(&self) -> bool {
        self.flag(CKF_SO_PIN_TO_BE_CHANGED)
    }

    /// Sets value of [`CKF_SO_PIN_TO_BE_CHANGED`]
    pub fn set_so_pin_to_be_changed(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SO_PIN_TO_BE_CHANGED, b);
        self
    }
}

impl std::fmt::Display for TokenFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let flags = vec![
            CKF_RNG,
            CKF_WRITE_PROTECTED,
            CKF_LOGIN_REQUIRED,
            CKF_USER_PIN_INITIALIZED,
            CKF_RESTORE_KEY_NOT_NEEDED,
            CKF_CLOCK_ON_TOKEN,
            CKF_PROTECTED_AUTHENTICATION_PATH,
            CKF_DUAL_CRYPTO_OPERATIONS,
            CKF_TOKEN_INITIALIZED,
            CKF_SECONDARY_AUTHENTICATION,
            CKF_USER_PIN_COUNT_LOW,
            CKF_USER_PIN_FINAL_TRY,
            CKF_USER_PIN_LOCKED,
            CKF_USER_PIN_TO_BE_CHANGED,
            CKF_SO_PIN_COUNT_LOW,
            CKF_SO_PIN_FINAL_TRY,
            CKF_SO_PIN_LOCKED,
            CKF_SO_PIN_TO_BE_CHANGED,
        ];
        self.stringify_fmt(f, flags)
    }
}

impl From<TokenFlags> for CK_FLAGS {
    fn from(flags: TokenFlags) -> Self {
        flags.flags
    }
}

impl From<CK_FLAGS> for TokenFlags {
    fn from(flags: CK_FLAGS) -> Self {
        Self { flags }
    }
}

#[repr(u8)]
#[derive(Debug, Copy, Clone)]
/// Byte-sized boolean
pub enum Bbool {
    /// False value
    False = 0,
    /// True value
    True = 1,
}

impl TryFrom<&[u8]> for Bbool {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self> {
        CK_BBOOL::from_ne_bytes(slice.try_into()?).try_into()
    }
}

impl From<Bbool> for CK_BBOOL {
    fn from(bbool: Bbool) -> Self {
        bbool as CK_BBOOL
    }
}

impl From<bool> for Bbool {
    fn from(val: bool) -> Self {
        if val {
            Bbool::True
        } else {
            Bbool::False
        }
    }
}

impl TryFrom<CK_BBOOL> for Bbool {
    type Error = Error;

    fn try_from(bbool: CK_BBOOL) -> Result<Self> {
        match bbool {
            CK_FALSE => Ok(Bbool::False),
            CK_TRUE => Ok(Bbool::True),
            other => {
                error!("Bbool value {} is invalid.", other);
                Err(Error::InvalidValue)
            }
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
/// Unsigned value, at least 32 bits long
pub struct Ulong {
    val: CK_ULONG,
}

impl Deref for Ulong {
    type Target = CK_ULONG;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

impl From<Ulong> for CK_ULONG {
    fn from(ulong: Ulong) -> Self {
        *ulong
    }
}

impl From<CK_ULONG> for Ulong {
    fn from(ulong: CK_ULONG) -> Self {
        Ulong { val: ulong }
    }
}

impl TryFrom<usize> for Ulong {
    type Error = Error;

    fn try_from(ulong: usize) -> Result<Self> {
        Ok(Ulong {
            val: ulong.try_into()?,
        })
    }
}

impl std::fmt::Display for Ulong {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.val)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// Represents a version
pub struct Version {
    major: CK_BYTE,
    minor: CK_BYTE,
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl Version {
    /// Returns the major version
    pub fn major(&self) -> CK_BYTE {
        self.major
    }

    /// Returns the minor version
    pub fn minor(&self) -> CK_BYTE {
        self.minor
    }
}

impl From<Version> for CK_VERSION {
    fn from(version: Version) -> Self {
        CK_VERSION {
            major: version.major,
            minor: version.minor,
        }
    }
}

impl From<CK_VERSION> for Version {
    fn from(version: CK_VERSION) -> Self {
        Version {
            major: version.major,
            minor: version.minor,
        }
    }
}

#[derive(Debug, Clone, Copy)]
/// Type identifying the PKCS#11 library information
pub struct Info {
    val: CK_INFO,
}

impl Info {
    pub(crate) fn new(val: CK_INFO) -> Self {
        Self { val }
    }

    /// Returns the version of Cryptoki that the library is compatible with
    pub fn cryptoki_version(&self) -> Version {
        self.val.cryptokiVersion.into()
    }

    /// Returns the flags of the library (should be zero!)
    pub fn flags(&self) -> CK_FLAGS {
        self.val.flags
    }

    /// Returns the description of the library
    pub fn library_description(&self) -> String {
        string_from_blank_padded(&self.val.libraryDescription)
    }

    /// Returns the version of the library
    pub fn library_version(&self) -> Version {
        self.val.libraryVersion.into()
    }

    /// Returns the manufacturer of the library
    pub fn manufacturer_id(&self) -> String {
        string_from_blank_padded(&self.val.manufacturerID)
    }
}

impl Deref for Info {
    type Target = CK_INFO;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

impl From<Info> for CK_INFO {
    fn from(info: Info) -> Self {
        *info
    }
}
