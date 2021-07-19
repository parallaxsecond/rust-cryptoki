// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! PKCS11 General Data Types

pub mod function;
pub mod locking;
pub mod mechanism;
pub mod object;
pub mod session;
pub mod slot_token;

use crate::{Error, Result};
use cryptoki_sys::*;
use log::error;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::ops::Deref;

#[derive(Debug, Default, Clone, Copy)]
/// Collection of boolean flags
pub struct Flags {
    flags: CK_FLAGS,
}

impl Flags {
    /// Create a new instance with all flags set to false
    pub fn new() -> Self {
        Flags::default()
    }

    fn get_flag(&self, flag: CK_FLAGS) -> bool {
        self.flags & flag == flag
    }

    fn set_flag(&mut self, flag: CK_FLAGS, b: bool) {
        if b {
            self.flags |= flag;
        } else {
            self.flags &= !flag;
        }
    }

    /// Get the TOKEN_PRESENT flag
    pub fn token_present(&self) -> bool {
        self.get_flag(CKF_TOKEN_PRESENT)
    }

    /// Set the TOKEN_PRESENT flag
    pub fn set_token_present(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_TOKEN_PRESENT, b);
        self
    }

    /// Get the REMOVABLE_DEVICE flag
    pub fn removable_device(&self) -> bool {
        self.get_flag(CKF_REMOVABLE_DEVICE)
    }

    /// Set the REMOVABLE_DEVICE flag
    pub fn set_removable_device(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_REMOVABLE_DEVICE, b);
        self
    }

    /// Get the HW_SLOT flag
    pub fn hw_slot(&self) -> bool {
        self.get_flag(CKF_HW_SLOT)
    }

    /// Set the HW_SLOT flag
    pub fn set_hw_slot(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_HW_SLOT, b);
        self
    }

    /// Get the ARRAY_ATTRIBUTE flag
    pub fn array_attribute(&self) -> bool {
        self.get_flag(CKF_ARRAY_ATTRIBUTE)
    }

    /// Set the ARRAY_ATTRIBUTE flag
    pub fn set_array_attribute(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_ARRAY_ATTRIBUTE, b);
        self
    }

    /// Get the RNG flag
    pub fn rng(&self) -> bool {
        self.get_flag(CKF_RNG)
    }

    /// Set the RNG flag
    pub fn set_rng(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_RNG, b);
        self
    }

    /// Get the WRITE_PROTECTED flag
    pub fn write_protected(&self) -> bool {
        self.get_flag(CKF_WRITE_PROTECTED)
    }

    /// Set the WRITE_PROTECTED flag
    pub fn set_write_protected(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_WRITE_PROTECTED, b);
        self
    }

    /// Get the LOGIN_REQUIRED flag
    pub fn login_required(&self) -> bool {
        self.get_flag(CKF_LOGIN_REQUIRED)
    }

    /// Set the LOGIN_REQUIRED flag
    pub fn set_login_required(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_LOGIN_REQUIRED, b);
        self
    }

    /// Get the USER_PIN_INITIALIZED flag
    pub fn user_pin_initialized(&self) -> bool {
        self.get_flag(CKF_USER_PIN_INITIALIZED)
    }

    /// Set the USER_PIN_INITIALIZED flag
    pub fn set_user_pin_initialized(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_USER_PIN_INITIALIZED, b);
        self
    }

    /// Get the RESTORE_KEY_NOT_NEEDED flag
    pub fn restore_key_not_needed(&self) -> bool {
        self.get_flag(CKF_RESTORE_KEY_NOT_NEEDED)
    }

    /// Set the RESTORE_KEY_NOT_NEEDED flag
    pub fn set_restore_key_not_needed(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_RESTORE_KEY_NOT_NEEDED, b);
        self
    }

    /// Get the CLOCK_ON_TOKEN flag
    pub fn clock_on_token(&self) -> bool {
        self.get_flag(CKF_CLOCK_ON_TOKEN)
    }

    /// Set the CLOCK_ON_TOKEN flag
    pub fn set_clock_on_token(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_CLOCK_ON_TOKEN, b);
        self
    }

    /// Get the PROTECTED_AUTHENTICATION flag
    pub fn protected_authentication_path(&self) -> bool {
        self.get_flag(CKF_PROTECTED_AUTHENTICATION_PATH)
    }

    /// Set the PROTECTED_AUTHENTICATION flag
    pub fn set_protected_authentication_path(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_PROTECTED_AUTHENTICATION_PATH, b);
        self
    }

    /// Get the DUAL_CRYPTO_OPERATIONS flag
    pub fn dual_crypto_operations(&self) -> bool {
        self.get_flag(CKF_DUAL_CRYPTO_OPERATIONS)
    }

    /// Set the DUAL_CRYPTO_OPERATIONS flag
    pub fn set_dual_crypto_operations(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_DUAL_CRYPTO_OPERATIONS, b);
        self
    }

    /// Get the TOKEN_INITIALIZED flag
    pub fn token_initialized(&self) -> bool {
        self.get_flag(CKF_TOKEN_INITIALIZED)
    }

    /// Set the TOKEN_INITIALIZED flag
    pub fn set_token_initialized(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_TOKEN_INITIALIZED, b);
        self
    }

    /// Get the SECONDARY_AUTHENTICATION flag
    pub fn secondary_authentication(&self) -> bool {
        self.get_flag(CKF_SECONDARY_AUTHENTICATION)
    }

    /// Set the SECONDARY_AUTHENTICATION flag
    pub fn set_secondary_authentication(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SECONDARY_AUTHENTICATION, b);
        self
    }

    /// Get the USER_PIN_COUNT_LOW flag
    pub fn user_pin_count_low(&self) -> bool {
        self.get_flag(CKF_USER_PIN_COUNT_LOW)
    }

    /// Set the USER_PIN_COUNT_LOW flag
    pub fn set_user_pin_count_low(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_USER_PIN_COUNT_LOW, b);
        self
    }

    /// Get the USER_PIN_FINAL_TRY flag
    pub fn user_pin_final_try(&self) -> bool {
        self.get_flag(CKF_USER_PIN_FINAL_TRY)
    }

    /// Set the USER_PIN_FINAL_TRY flag
    pub fn set_user_pin_final_try(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_USER_PIN_FINAL_TRY, b);
        self
    }

    /// Get the USER_PIN_LOCKED flag
    pub fn user_pin_locked(&self) -> bool {
        self.get_flag(CKF_USER_PIN_LOCKED)
    }

    /// Set the USER_PIN_LOCKED flag
    pub fn set_user_pin_locked(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_USER_PIN_LOCKED, b);
        self
    }

    /// Get the USER_PIN_TO_BE_CHANGED flag
    pub fn user_pin_to_be_changed(&self) -> bool {
        self.get_flag(CKF_USER_PIN_TO_BE_CHANGED)
    }

    /// Set the USER_PIN_TO_BE_CHANGED flag
    pub fn set_user_pin_to_be_changed(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_USER_PIN_TO_BE_CHANGED, b);
        self
    }

    /// Get the SO_PIN_COUNT_LOW flag
    pub fn so_pin_count_low(&self) -> bool {
        self.get_flag(CKF_SO_PIN_COUNT_LOW)
    }

    /// Set the SO_PIN_COUNT_LOW flag
    pub fn set_so_pin_count_low(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SO_PIN_COUNT_LOW, b);
        self
    }

    /// Get the SO_PIN_FINAL_TRY flag
    pub fn so_pin_final_try(&self) -> bool {
        self.get_flag(CKF_SO_PIN_FINAL_TRY)
    }

    /// Set the SO_PIN_FINAL_TRY flag
    pub fn set_so_pin_final_try(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SO_PIN_FINAL_TRY, b);
        self
    }

    /// Get the SO_PIN_LOCKED flag
    pub fn so_pin_locked(&self) -> bool {
        self.get_flag(CKF_SO_PIN_LOCKED)
    }

    /// Set the SO_PIN_LOCKED flag
    pub fn set_so_pin_locked(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SO_PIN_LOCKED, b);
        self
    }

    /// Get the SO_PIN_TO_BE_CHANGED flag
    pub fn so_pin_to_be_changed(&self) -> bool {
        self.get_flag(CKF_SO_PIN_TO_BE_CHANGED)
    }

    /// Set the SO_PIN_TO_BE_CHANGED flag
    pub fn set_so_pin_to_be_changed(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SO_PIN_TO_BE_CHANGED, b);
        self
    }

    /// Get the RW_SESSION flag
    pub fn rw_session(&self) -> bool {
        self.get_flag(CKF_RW_SESSION)
    }

    /// Set the RW_SESSION flag
    pub fn set_rw_session(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_RW_SESSION, b);
        self
    }

    /// Get the SERIAL_SESSION flag
    pub fn serial_session(&self) -> bool {
        self.get_flag(CKF_SERIAL_SESSION)
    }

    /// Set the SERIAL_SESSION flag
    pub fn set_serial_session(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SERIAL_SESSION, b);
        self
    }

    /// Get the NEXT_OTP flag
    pub fn next_otp(&self) -> bool {
        self.get_flag(CKF_NEXT_OTP)
    }

    /// Set the NEXT_OTP flag
    pub fn set_next_otp(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_NEXT_OTP, b);
        self
    }

    /// Get the EXCLUDE_TIME flag
    pub fn exclude_time(&self) -> bool {
        self.get_flag(CKF_EXCLUDE_TIME)
    }

    /// Set the EXCLUDE_TIME flag
    pub fn set_exclude_time(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EXCLUDE_TIME, b);
        self
    }

    /// Get the EXCLUDE_COUNTER flag
    pub fn exclude_counter(&self) -> bool {
        self.get_flag(CKF_EXCLUDE_COUNTER)
    }

    /// Set the EXCLUDE_COUNTER flag
    pub fn set_exclude_counter(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EXCLUDE_COUNTER, b);
        self
    }

    /// Get the EXCLUDE_CHALLENGE flag
    pub fn exclude_challenge(&self) -> bool {
        self.get_flag(CKF_EXCLUDE_CHALLENGE)
    }

    /// Set the EXCLUDE_CHALLENGE flag
    pub fn set_exclude_challenge(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EXCLUDE_CHALLENGE, b);
        self
    }

    /// Get the EXCLUDE_PIN flag
    pub fn exclude_pin(&self) -> bool {
        self.get_flag(CKF_EXCLUDE_PIN)
    }

    /// Set the EXCLUDE_PIN flag
    pub fn set_exclude_pin(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EXCLUDE_PIN, b);
        self
    }

    /// Get the USER_FRIENDLY_OTP flag
    pub fn user_friendly_otp(&self) -> bool {
        self.get_flag(CKF_USER_FRIENDLY_OTP)
    }

    /// Set the USER_FRIENDLY_OTP flag
    pub fn set_user_friendly_otp(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_USER_FRIENDLY_OTP, b);
        self
    }

    /// Get the HW flag
    pub fn hw(&self) -> bool {
        self.get_flag(CKF_HW)
    }

    /// Set the HW flag
    pub fn set_hw(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_HW, b);
        self
    }

    /// Get the ENCRYPT flag
    pub fn encrypt(&self) -> bool {
        self.get_flag(CKF_ENCRYPT)
    }

    /// Set the ENCRYPT flag
    pub fn set_encrypt(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_ENCRYPT, b);
        self
    }

    /// Get the DECRYPT flag
    pub fn decrypt(&self) -> bool {
        self.get_flag(CKF_DECRYPT)
    }

    /// Set the DECRYPT flag
    pub fn set_decrypt(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_DECRYPT, b);
        self
    }

    /// Get the DIGEST flag
    pub fn digest(&self) -> bool {
        self.get_flag(CKF_DIGEST)
    }

    /// Set the DIGEST flag
    pub fn set_digest(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_DIGEST, b);
        self
    }

    /// Get the SIGN flag
    pub fn sign(&self) -> bool {
        self.get_flag(CKF_SIGN)
    }

    /// Set the SIGN flag
    pub fn set_sign(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SIGN, b);
        self
    }

    /// Get the SIGN_RECOVER flag
    pub fn sign_recover(&self) -> bool {
        self.get_flag(CKF_SIGN_RECOVER)
    }

    /// Set the SIGN_RECOVER flag
    pub fn set_sign_recover(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SIGN_RECOVER, b);
        self
    }

    /// Get the VERIFY flag
    pub fn verify(&self) -> bool {
        self.get_flag(CKF_VERIFY)
    }

    /// Set the VERIFY flag
    pub fn set_verify(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_VERIFY, b);
        self
    }

    /// Get the VERIFY_RECOVER flag
    pub fn verify_recover(&self) -> bool {
        self.get_flag(CKF_VERIFY_RECOVER)
    }

    /// Set the VERIFY_RECOVER flag
    pub fn set_verify_recover(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_VERIFY_RECOVER, b);
        self
    }

    /// Get the GENERATE flag
    pub fn generate(&self) -> bool {
        self.get_flag(CKF_GENERATE)
    }

    /// Set the GENERATE flag
    pub fn set_generate(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_GENERATE, b);
        self
    }

    /// Get the GENERATE_KEY_PAIR flag
    pub fn generate_key_pair(&self) -> bool {
        self.get_flag(CKF_GENERATE_KEY_PAIR)
    }

    /// Set the GENERATE_KEY_PAIR flag
    pub fn set_generate_key_pair(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_GENERATE_KEY_PAIR, b);
        self
    }

    /// Get the WRAP flag
    pub fn wrap(&self) -> bool {
        self.get_flag(CKF_WRAP)
    }

    /// Set the WRAP flag
    pub fn set_wrap(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_WRAP, b);
        self
    }

    /// Get the UNWRAP flag
    pub fn unwrap(&self) -> bool {
        self.get_flag(CKF_UNWRAP)
    }

    /// Set the UNWRAP flag
    pub fn set_unwrap(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_UNWRAP, b);
        self
    }

    /// Get the DERIVE flag
    pub fn derive(&self) -> bool {
        self.get_flag(CKF_DERIVE)
    }

    /// Set the DERIVE flag
    pub fn set_derive(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_DERIVE, b);
        self
    }

    /// Get the EXTENSION flag
    pub fn extension(&self) -> bool {
        self.get_flag(CKF_EXTENSION)
    }

    /// Set the EXTENSION flag
    pub fn set_extension(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EXTENSION, b);
        self
    }

    /// Get the EC_F_P flag
    pub fn ec_f_p(&self) -> bool {
        self.get_flag(CKF_EC_F_P)
    }

    /// Set the EC_F_P flag
    pub fn set_ec_f_p(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EC_F_P, b);
        self
    }

    /// Get the EC_NAMEDCURVE flag
    pub fn ec_namedcurve(&self) -> bool {
        self.get_flag(CKF_EC_NAMEDCURVE)
    }

    /// Set the EC_NAMEDCURVE flag
    pub fn set_ec_namedcurve(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EC_NAMEDCURVE, b);
        self
    }

    /// Get the EC_UNCOMPRESS flag
    pub fn ec_uncompress(&self) -> bool {
        self.get_flag(CKF_EC_UNCOMPRESS)
    }

    /// Set the EC_UNCOMPRESS flag
    pub fn set_ec_uncompress(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EC_UNCOMPRESS, b);
        self
    }

    /// Get the EC_COMPRESS flag
    pub fn ec_compress(&self) -> bool {
        self.get_flag(CKF_EC_COMPRESS)
    }

    /// Set the EC_COMPRESS flag
    pub fn set_ec_compress(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EC_COMPRESS, b);
        self
    }

    /// Get the DONT_BLOCK flag
    pub fn dont_block(&self) -> bool {
        self.get_flag(CKF_DONT_BLOCK)
    }

    /// Set the DONT_BLOCK flag
    pub fn set_dont_block(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_DONT_BLOCK, b);
        self
    }

    /// Get the LIBRARY_CANT_CREATE_OS_THREADS flag
    pub fn library_cant_create_os_threads(&self) -> bool {
        self.get_flag(CKF_LIBRARY_CANT_CREATE_OS_THREADS)
    }

    /// Set the LIBRARY_CANT_CREATE_OS_THREADS flag
    pub fn set_library_cant_create_os_threads(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_LIBRARY_CANT_CREATE_OS_THREADS, b);
        self
    }

    /// Get the OS_LOCKING_OK flag
    pub fn os_locking_ok(&self) -> bool {
        self.get_flag(CKF_OS_LOCKING_OK)
    }

    /// Set the OS_LOCKING_OK flag
    pub fn set_os_locking_ok(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_OS_LOCKING_OK, b);
        self
    }
}

impl From<Flags> for CK_FLAGS {
    fn from(flags: Flags) -> Self {
        flags.flags
    }
}

impl From<CK_FLAGS> for Flags {
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
