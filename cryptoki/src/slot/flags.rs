// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! PKCS11 General Data Types

use crate::types::Flags;
use cryptoki_sys::*;
use std::fmt::Formatter;

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
