// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! PKCS11 General Data Types

use super::{SlotInfo, TokenInfo};
use cryptoki_sys::*;
use std::fmt::{self, Debug, Display, Formatter};

use crate::flag::*;

/// Collection of flags defined for [`CK_SLOT_INFO`]
pub(crate) const TOKEN_PRESENT: FlagBit<SlotInfo> = FlagBit::new(CKF_TOKEN_PRESENT);
pub(crate) const REMOVABLE_DEVICE: FlagBit<SlotInfo> = FlagBit::new(CKF_REMOVABLE_DEVICE);
pub(crate) const HW_SLOT: FlagBit<SlotInfo> = FlagBit::new(CKF_HW_SLOT);

impl Debug for CkFlags<SlotInfo> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Flags")
            .field("token_present", &(self.contains(TOKEN_PRESENT)))
            .field("removable_device", &(self.contains(REMOVABLE_DEVICE)))
            .field("hw_slot", &(self.contains(HW_SLOT)))
            .finish()
    }
}

impl Display for CkFlags<SlotInfo> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut set = f.debug_set();
        if self.contains(TOKEN_PRESENT) {
            let _ = set.entry(&"Token Present");
        }
        if self.contains(REMOVABLE_DEVICE) {
            let _ = set.entry(&"Removable Device");
        }
        if self.contains(HW_SLOT) {
            let _ = set.entry(&"Hardware Slot");
        }
        set.finish()
    }
}

pub(crate) const RNG: FlagBit<TokenInfo> = FlagBit::new(CKF_RNG);
pub(crate) const WRITE_PROTECTED: FlagBit<TokenInfo> = FlagBit::new(CKF_WRITE_PROTECTED);
pub(crate) const LOGIN_REQUIRED: FlagBit<TokenInfo> = FlagBit::new(CKF_LOGIN_REQUIRED);
pub(crate) const USER_PIN_INITIALIZED: FlagBit<TokenInfo> = FlagBit::new(CKF_USER_PIN_INITIALIZED);
pub(crate) const RESTORE_KEY_NOT_NEEDED: FlagBit<TokenInfo> =
    FlagBit::new(CKF_RESTORE_KEY_NOT_NEEDED);
pub(crate) const CLOCK_ON_TOKEN: FlagBit<TokenInfo> = FlagBit::new(CKF_CLOCK_ON_TOKEN);
pub(crate) const PROTECTED_AUTHENTICATION_PATH: FlagBit<TokenInfo> =
    FlagBit::new(CKF_PROTECTED_AUTHENTICATION_PATH);
pub(crate) const DUAL_CRYPTO_OPERATIONS: FlagBit<TokenInfo> =
    FlagBit::new(CKF_DUAL_CRYPTO_OPERATIONS);
pub(crate) const TOKEN_INITIALIZED: FlagBit<TokenInfo> = FlagBit::new(CKF_TOKEN_INITIALIZED);
pub(crate) const SECONDARY_AUTHENTICATION: FlagBit<TokenInfo> =
    FlagBit::new(CKF_SECONDARY_AUTHENTICATION);
pub(crate) const USER_PIN_COUNT_LOW: FlagBit<TokenInfo> = FlagBit::new(CKF_USER_PIN_COUNT_LOW);
pub(crate) const USER_PIN_FINAL_TRY: FlagBit<TokenInfo> = FlagBit::new(CKF_USER_PIN_FINAL_TRY);
pub(crate) const USER_PIN_LOCKED: FlagBit<TokenInfo> = FlagBit::new(CKF_USER_PIN_LOCKED);
pub(crate) const USER_PIN_TO_BE_CHANGED: FlagBit<TokenInfo> =
    FlagBit::new(CKF_USER_PIN_TO_BE_CHANGED);
pub(crate) const SO_PIN_COUNT_LOW: FlagBit<TokenInfo> = FlagBit::new(CKF_SO_PIN_COUNT_LOW);
pub(crate) const SO_PIN_FINAL_TRY: FlagBit<TokenInfo> = FlagBit::new(CKF_SO_PIN_FINAL_TRY);
pub(crate) const SO_PIN_LOCKED: FlagBit<TokenInfo> = FlagBit::new(CKF_SO_PIN_LOCKED);
pub(crate) const SO_PIN_TO_BE_CHANGED: FlagBit<TokenInfo> = FlagBit::new(CKF_SO_PIN_TO_BE_CHANGED);
pub(crate) const ERROR_STATE: FlagBit<TokenInfo> = FlagBit::new(CKF_ERROR_STATE);

impl Debug for CkFlags<TokenInfo> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Flags")
            .field("rng", &(self.contains(RNG)))
            .field("write_protected", &(self.contains(WRITE_PROTECTED)))
            .field("login_required", &(self.contains(LOGIN_REQUIRED)))
            .field(
                "user_pin_initialized",
                &(self.contains(USER_PIN_INITIALIZED)),
            )
            .field(
                "restore_key_not_needed",
                &(self.contains(RESTORE_KEY_NOT_NEEDED)),
            )
            .field("clock_on token", &(self.contains(CLOCK_ON_TOKEN)))
            .field(
                "protected_authentication_path",
                &(self.contains(PROTECTED_AUTHENTICATION_PATH)),
            )
            .field(
                "dual_crypto_operations",
                &(self.contains(DUAL_CRYPTO_OPERATIONS)),
            )
            .field("token_initialized", &(self.contains(TOKEN_INITIALIZED)))
            .field(
                "secondary_authentication",
                &(self.contains(SECONDARY_AUTHENTICATION)),
            )
            .field("user_pin_count_low", &(self.contains(USER_PIN_COUNT_LOW)))
            .field("user_pin_final_try", &(self.contains(USER_PIN_FINAL_TRY)))
            .field("user_pin_locked", &(self.contains(USER_PIN_LOCKED)))
            .field(
                "user_pin_to_be_changed",
                &(self.contains(USER_PIN_TO_BE_CHANGED)),
            )
            .field("so_pin_count_low", &(self.contains(SO_PIN_COUNT_LOW)))
            .field("so_pin_final_try", &(self.contains(SO_PIN_FINAL_TRY)))
            .field("so_pin_locked", &(self.contains(SO_PIN_LOCKED)))
            .field(
                "so_pin_to_be_changed",
                &(self.contains(SO_PIN_TO_BE_CHANGED)),
            )
            .field("error_state", &(self.contains(ERROR_STATE)))
            .finish()
    }
}

impl Display for CkFlags<TokenInfo> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut set = f.debug_set();
        if self.contains(RNG) {
            let _ = set.entry(&"Random Number Generator");
        }
        if self.contains(WRITE_PROTECTED) {
            let _ = set.entry(&"Write-Protected");
        }
        if self.contains(LOGIN_REQUIRED) {
            let _ = set.entry(&"Login Required");
        }
        if self.contains(USER_PIN_INITIALIZED) {
            let _ = set.entry(&"User Pin Initialized");
        }
        if self.contains(RESTORE_KEY_NOT_NEEDED) {
            let _ = set.entry(&"Restore Key Not Needed");
        }
        if self.contains(CLOCK_ON_TOKEN) {
            let _ = set.entry(&"Clock on Token");
        }
        if self.contains(PROTECTED_AUTHENTICATION_PATH) {
            let _ = set.entry(&"Protected Authentication Path");
        }
        if self.contains(DUAL_CRYPTO_OPERATIONS) {
            let _ = set.entry(&"Dual Crypto Operations");
        }
        if self.contains(TOKEN_INITIALIZED) {
            let _ = set.entry(&"Token Initialized");
        }
        if self.contains(SECONDARY_AUTHENTICATION) {
            let _ = set.entry(&"Secondary Authentication");
        }
        if self.contains(USER_PIN_COUNT_LOW) {
            let _ = set.entry(&"User PIN Count Low");
        }
        if self.contains(USER_PIN_FINAL_TRY) {
            let _ = set.entry(&"User PIN Final Try");
        }
        if self.contains(USER_PIN_LOCKED) {
            let _ = set.entry(&"User PIN Locked");
        }
        if self.contains(USER_PIN_TO_BE_CHANGED) {
            let _ = set.entry(&"User PIN to be Changed");
        }
        if self.contains(SO_PIN_COUNT_LOW) {
            let _ = set.entry(&"Security Officer PIN Count Low");
        }
        if self.contains(SO_PIN_FINAL_TRY) {
            let _ = set.entry(&"Security Officer PIN Final Try");
        }
        if self.contains(SO_PIN_LOCKED) {
            let _ = set.entry(&"Security Officer PIN Locked");
        }
        if self.contains(SO_PIN_TO_BE_CHANGED) {
            let _ = set.entry(&"Security Officer PIN to be Changed");
        }
        if self.contains(ERROR_STATE) {
            let _ = set.entry(&"Error State");
        }
        set.finish()
    }
}
