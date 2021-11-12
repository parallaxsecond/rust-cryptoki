// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! PKCS11 Token info and associated flags

use cryptoki_sys::*;
use std::fmt::{self, Debug, Display, Formatter};

use crate::flag::{CkFlags, FlagBit};
use crate::string_from_blank_padded;
use crate::types::{maybe_unlimited, MaybeUnavailable, Version};

const RNG: FlagBit<TokenInfo> = FlagBit::new(CKF_RNG);
const WRITE_PROTECTED: FlagBit<TokenInfo> = FlagBit::new(CKF_WRITE_PROTECTED);
const LOGIN_REQUIRED: FlagBit<TokenInfo> = FlagBit::new(CKF_LOGIN_REQUIRED);
const USER_PIN_INITIALIZED: FlagBit<TokenInfo> = FlagBit::new(CKF_USER_PIN_INITIALIZED);
const RESTORE_KEY_NOT_NEEDED: FlagBit<TokenInfo> = FlagBit::new(CKF_RESTORE_KEY_NOT_NEEDED);
const CLOCK_ON_TOKEN: FlagBit<TokenInfo> = FlagBit::new(CKF_CLOCK_ON_TOKEN);
const PROTECTED_AUTHENTICATION_PATH: FlagBit<TokenInfo> =
    FlagBit::new(CKF_PROTECTED_AUTHENTICATION_PATH);
const DUAL_CRYPTO_OPERATIONS: FlagBit<TokenInfo> = FlagBit::new(CKF_DUAL_CRYPTO_OPERATIONS);
const TOKEN_INITIALIZED: FlagBit<TokenInfo> = FlagBit::new(CKF_TOKEN_INITIALIZED);
const SECONDARY_AUTHENTICATION: FlagBit<TokenInfo> = FlagBit::new(CKF_SECONDARY_AUTHENTICATION);
const USER_PIN_COUNT_LOW: FlagBit<TokenInfo> = FlagBit::new(CKF_USER_PIN_COUNT_LOW);
const USER_PIN_FINAL_TRY: FlagBit<TokenInfo> = FlagBit::new(CKF_USER_PIN_FINAL_TRY);
const USER_PIN_LOCKED: FlagBit<TokenInfo> = FlagBit::new(CKF_USER_PIN_LOCKED);
const USER_PIN_TO_BE_CHANGED: FlagBit<TokenInfo> = FlagBit::new(CKF_USER_PIN_TO_BE_CHANGED);
const SO_PIN_COUNT_LOW: FlagBit<TokenInfo> = FlagBit::new(CKF_SO_PIN_COUNT_LOW);
const SO_PIN_FINAL_TRY: FlagBit<TokenInfo> = FlagBit::new(CKF_SO_PIN_FINAL_TRY);
const SO_PIN_LOCKED: FlagBit<TokenInfo> = FlagBit::new(CKF_SO_PIN_LOCKED);
const SO_PIN_TO_BE_CHANGED: FlagBit<TokenInfo> = FlagBit::new(CKF_SO_PIN_TO_BE_CHANGED);
const ERROR_STATE: FlagBit<TokenInfo> = FlagBit::new(CKF_ERROR_STATE);

impl Debug for CkFlags<TokenInfo> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
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

/// Contains information about a token
#[derive(Debug, Clone)]
pub struct TokenInfo {
    label: String,           // 32
    manufacturer_id: String, // 32
    model: String,           // 16
    serial_number: String,   // 16
    flags: CkFlags<Self>,
    max_session_count: Option<Option<u64>>,
    session_count: Option<u64>,
    max_rw_session_count: Option<Option<u64>>,
    rw_session_count: Option<u64>,
    max_pin_len: usize,
    min_pin_len: usize,
    total_public_memory: Option<usize>,
    free_public_memory: Option<usize>,
    total_private_memory: Option<usize>,
    free_private_memory: Option<usize>,
    hardware_version: Version,
    firmware_version: Version,
    utc_time: String,
}

#[doc(hidden)]
impl From<CK_TOKEN_INFO> for TokenInfo {
    fn from(val: CK_TOKEN_INFO) -> Self {
        Self {
            label: string_from_blank_padded(&val.label),
            manufacturer_id: string_from_blank_padded(&val.manufacturerID),
            model: string_from_blank_padded(&val.model),
            serial_number: string_from_blank_padded(&val.serialNumber),
            flags: CkFlags::from(val.flags),
            max_session_count: maybe_unlimited(val.ulMaxSessionCount),
            session_count: u64::maybe_unavailable(val.ulSessionCount),
            max_rw_session_count: maybe_unlimited(val.ulMaxRwSessionCount),
            rw_session_count: u64::maybe_unavailable(val.ulRwSessionCount),
            max_pin_len: val.ulMaxPinLen as usize,
            min_pin_len: val.ulMinPinLen as usize,
            total_public_memory: usize::maybe_unavailable(val.ulTotalPublicMemory),
            free_public_memory: usize::maybe_unavailable(val.ulFreePublicMemory),
            total_private_memory: usize::maybe_unavailable(val.ulTotalPrivateMemory),
            free_private_memory: usize::maybe_unavailable(val.ulFreePrivateMemory),
            hardware_version: val.hardwareVersion.into(),
            firmware_version: val.firmwareVersion.into(),
            // UTC time is not blank padded as it has the format YYYYMMDDhhmmssxx where
            // x is the '0' character
            utc_time: String::from_utf8_lossy(&val.utcTime).trim_end().to_string(),
        }
    }
}

impl TokenInfo {
    /// An application-defined label, assigned during token initialization
    ///
    /// **[Conformance](crate#conformance-notes):**
    /// This string is maximally 32 bytes (*not* chars) as UTF-8
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The ID of the device manufacturer
    ///
    /// **[Conformance](crate#conformance-notes):**
    /// This string is maximally 32 bytes (*not* chars) as UTF-8
    pub fn manufacturer_id(&self) -> &str {
        &self.manufacturer_id
    }

    /// The model of the device
    ///
    /// **[Conformance](crate#conformance-notes):**
    /// This string is maximally 16 bytes (*not* chars) as UTF-8
    pub fn model(&self) -> &str {
        &self.model
    }

    /// The character-string serial number of the device
    ///
    /// **[Conformance](crate#conformance-notes):**
    /// This string is maximally 16 bytes (*not* chars) as UTF-8
    pub fn serial_number(&self) -> &str {
        &self.serial_number
    }

    /// True if the token has its own random number generator
    pub fn rng(&self) -> bool {
        self.flags.contains(RNG)
    }

    /// True if the token is write-protected
    ///
    /// **[Conformance](crate#conformance-notes):**
    /// Exaclty what this value means is determined by the application. An
    /// application may be unable to perform certain actions on a write-
    /// protected token. These actions can include any of the following (non-
    /// exhaustive):
    /// * Creating/modifying/deleting any object on the token
    /// * Creating/modifying/deleting a token object on the token
    /// * Changing the Security Officer's PIN
    /// * Changing the normal user's PIN
    ///
    /// The token may change its write-protected status depending on the
    /// session state to implement its object management policy. For instance,
    /// the token may report write-protection unless the session state is R/W
    /// SO or R/W User to implement a policy that does not allow any objects,
    /// public or private, to be created, modified, or deleted unless the user
    /// has successfully called [`Session::login`](crate::session::Session::login).
    pub fn write_protected(&self) -> bool {
        self.flags.contains(WRITE_PROTECTED)
    }

    /// True if there are some cryptographic functions that a user *must* be
    /// logged in to perform
    pub fn login_required(&self) -> bool {
        self.flags.contains(LOGIN_REQUIRED)
    }

    /// True of the normal user's PIN has been initialized
    pub fn user_pin_initialized(&self) -> bool {
        self.flags.contains(USER_PIN_INITIALIZED)
    }

    /// True if a successful save of a session's cryptographic operations state
    /// *always* contains all keys needed to restore the state of the session.
    pub fn restore_key_not_needed(&self) -> bool {
        self.flags.contains(RESTORE_KEY_NOT_NEEDED)
    }

    /// True if the token has its own hardware clock
    pub fn clock_on_token(&self) -> bool {
        self.flags.contains(CLOCK_ON_TOKEN)
    }

    /// True if the token has a "protected authentication path" whereby a user
    /// can log into the token without passing a PIN
    pub fn protected_authentication_path(&self) -> bool {
        self.flags.contains(PROTECTED_AUTHENTICATION_PATH)
    }

    /// True if a single session with the token can perform dual cryptographic
    /// operations
    // TODO: Requires Session callbacks:to access
    // * digest_encrypt_update
    // * decrypt_digest_update
    // * sign_encrypt_update
    // * decrypt_verify_update
    pub fn dual_crypto_operations(&self) -> bool {
        self.flags.contains(DUAL_CRYPTO_OPERATIONS)
    }

    /// True if the token has been initialized with
    /// [`Pkcs11::init_token](crate::context::Pkcs11::init_token) or an
    /// equivalent mechanism outside the scope of the PKCS#11 standard
    ///
    /// **[Conformance](crate#conformance-notes):**
    /// Calling [`Pkcs11::init_token`](crate::context::Pkcs11::init_token) when
    /// this flag is set will cause the token to be reinitialized.
    pub fn token_initialized(&self) -> bool {
        self.flags.contains(TOKEN_INITIALIZED)
    }

    /// True if the token supports secondary authentication for private key
    /// objects
    /// **[Conformance](crate#conformance-notes):**
    /// This field is deprecated and new providers *must not* set it. I.e., this function must always return `false`.
    pub fn secondary_authentication(&self) -> bool {
        self.flags.contains(SECONDARY_AUTHENTICATION)
    }

    /// True if an incorrect user login PIN has been entered at least once
    /// since the last successful authentication
    ///
    /// **[Conformance](crate#conformance-notes):**
    /// This value may be set to always be false if the token either does not
    /// support the functionality or will not reveal the information because of
    /// its security policy.
    pub fn user_pin_count_low(&self) -> bool {
        self.flags.contains(USER_PIN_COUNT_LOW)
    }

    /// True if supplying an incorrect user PIN will cause it to become locked
    ///
    /// **[Conformance](crate#conformance-notes):**
    /// This value may be set to always be false if the token either does not
    /// support the functionality or will not reveal the information because of
    /// its security policy.
    pub fn user_pin_final_try(&self) -> bool {
        self.flags.contains(USER_PIN_FINAL_TRY)
    }

    /// True if the user PIN has been locked; user login to the token is not
    /// possible
    pub fn user_pin_locked(&self) -> bool {
        self.flags.contains(USER_PIN_LOCKED)
    }

    /// True if the user PIN value is the default value set by the token
    /// initialization or manufacturing, or the PIN has been expired by the
    /// card
    ///
    /// **[Conformance](crate#conformance-notes):**
    /// This may be always false if the token either does not support the
    /// functionality or will not reveal the information because of its
    /// security policy.
    ///
    /// If a PIN is set to the default value or has expired, this function
    /// returns `true`. When true, logging in with a PIN will succeed, but only
    /// the [`Session::set_pin`][crate::session::Session::set_pin] function can
    /// be called. Calling any other function that required the user to be
    /// logged in will cause [`PinExpired`][crate::error::RvError::PinExpired]
    /// to be returned until
    /// [`Session::set_pin`][crate::session::Session::set_pin] is called
    /// successfully.
    pub fn user_pin_to_be_changed(&self) -> bool {
        self.flags.contains(USER_PIN_TO_BE_CHANGED)
    }

    /// True if an incorrect Security Officer login PIN has been entered at least once since
    /// the last successful authentication
    ///
    /// **[Conformance](crate#conformance-notes):**
    /// This value may be set to always be false if the token either does not
    /// support the functionality or will not reveal the information because of
    /// its security policy.
    pub fn so_pin_count_low(&self) -> bool {
        self.flags.contains(SO_PIN_COUNT_LOW)
    }

    /// True if supplying an incorrect Security Officer PIN will cause it to become locked
    ///
    /// **[Conformance](crate#conformance-notes):**
    /// This value may be set to always be false if the token either does not
    /// support the functionality or will not reveal the information because of
    /// its security policy.
    pub fn so_pin_final_try(&self) -> bool {
        self.flags.contains(SO_PIN_FINAL_TRY)
    }

    /// True if the Security Officer PIN has been locked; Security Officer login to the token is not
    /// possible
    pub fn so_pin_locked(&self) -> bool {
        self.flags.contains(SO_PIN_LOCKED)
    }

    /// True if the Security Officer PIN value is the default value set by the token
    /// initialization or manufacturing, or the PIN has been expired by the card
    ///
    /// **[Conformance](crate#conformance-notes):**
    /// This may be always false if the token either does not support the
    /// functionality or will not reveal the information because of its security
    /// policy.
    ///
    /// If a PIN is set to the default value or has expired, this function
    /// returns `true`. When true, logging in with a PIN will succeed, but only
    /// the [`Session::set_pin`][crate::session::Session::set_pin] function can
    /// be called. Calling any other function that required the user to be
    /// logged in will cause [`PinExpired`][crate::error::RvError::PinExpired]
    /// to be returned until
    /// [`Session::set_pin`][crate::session::Session::set_pin] is called
    /// successfully.
    pub fn so_pin_to_be_changed(&self) -> bool {
        self.flags.contains(SO_PIN_TO_BE_CHANGED)
    }

    /// True if the token failed a FIPS 140-2 self-test and entered an error state
    pub fn error_state(&self) -> bool {
        self.flags.contains(ERROR_STATE)
    }

    /// The maximum number of sessions that can be opened with the token at one
    /// time by a single application
    /// If `None`, this information was unavailable.
    /// If `Some(None)` there is no maximum, meaning the value is effectively infinite
    /// If `Some(Some(n))` the maximum number of sessions is `n`
    pub fn max_session_count(&self) -> Option<Option<u64>> {
        self.max_session_count
    }

    /// The number of sessions this application currently has open with the
    /// token
    pub fn session_count(&self) -> Option<u64> {
        self.session_count
    }

    /// The maximum number of read/write sessions that can be opened with the
    /// token at one time by a single application
    /// If `None`, this information was unavailable.
    /// If `Some(None)` there is no maximum, meaning the value is effectively infinite
    /// If `Some(Some(n))` the maximum number of read/write sessions is `n`
    pub fn max_rw_session_count(&self) -> Option<Option<u64>> {
        self.max_rw_session_count
    }

    /// The number of read/write sessions this application currently has open
    /// with the token
    pub fn rw_session_count(&self) -> Option<u64> {
        self.rw_session_count
    }

    /// The maximum length in bytes of the PIN
    pub fn max_pin_length(&self) -> usize {
        self.max_pin_len
    }

    /// The minimum length in bytes of the PIN
    pub fn min_pin_length(&self) -> usize {
        self.min_pin_len
    }

    /// The total amount of memory on the token (in bytes) in which public
    /// objects may be stored
    /// Returns `None` if this information is unavailable
    pub fn total_public_memory(&self) -> Option<usize> {
        self.total_public_memory
    }

    /// The amount of free (unused) emmeory on the token (in bytes) for public
    /// objects
    /// Returns `None` if this information is unavailable
    pub fn free_public_memory(&self) -> Option<usize> {
        self.free_public_memory
    }

    /// The total amount of memory on the token (in bytes) in which private
    /// objects may be stored
    /// Returns `None` if this information is unavailable
    pub fn total_private_memory(&self) -> Option<usize> {
        self.total_private_memory
    }

    /// The amount of free (unused) emmeory on the token (in bytes) for private
    /// objects
    /// Returns `None` if this information is unavailable
    pub fn free_private_memory(&self) -> Option<usize> {
        self.free_private_memory
    }

    /// The version number of the hardware
    pub fn hardware_version(&self) -> Version {
        self.hardware_version
    }

    /// The version number of the firmware
    pub fn firmware_version(&self) -> Version {
        self.firmware_version
    }

    /// The current datetime with resolution in seconds
    ///
    /// Returns None if the token is not equipped with a clock (i.e.,
    /// `self.clock_on_token() == false`)
    pub fn utc_time(&self) -> Option<&str> {
        // TODO
        Some(&self.utc_time)
    }
}
