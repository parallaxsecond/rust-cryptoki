// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! PKCS11 General Data Types

use crate::error::{Error, Result};
use cryptoki_sys::*;
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt::Formatter;
use std::ops::Deref;

#[derive(Debug, Copy, Clone, Default)]
#[repr(transparent)]
/// Value that represents a date
pub struct Date {
    date: CK_DATE,
}

impl Date {
    /// Creates a new `Date` structure
    ///
    /// # Arguments
    ///
    /// * `year` - A 4 character length year, e.g. "2021"
    /// * `month` - A 2 character length mont, e.g. "02"
    /// * `day` - A 2 character length day, e.g. "15"
    ///
    /// # Errors
    ///
    /// If the lengths are invalid, an `Error::InvalidValue` will be returned
    pub fn new_from_str_slice(year: &str, month: &str, day: &str) -> Result<Self> {
        if year.len() != 4 || month.len() != 2 || day.len() != 2 {
            Err(Error::InvalidValue)
        } else {
            let mut year_slice: [u8; 4] = Default::default();
            let mut month_slice: [u8; 2] = Default::default();
            let mut day_slice: [u8; 2] = Default::default();
            year_slice.copy_from_slice(year.as_bytes());
            month_slice.copy_from_slice(month.as_bytes());
            day_slice.copy_from_slice(day.as_bytes());
            Ok(Date::new(year_slice, month_slice, day_slice))
        }
    }

    /// Creates a new `Date` structure from byte slices
    ///
    /// # Arguments
    ///
    /// * `year` - A 4 character length year, e.g. "2021"
    /// * `month` - A 2 character length mont, e.g. "02"
    /// * `day` - A 2 character length day, e.g. "15"
    pub fn new(year: [u8; 4], month: [u8; 2], day: [u8; 2]) -> Self {
        let date = CK_DATE { year, month, day };
        Self { date }
    }

    /// Creates a new, empty `Date` structure
    ///
    /// This represents the default value of the attribute (on
    /// newer implementations of `Cryptoki`).
    pub fn new_empty() -> Self {
        Self::default()
    }

    /// Check if `Date` is empty
    ///
    /// *NOTE*: This function is only representative of newer implementations
    /// of `Cryptoki`, for which dates are represented as empty object attributes.
    pub fn is_empty(&self) -> bool {
        self.date.year == <[u8; 4]>::default()
            && self.date.month == <[u8; 2]>::default()
            && self.date.day == <[u8; 2]>::default()
    }
}

impl Deref for Date {
    type Target = CK_DATE;

    fn deref(&self) -> &Self::Target {
        &self.date
    }
}

impl From<Date> for CK_DATE {
    fn from(date: Date) -> Self {
        *date
    }
}

impl From<CK_DATE> for Date {
    fn from(date: CK_DATE) -> Self {
        Self { date }
    }
}

impl std::fmt::Display for Date {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let year = String::from_utf8_lossy(Vec::from(self.year).as_slice())
            .trim_end()
            .to_string();
        let month = String::from_utf8_lossy(Vec::from(self.month).as_slice())
            .trim_end()
            .to_string();
        let day = String::from_utf8_lossy(Vec::from(self.day).as_slice())
            .trim_end()
            .to_string();

        write!(f, "Month: {month}\nDay: {day}\nYear: {year}")
    }
}

impl PartialEq for Date {
    fn eq(&self, other: &Self) -> bool {
        self.date.year == other.date.year
            && self.date.month == other.date.month
            && self.date.day == other.date.day
    }
}

impl Eq for Date {}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
/// Unsigned value, at least 32 bits long
pub struct Ulong {
    val: CK_ULONG,
}

impl Ulong {
    /// Create a new variable
    #[must_use]
    pub const fn new(ulong: CK_ULONG) -> Self {
        Ulong { val: ulong }
    }
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

impl From<Ulong> for usize {
    fn from(ulong: Ulong) -> Self {
        ulong.val as usize
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
    /// Construct a new version
    pub(crate) fn new(major: u8, minor: u8) -> Self {
        Self { major, minor }
    }

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

/// A UTC datetime returned by a token's clock if present.
#[derive(Copy, Clone, Debug)]
pub struct UtcTime {
    /// **[Conformance](crate#conformance-notes): **
    /// Guaranteed to be in range 0..=9999
    pub year: u16,
    /// **[Conformance](crate#conformance-notes): **
    /// Guaranteed to be in range 0..=99
    pub month: u8,
    /// **[Conformance](crate#conformance-notes): **
    /// Guaranteed to be in range 0..=99
    pub day: u8,
    /// **[Conformance](crate#conformance-notes): **
    /// Guaranteed to be in range 0..=99
    pub hour: u8,
    /// **[Conformance](crate#conformance-notes): **
    /// Guaranteed to be in range 0..=99
    pub minute: u8,
    /// **[Conformance](crate#conformance-notes): **
    /// Guaranteed to be in range 0..=99
    pub second: u8,
}

impl UtcTime {
    /// Stringify the structure in ISO 8601 format.
    ///
    /// PKCS#11 and ISO are unrelated standards, and this function is provided
    /// only for convenience. ISO format is more widely recognized and parsable
    /// by various date/time utilities, while PKCS#11's internal representation
    /// of this type is not used elsewhere.
    /// Other than formatting, this crate does not guarantee or enforce any part
    /// of the ISO standard.
    pub fn as_iso8601_string(&self) -> String {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

// UTC time has the format YYYYMMDDhhmmss00 as ASCII digits
pub(crate) fn convert_utc_time(orig: [u8; 16]) -> Result<UtcTime> {
    // Note: No validation of these values beyond being ASCII digits
    // because PKCS#11 doesn't impose any such restrictions.
    Ok(UtcTime {
        year: std::str::from_utf8(&orig[0..4])?.parse()?,
        month: std::str::from_utf8(&orig[4..6])?.parse()?,
        day: std::str::from_utf8(&orig[6..8])?.parse()?,
        hour: std::str::from_utf8(&orig[8..10])?.parse()?,
        minute: std::str::from_utf8(&orig[10..12])?.parse()?,
        second: std::str::from_utf8(&orig[12..14])?.parse()?,
    })
}

/// Secret wrapper for a Pin
///
/// Enable the `serde` feature to add support for Deserialize
pub type AuthPin = SecretString;

/// Secret wrapper for a raw non UTF-8 Pin
///
/// Enable the `serde` feature to add support for Deserialize
pub type RawAuthPin = SecretSlice<u8>;

/// Credentials used to authenticate a session.
#[derive(Debug, Copy, Clone)]
pub enum Credential<'a> {
    /// UTF-8 PIN/passphrase.
    Pin(&'a AuthPin),
    /// UTF-8 PIN/passphrase with a username.
    PinWithUser {
        /// The PIN/passphrase.
        pin: &'a AuthPin,
        /// The username.
        username: &'a str,
    },
    /// Raw PIN/passphrase (non UTF-8).
    RawPin(&'a RawAuthPin),
    /// Raw PIN/passphrase with a username (non UTF-8).
    RawPinWithUser {
        /// The raw PIN/passphrase.
        pin: &'a RawAuthPin,
        /// The username.
        username: &'a str,
    },
    /// Use the protected authentication path instead of a PIN.
    ProtectedAuthenticationPath,
    /// Use the protected authentication path with a username.
    ProtectedAuthenticationPathWithUser {
        /// The username.
        username: &'a str,
    },
}

impl<'a> Credential<'a> {
    /// Create a credential from a UTF-8 PIN/passphrase.
    #[must_use]
    pub fn pin(pin: &'a AuthPin) -> Self {
        Self::Pin(pin)
    }

    /// Create a credential from a UTF-8 PIN/passphrase and a username.
    #[must_use]
    pub fn pin_with_user(pin: &'a AuthPin, username: &'a str) -> Self {
        Self::PinWithUser { pin, username }
    }

    /// Create a credential from a raw PIN/passphrase.
    #[must_use]
    pub fn raw_pin(pin: &'a RawAuthPin) -> Self {
        Self::RawPin(pin)
    }

    /// Create a credential from a raw PIN/passphrase and a username.
    #[must_use]
    pub fn raw_pin_with_user(pin: &'a RawAuthPin, username: &'a str) -> Self {
        Self::RawPinWithUser { pin, username }
    }

    /// Create a credential for the protected authentication path.
    #[must_use]
    pub fn protected_authentication_path() -> Self {
        Self::ProtectedAuthenticationPath
    }

    /// Create a credential for the protected authentication path with a username.
    #[must_use]
    pub fn protected_authentication_path_with_user(username: &'a str) -> Self {
        Self::ProtectedAuthenticationPathWithUser { username }
    }

    /// Return the PIN pointer and length for PKCS#11 calls.
    pub(crate) fn pin_ptr_len(&self) -> (*mut u8, usize) {
        match self {
            Self::Pin(pin) | Self::PinWithUser { pin, .. } => {
                let pin = pin.expose_secret().as_bytes();
                (pin.as_ptr() as *mut u8, pin.len())
            }
            Self::RawPin(pin) | Self::RawPinWithUser { pin, .. } => {
                let pin = pin.expose_secret();
                (pin.as_ptr() as *mut u8, pin.len())
            }
            Self::ProtectedAuthenticationPath
            | Self::ProtectedAuthenticationPathWithUser { .. } => (std::ptr::null_mut(), 0),
        }
    }

    /// Return the username if this credential includes one.
    pub(crate) fn username(&self) -> Option<&str> {
        match self {
            Self::PinWithUser { username, .. } | Self::RawPinWithUser { username, .. } => {
                Some(username)
            }
            Self::Pin(_) | Self::RawPin(_) | Self::ProtectedAuthenticationPath => None,
            Self::ProtectedAuthenticationPathWithUser { username } => Some(username),
        }
    }
}

impl<'a> From<Option<&'a AuthPin>> for Credential<'a> {
    fn from(pin: Option<&'a AuthPin>) -> Self {
        match pin {
            Some(pin) => Credential::Pin(pin),
            None => Credential::ProtectedAuthenticationPath,
        }
    }
}

impl<'a> From<Option<&'a RawAuthPin>> for Credential<'a> {
    fn from(pin: Option<&'a RawAuthPin>) -> Self {
        match pin {
            Some(pin) => Credential::RawPin(pin),
            None => Credential::ProtectedAuthenticationPath,
        }
    }
}

impl<'a> From<&'a AuthPin> for Credential<'a> {
    fn from(pin: &'a AuthPin) -> Self {
        Credential::Pin(pin)
    }
}

impl<'a> From<&'a RawAuthPin> for Credential<'a> {
    fn from(pin: &'a RawAuthPin) -> Self {
        Credential::RawPin(pin)
    }
}

impl<'a> From<(&'a AuthPin, &'a str)> for Credential<'a> {
    fn from((pin, username): (&'a AuthPin, &'a str)) -> Self {
        Credential::PinWithUser { pin, username }
    }
}

impl<'a> From<(&'a RawAuthPin, &'a str)> for Credential<'a> {
    fn from((pin, username): (&'a RawAuthPin, &'a str)) -> Self {
        Credential::RawPinWithUser { pin, username }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    const UTC_TIME: UtcTime = UtcTime {
        year: 1970,
        month: 1,
        day: 1,
        hour: 0,
        minute: 0,
        second: 0,
    };

    #[test]
    fn utc_time_convert_good() {
        let valid: [u8; 16] = [
            0x31, 0x39, 0x37, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30,
        ];
        let valid = convert_utc_time(valid).unwrap();
        assert_eq!(valid.year, UTC_TIME.year);
        assert_eq!(valid.month, UTC_TIME.month);
        assert_eq!(valid.day, UTC_TIME.day);
        assert_eq!(valid.hour, UTC_TIME.hour);
        assert_eq!(valid.minute, UTC_TIME.minute);
        assert_eq!(valid.second, UTC_TIME.second);
    }

    #[test]
    fn utc_time_convert_bad() {
        // Year starts with a non-numeric value ('A')
        let invalid: [u8; 16] = [
            0x41, 0x39, 0x37, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30,
        ];
        let invalid = convert_utc_time(invalid);
        assert!(invalid.is_err());
    }

    #[test]
    fn utc_time_debug_fmt() {
        let expected = r#"UtcTime {
    year: 1970,
    month: 1,
    day: 1,
    hour: 0,
    minute: 0,
    second: 0,
}"#;
        let observed = format!("{UTC_TIME:#?}");
        assert_eq!(observed, expected);
    }
    #[test]
    fn utc_time_display_fmt() {
        let iso_format = UTC_TIME.as_iso8601_string();
        assert_eq!(&iso_format, "1970-01-01T00:00:00Z");
    }

    #[test]
    fn credential_pin() {
        let pin = AuthPin::from("my_secret_pin");
        let credential: Credential = Credential::pin(&pin);

        // Test pin_ptr_len
        let (ptr, len) = credential.pin_ptr_len();
        assert!(!ptr.is_null());
        assert_eq!(len, 13);

        // Test username
        assert!(credential.username().is_none());
    }

    #[test]
    fn credential_pin_with_user() {
        let pin = AuthPin::from("my_secret_pin");
        let username = "alice";
        let credential = Credential::pin_with_user(&pin, username);

        // Test pin_ptr_len
        let (ptr, len) = credential.pin_ptr_len();
        assert!(!ptr.is_null());
        assert_eq!(len, 13);

        // Test username
        assert_eq!(credential.username(), Some("alice"));
    }

    #[test]
    fn credential_raw_pin() {
        let raw_pin_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let raw_pin = RawAuthPin::from(raw_pin_data);
        let credential: Credential = Credential::raw_pin(&raw_pin);

        // Test pin_ptr_len
        let (ptr, len) = credential.pin_ptr_len();
        assert!(!ptr.is_null());
        assert_eq!(len, 4);

        // Test username
        assert!(credential.username().is_none());
    }

    #[test]
    fn credential_raw_pin_with_user() {
        let raw_pin_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let raw_pin = RawAuthPin::from(raw_pin_data);
        let username = "bob";
        let credential = Credential::raw_pin_with_user(&raw_pin, username);

        // Test pin_ptr_len
        let (ptr, len) = credential.pin_ptr_len();
        assert!(!ptr.is_null());
        assert_eq!(len, 4);

        // Test username
        assert_eq!(credential.username(), Some("bob"));
    }

    #[test]
    fn credential_protected_authentication_path() {
        let credential = Credential::protected_authentication_path();

        // Test pin_ptr_len
        let (ptr, len) = credential.pin_ptr_len();
        assert!(ptr.is_null());
        assert_eq!(len, 0);

        // Test username
        assert!(credential.username().is_none());
    }

    #[test]
    fn credential_protected_authentication_path_with_user() {
        let username = "charlie";
        let credential = Credential::protected_authentication_path_with_user(username);

        // Test pin_ptr_len
        let (ptr, len) = credential.pin_ptr_len();
        assert!(ptr.is_null());
        assert_eq!(len, 0);

        // Test username
        assert_eq!(credential.username(), Some("charlie"));
    }

    #[test]
    fn credential_from_option_auth_pin_some() {
        let pin = AuthPin::from("test_pin");
        let credential = Credential::from(Some(&pin));

        // Should create Pin variant
        let (ptr, len) = credential.pin_ptr_len();
        assert!(!ptr.is_null());
        assert_eq!(len, 8);
        assert!(credential.username().is_none());
    }

    #[test]
    fn credential_from_option_auth_pin_none() {
        let credential = Credential::from(None::<&AuthPin>);

        // Should create ProtectedAuthenticationPath variant
        let (ptr, len) = credential.pin_ptr_len();
        assert!(ptr.is_null());
        assert_eq!(len, 0);
        assert!(credential.username().is_none());
    }

    #[test]
    fn credential_from_option_raw_auth_pin_some() {
        let raw_pin = RawAuthPin::from(vec![0x01, 0x02, 0x03]);
        let credential = Credential::from(Some(&raw_pin));

        // Should create RawPin variant
        let (ptr, len) = credential.pin_ptr_len();
        assert!(!ptr.is_null());
        assert_eq!(len, 3);
        assert!(credential.username().is_none());
    }

    #[test]
    fn credential_from_option_raw_auth_pin_none() {
        let credential = Credential::from(None::<&RawAuthPin>);

        // Should create ProtectedAuthenticationPath variant
        let (ptr, len) = credential.pin_ptr_len();
        assert!(ptr.is_null());
        assert_eq!(len, 0);
        assert!(credential.username().is_none());
    }

    #[test]
    fn credential_from_auth_pin() {
        let pin = AuthPin::from("direct_pin");
        let credential = Credential::from(&pin);

        // Should create Pin variant
        let (ptr, len) = credential.pin_ptr_len();
        assert!(!ptr.is_null());
        assert_eq!(len, 10);
        assert!(credential.username().is_none());
    }

    #[test]
    fn credential_from_raw_auth_pin() {
        let raw_pin = RawAuthPin::from(vec![0xAA, 0xBB, 0xCC, 0xDD]);
        let credential = Credential::from(&raw_pin);

        // Should create RawPin variant
        let (ptr, len) = credential.pin_ptr_len();
        assert!(!ptr.is_null());
        assert_eq!(len, 4);
        assert!(credential.username().is_none());
    }

    #[test]
    fn credential_from_auth_pin_with_user() {
        let pin = AuthPin::from("user_pin");
        let username = "dave";
        let credential = Credential::from((&pin, username));

        // Should create PinWithUser variant
        let (ptr, len) = credential.pin_ptr_len();
        assert!(!ptr.is_null());
        assert_eq!(len, 8);
        assert_eq!(credential.username(), Some("dave"));
    }

    #[test]
    fn credential_from_raw_auth_pin_with_user() {
        let raw_pin = RawAuthPin::from(vec![0x11, 0x22, 0x33]);
        let username = "eve";
        let credential = Credential::from((&raw_pin, username));

        // Should create RawPinWithUser variant
        let (ptr, len) = credential.pin_ptr_len();
        assert!(!ptr.is_null());
        assert_eq!(len, 3);
        assert_eq!(credential.username(), Some("eve"));
    }

    #[test]
    fn credential_with_string_username() {
        let pin = AuthPin::from("test_pin");
        let username = String::from("owned_username");
        let credential = Credential::pin_with_user(&pin, &username);

        // Test with owned String username
        assert_eq!(credential.username(), Some("owned_username"));
    }
}
