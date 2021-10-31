// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! PKCS11 General Data Types

pub(crate) mod function;
pub(crate) mod locking;

use crate::{string_from_blank_padded, Error, Result};
use cryptoki_sys::*;
use log::error;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt::Formatter;
use std::ops::Deref;

pub(crate) trait Flags: std::fmt::Display {
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

impl TryFrom<CK_FLAGS> for InitializeFlags {
    type Error = Error;

    fn try_from(flags: CK_FLAGS) -> Result<Self> {
        if flags & !(CKF_OS_LOCKING_OK | CKF_LIBRARY_CANT_CREATE_OS_THREADS) != 0 {
            Err(Error::InvalidValue)
        } else {
            Ok(Self { flags })
        }
    }
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
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

impl From<Bbool> for bool {
    fn from(val: Bbool) -> Self {
        match val {
            Bbool::False => false,
            Bbool::True => true,
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

#[derive(Debug, Copy, Clone)]
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
    /// If the lengths are invalid a `Error::InvalidValue` will be returned
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

        write!(f, "Month: {}\nDay: {}\nYear: {}", month, day, year)
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
