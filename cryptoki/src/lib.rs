// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Rust PKCS11 new abstraction
//!
//! The items in the new module only expose idiomatic and safe Rust types and functions to
//! interface with the PKCS11 API. All the PKCS11 items might not be implemented but everything
//! that is implemented is safe.
//!
//! The modules under `new` follow the structure of the PKCS11 document version 2.40 available [here](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html).

// This list comes from
// https://github.com/rust-unofficial/patterns/blob/master/anti_patterns/deny-warnings.md
#![deny(bad_style,
       const_err,
       dead_code,
       improper_ctypes,
       non_shorthand_field_patterns,
       no_mangle_generic_items,
       overflowing_literals,
       path_statements ,
       patterns_in_fns_without_body,
       private_in_public,
       unconditional_recursion,
       unused,
       unused_allocation,
       unused_comparisons,
       unused_parens,
       while_true,
       missing_debug_implementations,
       missing_copy_implementations,
       missing_docs,
       // Useful to cast to raw pointers
       //trivial_casts,
       trivial_numeric_casts,
       unused_extern_crates,
       unused_import_braces,
       unused_qualifications,
       unused_results)]

pub(crate) mod functions;
pub(crate) mod objects;

mod rv;
pub use rv::*;

pub mod types;
pub mod context;
pub mod mechanism;
pub mod session;
pub mod object;
pub mod slot;

use cryptoki_sys::CK_UTF8CHAR;
use std::fmt;

#[derive(Debug)]
/// Main error type
pub enum Error {
    /// Any error that happens during library loading of the PKCS#11 module is encompassed under
    /// this error. It is a direct forward of the underlying error from libloading.
    LibraryLoading(libloading::Error),

    /// All PKCS#11 functions that return non-zero translate to this error.
    Pkcs11(RvError),

    /// This error marks a feature that is not yet supported by the PKCS11 Rust abstraction layer.
    NotSupported,

    /// Error happening while converting types
    TryFromInt(std::num::TryFromIntError),

    /// Error when converting a slice to an array
    TryFromSlice(std::array::TryFromSliceError),

    /// Error with nul characters in Strings
    NulError(std::ffi::NulError),

    /// Calling a PKCS11 function that is a NULL function pointer.
    NullFunctionPointer,

    /// The value is not one of those expected.
    InvalidValue,

    /// The PIN was not set before logging in.
    PinNotSet,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::LibraryLoading(e) => write!(f, "libloading error ({})", e),
            Error::Pkcs11(e) => write!(f, "PKCS11 error: {}", e),
            Error::NotSupported => write!(f, "Feature not supported"),
            Error::TryFromInt(e) => write!(f, "Conversion between integers failed ({})", e),
            Error::TryFromSlice(e) => write!(f, "Error converting slice to array ({})", e),
            Error::NulError(e) => write!(f, "An interior nul byte was found ({})", e),
            Error::NullFunctionPointer => write!(f, "Calling a NULL function pointer"),
            Error::InvalidValue => write!(f, "The value is not one of the expected options"),
            Error::PinNotSet => write!(f, "Pin has not been set before trying to log in"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::LibraryLoading(e) => Some(e),
            Error::TryFromInt(e) => Some(e),
            Error::TryFromSlice(e) => Some(e),
            Error::NulError(e) => Some(e),
            Error::Pkcs11(_)
            | Error::NotSupported
            | Error::NullFunctionPointer
            | Error::PinNotSet
            | Error::InvalidValue => None,
        }
    }
}

impl From<libloading::Error> for Error {
    fn from(err: libloading::Error) -> Error {
        Error::LibraryLoading(err)
    }
}

impl From<std::num::TryFromIntError> for Error {
    fn from(err: std::num::TryFromIntError) -> Error {
        Error::TryFromInt(err)
    }
}

impl From<std::array::TryFromSliceError> for Error {
    fn from(err: std::array::TryFromSliceError) -> Error {
        Error::TryFromSlice(err)
    }
}

impl From<std::ffi::NulError> for Error {
    fn from(err: std::ffi::NulError) -> Error {
        Error::NulError(err)
    }
}

impl From<std::convert::Infallible> for Error {
    fn from(_err: std::convert::Infallible) -> Error {
        unreachable!()
    }
}

/// Main Result type
pub type Result<T> = core::result::Result<T, Error>;

fn string_from_blank_padded(field: &[CK_UTF8CHAR]) -> String {
    let decoded_str = String::from_utf8_lossy(field);
    decoded_str.trim_end_matches(' ').to_string()
}

fn label_from_str(label: &str) -> [CK_UTF8CHAR; 32] {
    let mut lab: [CK_UTF8CHAR; 32] = [32; 32];
    let mut i = 0;
    for c in label.chars() {
        if i + c.len_utf8() <= 32 {
            let mut buf = [0; 4];
            let bytes = c.encode_utf8(&mut buf).as_bytes();
            for b in bytes {
                lab[i] = *b;
                i += 1;
            }
        } else {
            break;
        }
    }
    lab
}
