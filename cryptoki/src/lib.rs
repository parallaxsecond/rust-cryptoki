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

// Warning: The context module defines the
// get_pkcs11() macro, which must be defined before
// any modules that use it are declared.
#[macro_use]
pub mod context;

pub mod error;
pub(crate) mod flag;
pub mod mechanism;
pub mod object;
pub mod session;
pub mod slot;
pub mod types;

use cryptoki_sys::CK_UTF8CHAR;

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
