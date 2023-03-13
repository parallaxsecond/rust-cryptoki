// Copyright 2021,2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::redundant_field_names)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::string_lit_as_bytes)]
#![allow(clippy::too_many_arguments)]
// Public items exportedby this crate should match the C style
#![allow(clippy::upper_case_acronyms)]
// Suppress warnings from bindgen-generated code
// Remove on resolution of
// https://github.com/rust-lang/rust-bindgen/issues/1651
#![allow(deref_nullptr)]

// For supported targets: use the generated and committed bindings.
#[cfg(all(
    not(feature = "generate-bindings"),
    target_arch = "x86_64",
    target_os = "linux"
))]
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/bindings/x86_64-unknown-linux-gnu.rs"
));

#[cfg(all(
    not(feature = "generate-bindings"),
    target_arch = "x86",
    target_os = "linux"
))]
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/bindings/i686-unknown-linux-gnu.rs"
));

#[cfg(all(
    not(feature = "generate-bindings"),
    target_arch = "powerpc64",
    target_os = "linux"
))]
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/bindings/powerpc64-unknown-linux-gnu.rs"
));

#[cfg(all(
    not(feature = "generate-bindings"),
    target_arch = "aarch64",
    target_os = "linux"
))]
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/bindings/aarch64-unknown-linux-gnu.rs"
));

#[cfg(all(
    not(feature = "generate-bindings"),
    target_arch = "arm",
    target_os = "linux"
))]
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/bindings/arm-unknown-linux-gnueabi.rs"
));

#[cfg(all(
    not(feature = "generate-bindings"),
    target_arch = "x86_64",
    target_os = "macos"
))]
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/bindings/x86_64-apple-darwin.rs"
));

#[cfg(all(
    not(feature = "generate-bindings"),
    target_arch = "x86_64",
    target_os = "windows"
))]
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/bindings/x86_64-pc-windows-msvc.rs"
));

// If the "generate-bindings" feature is on, use the generated bindings.
#[cfg(feature = "generate-bindings")]
include!(concat!(env!("OUT_DIR"), "/pkcs11_bindings.rs"));

/// Typedefs and defines for the CKM_X9_42_DH_KEY_PAIR_GEN and the
/// CKM_X9_42_DH_PARAMETER_GEN mechanisms
pub type CK_X9_42_DH_KDF_TYPE = CK_ULONG;
pub type CK_X9_42_DH_KDF_TYPE_PTR = *mut CK_X9_42_DH_KDF_TYPE;

pub type CK_EC_KDF_TYPE = CK_ULONG;

// The values below are defined in pkcs11.h with `#define` macros. As a result, bindgen cannot
// generate bindings for them. They are included here for completeness.

pub const CKA_WRAP_TEMPLATE: CK_ATTRIBUTE_TYPE = CKF_ARRAY_ATTRIBUTE | 0x00000211;
pub const CKA_UNWRAP_TEMPLATE: CK_ATTRIBUTE_TYPE = CKF_ARRAY_ATTRIBUTE | 0x00000212;
pub const CKA_DERIVE_TEMPLATE: CK_ATTRIBUTE_TYPE = CKF_ARRAY_ATTRIBUTE | 0x00000213;
pub const CKA_ALLOWED_MECHANISMS: CK_ATTRIBUTE_TYPE = CKF_ARRAY_ATTRIBUTE | 0x00000600;
pub const CK_UNAVAILABLE_INFORMATION: CK_ULONG = !0;
pub const CKF_EXTENSION: CK_FLAGS = 0x80000000;
pub const CKK_EC_MONTGOMERY: CK_KEY_TYPE = 0x00000041;
pub const CKR_VENDOR_DEFINED: CK_RV = 0x80000000;
pub const CKR_CURVE_NOT_SUPPORTED: CK_RV = 0x00000140;
pub const CKM_VENDOR_DEFINED: CK_MECHANISM_TYPE = 0x80000000;
