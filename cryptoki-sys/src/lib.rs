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
    target_arch = "aarch64",
    target_os = "macos"
))]
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/bindings/aarch64-apple-darwin.rs"
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

#[cfg(all(
    not(feature = "generate-bindings"),
    target_arch = "x86_64",
    target_os = "freebsd"
))]
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/bindings/x86_64-unknown-freebsd.rs"
));

// For supported targets: use the generated and committed bindings.
#[cfg(not(any(
    feature = "generate-bindings",
    all(target_arch = "x86_64", target_os = "linux"),
    all(target_arch = "x86", target_os = "linux"),
    all(target_arch = "powerpc64", target_os = "linux"),
    all(target_arch = "aarch64", target_os = "linux"),
    all(target_arch = "arm", target_os = "linux"),
    all(target_arch = "x86_64", target_os = "macos"),
    all(target_arch = "aarch64", target_os = "macos"),
    all(target_arch = "x86_64", target_os = "windows"),
    all(target_arch = "x86_64", target_os = "freebsd"),
)))]
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/bindings/generic.rs"
));

// If the "generate-bindings" feature is on, use the generated bindings.
#[cfg(feature = "generate-bindings")]
include!(concat!(env!("OUT_DIR"), "/pkcs11_bindings.rs"));

// this value is defined in pkcs11t.h as ~0
// bindgen converts that into a platform specific numeric value
pub const CK_UNAVAILABLE_INFORMATION: CK_ULONG = !0;

#[deprecated = "Use CK_ATTRIBUTE"]
pub type _CK_ATTRIBUTE = CK_ATTRIBUTE;
#[deprecated = "Use CK_C_INITIALIZE_ARGS"]
pub type _CK_C_INITIALIZE_ARGS = CK_C_INITIALIZE_ARGS;
#[deprecated = "Use CK_DATE"]
pub type _CK_DATE = CK_DATE;
#[deprecated = "Use CK_FUNCTION_LIST"]
pub type _CK_FUNCTION_LIST = CK_FUNCTION_LIST;
#[deprecated = "Use CK_INFO"]
pub type _CK_INFO = CK_INFO;
#[deprecated = "Use CK_MECHANISM"]
pub type _CK_MECHANISM = CK_MECHANISM;
#[deprecated = "Use CK_MECHANISM_INFO"]
pub type _CK_MECHANISM_INFO = CK_MECHANISM_INFO;
#[deprecated = "Use CK_SESSION_INFO"]
pub type _CK_SESSION_INFO = CK_SESSION_INFO;
#[deprecated = "Use CK_SLOT_INFO"]
pub type _CK_SLOT_INFO = CK_SLOT_INFO;
#[deprecated = "Use CK_TOKEN_INFO"]
pub type _CK_TOKEN_INFO = CK_TOKEN_INFO;
#[deprecated = "Use CK_VERSION"]
pub type _CK_VERSION = CK_VERSION;
#[deprecated = "Use CK_AES_CBC_ENCRYPT_DATA_PARAMS"]
pub type ck_aes_cbc_encrypt_data_params = CK_AES_CBC_ENCRYPT_DATA_PARAMS;
#[deprecated = "Use CK_AES_CTR_PARAMS"]
pub type ck_aes_ctr_params = CK_AES_CTR_PARAMS;
#[deprecated = "Use CK_DES_CBC_ENCRYPT_DATA_PARAMS"]
pub type ck_des_cbc_encrypt_data_params = CK_DES_CBC_ENCRYPT_DATA_PARAMS;
#[deprecated = "Use CK_ECDH1_DERIVE_PARAMS"]
pub type ck_ecdh1_derive_params = CK_ECDH1_DERIVE_PARAMS;
#[deprecated = "Use CK_GCM_PARAMS"]
pub type ck_gcm_params = CK_GCM_PARAMS;
#[deprecated = "Use CK_KEY_DERIVATION_STRING_DATA"]
pub type ck_key_derivation_string_data = CK_KEY_DERIVATION_STRING_DATA;
#[deprecated = "Use CK_RSA_PKCS_OAEP_PARAMS"]
pub type ck_rsa_pkcs_oaep_params = CK_RSA_PKCS_OAEP_PARAMS;
#[deprecated = "Use CK_RSA_PKCS_PSS_PARAMS"]
pub type ck_rsa_pkcs_pss_params = CK_RSA_PKCS_PSS_PARAMS;
