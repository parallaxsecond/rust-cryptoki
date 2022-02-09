// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! General-purpose functions

use crate::context::{CInitializeArgs, Info, Pkcs11};
use crate::error::{Result, Rv};
use cryptoki_sys::{CK_C_INITIALIZE_ARGS, CK_INFO};
use paste::paste;
use std::convert::TryFrom;

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn initialize(ctx: &Pkcs11, init_args: CInitializeArgs) -> Result<()> {
    // if no args are specified, library expects NULL
    let mut init_args = CK_C_INITIALIZE_ARGS::from(init_args);
    let init_args_ptr = &mut init_args;
    unsafe {
        Rv::from(get_pkcs11!(ctx, C_Initialize)(
            init_args_ptr as *mut CK_C_INITIALIZE_ARGS as *mut ::std::ffi::c_void,
        ))
        .into_result()
    }
}

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn get_library_info(ctx: &Pkcs11) -> Result<Info> {
    let mut info = CK_INFO::default();
    unsafe {
        Rv::from(get_pkcs11!(ctx, C_GetInfo)(&mut info)).into_result()?;
        Info::try_from(info)
    }
}

macro_rules! check_fn {
    ($pkcs11:expr, $func_name:ident) => {
        paste! { $pkcs11
            .impl_
            .function_list
            .[< C_ $func_name >]
            .is_some()
        }
    };
}

#[allow(clippy::enum_variant_names, missing_docs)]
#[derive(Debug, Copy, Clone)]
/// Enumeration of all functions defined by the PKCS11 spec
pub enum Function {
    Initialize,
    Finalize,
    GetInfo,
    GetFunctionList,
    GetSlotList,
    GetSlotInfo,
    GetTokenInfo,
    GetMechanismList,
    GetMechanismInfo,
    InitToken,
    InitPIN,
    SetPIN,
    OpenSession,
    CloseSession,
    CloseAllSessions,
    GetSessionInfo,
    GetOperationState,
    SetOperationState,
    Login,
    Logout,
    CreateObject,
    CopyObject,
    DestroyObject,
    GetObjectSize,
    GetAttributeValue,
    SetAttributeValue,
    FindObjectsInit,
    FindObjects,
    FindObjectsFinal,
    EncryptInit,
    Encrypt,
    EncryptUpdate,
    EncryptFinal,
    DecryptInit,
    Decrypt,
    DecryptUpdate,
    DecryptFinal,
    DigestInit,
    Digest,
    DigestUpdate,
    DigestKey,
    DigestFinal,
    SignInit,
    Sign,
    SignUpdate,
    SignFinal,
    SignRecoverInit,
    SignRecover,
    VerifyInit,
    Verify,
    VerifyUpdate,
    VerifyFinal,
    VerifyRecoverInit,
    VerifyRecover,
    DigestEncryptUpdate,
    DecryptDigestUpdate,
    SignEncryptUpdate,
    DecryptVerifyUpdate,
    GenerateKey,
    GenerateKeyPair,
    WrapKey,
    UnwrapKey,
    DeriveKey,
    SeedRandom,
    GenerateRandom,
    GetFunctionStatus,
    CancelFunction,
    WaitForSlotEvent,
}

#[inline(always)]
pub(super) fn is_fn_supported(ctx: &Pkcs11, function: Function) -> bool {
    match function {
        Function::Initialize => check_fn!(ctx, Initialize),
        Function::Finalize => check_fn!(ctx, Finalize),
        Function::GetInfo => check_fn!(ctx, GetInfo),
        Function::GetFunctionList => check_fn!(ctx, GetFunctionList),
        Function::GetSlotList => check_fn!(ctx, GetSlotList),
        Function::GetSlotInfo => check_fn!(ctx, GetSlotInfo),
        Function::GetTokenInfo => check_fn!(ctx, GetTokenInfo),
        Function::GetMechanismList => check_fn!(ctx, GetMechanismList),
        Function::GetMechanismInfo => check_fn!(ctx, GetMechanismInfo),
        Function::InitToken => check_fn!(ctx, InitToken),
        Function::InitPIN => check_fn!(ctx, InitPIN),
        Function::SetPIN => check_fn!(ctx, SetPIN),
        Function::OpenSession => check_fn!(ctx, OpenSession),
        Function::CloseSession => check_fn!(ctx, CloseSession),
        Function::CloseAllSessions => check_fn!(ctx, CloseAllSessions),
        Function::GetSessionInfo => check_fn!(ctx, GetSessionInfo),
        Function::GetOperationState => check_fn!(ctx, GetOperationState),
        Function::SetOperationState => check_fn!(ctx, SetOperationState),
        Function::Login => check_fn!(ctx, Login),
        Function::Logout => check_fn!(ctx, Logout),
        Function::CreateObject => check_fn!(ctx, CreateObject),
        Function::CopyObject => check_fn!(ctx, CopyObject),
        Function::DestroyObject => check_fn!(ctx, DestroyObject),
        Function::GetObjectSize => check_fn!(ctx, GetObjectSize),
        Function::GetAttributeValue => check_fn!(ctx, GetAttributeValue),
        Function::SetAttributeValue => check_fn!(ctx, SetAttributeValue),
        Function::FindObjectsInit => check_fn!(ctx, FindObjectsInit),
        Function::FindObjects => check_fn!(ctx, FindObjects),
        Function::FindObjectsFinal => check_fn!(ctx, FindObjectsFinal),
        Function::EncryptInit => check_fn!(ctx, EncryptInit),
        Function::Encrypt => check_fn!(ctx, Encrypt),
        Function::EncryptUpdate => check_fn!(ctx, EncryptUpdate),
        Function::EncryptFinal => check_fn!(ctx, EncryptFinal),
        Function::DecryptInit => check_fn!(ctx, DecryptInit),
        Function::Decrypt => check_fn!(ctx, Decrypt),
        Function::DecryptUpdate => check_fn!(ctx, DecryptUpdate),
        Function::DecryptFinal => check_fn!(ctx, DecryptFinal),
        Function::DigestInit => check_fn!(ctx, DigestInit),
        Function::Digest => check_fn!(ctx, Digest),
        Function::DigestUpdate => check_fn!(ctx, DigestUpdate),
        Function::DigestKey => check_fn!(ctx, DigestKey),
        Function::DigestFinal => check_fn!(ctx, DigestFinal),
        Function::SignInit => check_fn!(ctx, SignInit),
        Function::Sign => check_fn!(ctx, Sign),
        Function::SignUpdate => check_fn!(ctx, SignUpdate),
        Function::SignFinal => check_fn!(ctx, SignFinal),
        Function::SignRecoverInit => check_fn!(ctx, SignRecoverInit),
        Function::SignRecover => check_fn!(ctx, SignRecover),
        Function::VerifyInit => check_fn!(ctx, VerifyInit),
        Function::Verify => check_fn!(ctx, Verify),
        Function::VerifyUpdate => check_fn!(ctx, VerifyUpdate),
        Function::VerifyFinal => check_fn!(ctx, VerifyFinal),
        Function::VerifyRecoverInit => check_fn!(ctx, VerifyRecoverInit),
        Function::VerifyRecover => check_fn!(ctx, VerifyRecover),
        Function::DigestEncryptUpdate => check_fn!(ctx, DigestEncryptUpdate),
        Function::DecryptDigestUpdate => check_fn!(ctx, DecryptDigestUpdate),
        Function::SignEncryptUpdate => check_fn!(ctx, SignEncryptUpdate),
        Function::DecryptVerifyUpdate => check_fn!(ctx, DecryptVerifyUpdate),
        Function::GenerateKey => check_fn!(ctx, GenerateKey),
        Function::GenerateKeyPair => check_fn!(ctx, GenerateKeyPair),
        Function::WrapKey => check_fn!(ctx, WrapKey),
        Function::UnwrapKey => check_fn!(ctx, UnwrapKey),
        Function::DeriveKey => check_fn!(ctx, DeriveKey),
        Function::SeedRandom => check_fn!(ctx, SeedRandom),
        Function::GenerateRandom => check_fn!(ctx, GenerateRandom),
        Function::GetFunctionStatus => check_fn!(ctx, GetFunctionStatus),
        Function::CancelFunction => check_fn!(ctx, CancelFunction),
        Function::WaitForSlotEvent => check_fn!(ctx, WaitForSlotEvent),
    }
}
