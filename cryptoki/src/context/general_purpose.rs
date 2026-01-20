// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! General-purpose functions

use crate::context::{CInitializeArgs, Info, Pkcs11};
use crate::error::{Result, Rv};
use cryptoki_sys::{CK_C_INITIALIZE_ARGS, CK_INFO};
use std::convert::TryFrom;
use std::fmt::Display;
use std::ptr;

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn initialize(ctx: &Pkcs11, init_args: CInitializeArgs) -> Result<()> {
    // if no args are specified, library expects NULL
    let mut init_args = CK_C_INITIALIZE_ARGS::from(init_args);
    let init_args_ptr = &mut init_args;
    unsafe {
        Rv::from(get_pkcs11!(ctx, C_Initialize)(
            init_args_ptr as *mut CK_C_INITIALIZE_ARGS as *mut std::ffi::c_void,
        ))
        .into_result(Function::Initialize)
    }
}

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn finalize(ctx: Pkcs11) -> Result<()> {
    unsafe {
        Rv::from(get_pkcs11!(ctx, C_Finalize)(ptr::null_mut())).into_result(Function::Finalize)
    }
}

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn get_library_info(ctx: &Pkcs11) -> Result<Info> {
    let mut info = CK_INFO::default();
    unsafe {
        Rv::from(get_pkcs11!(ctx, C_GetInfo)(&mut info)).into_result(Function::GetInfo)?;
        Info::try_from(info)
    }
}

macro_rules! check_fn {
    ($pkcs11:expr, $c_func_name:ident) => {{
        // '.$c_func_name' might be unaligned, so copy it out.
        let func = $pkcs11.impl_.get_function_list().$c_func_name;
        func.is_some()
    }};
}

#[allow(missing_docs)]
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
    /* PKCS #11 3.0 */
    GetInterfaceList,
    GetInterface,
    LoginUser,
    SessionCancel,
    MessageEncryptInit,
    EncryptMessage,
    EncryptMessageBegin,
    EncryptMessageNext,
    MessageEncryptFinal,
    MessageDecryptInit,
    DecryptMessage,
    DecryptMessageBegin,
    DecryptMessageNext,
    MessageDecryptFinal,
    MessageSignInit,
    SignMessage,
    SignMessageBegin,
    SignMessageNext,
    MessageSignFinal,
    MessageVerifyInit,
    VerifyMessage,
    VerifyMessageBegin,
    VerifyMessageNext,
    MessageVerifyFinal,
    /* PKCS #11 3.2 */
    EncapsulateKey,
    DecapsulateKey,
    VerifySignatureInit,
    VerifySignature,
    VerifySignatureUpdate,
    VerifySignatureFinal,
    GetSessionValidationFlags,
    AsyncComplete,
    AsyncGetID,
    AsyncJoin,
    WrapKeyAuthenticated,
    UnwrapKeyAuthenticated,
}

impl Display for Function {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Function::{self:?}")
    }
}

#[inline(always)]
pub(super) fn is_fn_supported(ctx: &Pkcs11, function: Function) -> bool {
    match function {
        Function::Initialize => check_fn!(ctx, C_Initialize),
        Function::Finalize => check_fn!(ctx, C_Finalize),
        Function::GetInfo => check_fn!(ctx, C_GetInfo),
        Function::GetFunctionList => check_fn!(ctx, C_GetFunctionList),
        Function::GetSlotList => check_fn!(ctx, C_GetSlotList),
        Function::GetSlotInfo => check_fn!(ctx, C_GetSlotInfo),
        Function::GetTokenInfo => check_fn!(ctx, C_GetTokenInfo),
        Function::GetMechanismList => check_fn!(ctx, C_GetMechanismList),
        Function::GetMechanismInfo => check_fn!(ctx, C_GetMechanismInfo),
        Function::InitToken => check_fn!(ctx, C_InitToken),
        Function::InitPIN => check_fn!(ctx, C_InitPIN),
        Function::SetPIN => check_fn!(ctx, C_SetPIN),
        Function::OpenSession => check_fn!(ctx, C_OpenSession),
        Function::CloseSession => check_fn!(ctx, C_CloseSession),
        Function::CloseAllSessions => check_fn!(ctx, C_CloseAllSessions),
        Function::GetSessionInfo => check_fn!(ctx, C_GetSessionInfo),
        Function::GetOperationState => check_fn!(ctx, C_GetOperationState),
        Function::SetOperationState => check_fn!(ctx, C_SetOperationState),
        Function::Login => check_fn!(ctx, C_Login),
        Function::Logout => check_fn!(ctx, C_Logout),
        Function::CreateObject => check_fn!(ctx, C_CreateObject),
        Function::CopyObject => check_fn!(ctx, C_CopyObject),
        Function::DestroyObject => check_fn!(ctx, C_DestroyObject),
        Function::GetObjectSize => check_fn!(ctx, C_GetObjectSize),
        Function::GetAttributeValue => check_fn!(ctx, C_GetAttributeValue),
        Function::SetAttributeValue => check_fn!(ctx, C_SetAttributeValue),
        Function::FindObjectsInit => check_fn!(ctx, C_FindObjectsInit),
        Function::FindObjects => check_fn!(ctx, C_FindObjects),
        Function::FindObjectsFinal => check_fn!(ctx, C_FindObjectsFinal),
        Function::EncryptInit => check_fn!(ctx, C_EncryptInit),
        Function::Encrypt => check_fn!(ctx, C_Encrypt),
        Function::EncryptUpdate => check_fn!(ctx, C_EncryptUpdate),
        Function::EncryptFinal => check_fn!(ctx, C_EncryptFinal),
        Function::DecryptInit => check_fn!(ctx, C_DecryptInit),
        Function::Decrypt => check_fn!(ctx, C_Decrypt),
        Function::DecryptUpdate => check_fn!(ctx, C_DecryptUpdate),
        Function::DecryptFinal => check_fn!(ctx, C_DecryptFinal),
        Function::DigestInit => check_fn!(ctx, C_DigestInit),
        Function::Digest => check_fn!(ctx, C_Digest),
        Function::DigestUpdate => check_fn!(ctx, C_DigestUpdate),
        Function::DigestKey => check_fn!(ctx, C_DigestKey),
        Function::DigestFinal => check_fn!(ctx, C_DigestFinal),
        Function::SignInit => check_fn!(ctx, C_SignInit),
        Function::Sign => check_fn!(ctx, C_Sign),
        Function::SignUpdate => check_fn!(ctx, C_SignUpdate),
        Function::SignFinal => check_fn!(ctx, C_SignFinal),
        Function::SignRecoverInit => check_fn!(ctx, C_SignRecoverInit),
        Function::SignRecover => check_fn!(ctx, C_SignRecover),
        Function::VerifyInit => check_fn!(ctx, C_VerifyInit),
        Function::Verify => check_fn!(ctx, C_Verify),
        Function::VerifyUpdate => check_fn!(ctx, C_VerifyUpdate),
        Function::VerifyFinal => check_fn!(ctx, C_VerifyFinal),
        Function::VerifyRecoverInit => check_fn!(ctx, C_VerifyRecoverInit),
        Function::VerifyRecover => check_fn!(ctx, C_VerifyRecover),
        Function::DigestEncryptUpdate => check_fn!(ctx, C_DigestEncryptUpdate),
        Function::DecryptDigestUpdate => check_fn!(ctx, C_DecryptDigestUpdate),
        Function::SignEncryptUpdate => check_fn!(ctx, C_SignEncryptUpdate),
        Function::DecryptVerifyUpdate => check_fn!(ctx, C_DecryptVerifyUpdate),
        Function::GenerateKey => check_fn!(ctx, C_GenerateKey),
        Function::GenerateKeyPair => check_fn!(ctx, C_GenerateKeyPair),
        Function::WrapKey => check_fn!(ctx, C_WrapKey),
        Function::UnwrapKey => check_fn!(ctx, C_UnwrapKey),
        Function::DeriveKey => check_fn!(ctx, C_DeriveKey),
        Function::SeedRandom => check_fn!(ctx, C_SeedRandom),
        Function::GenerateRandom => check_fn!(ctx, C_GenerateRandom),
        Function::GetFunctionStatus => check_fn!(ctx, C_GetFunctionStatus),
        Function::CancelFunction => check_fn!(ctx, C_CancelFunction),
        Function::WaitForSlotEvent => check_fn!(ctx, C_WaitForSlotEvent),
        /* PKCS #11 3.0 */
        Function::GetInterfaceList => check_fn!(ctx, C_GetInterfaceList),
        Function::GetInterface => check_fn!(ctx, C_GetInterface),
        Function::LoginUser => check_fn!(ctx, C_LoginUser),
        Function::SessionCancel => check_fn!(ctx, C_SessionCancel),
        Function::MessageEncryptInit => check_fn!(ctx, C_MessageEncryptInit),
        Function::EncryptMessage => check_fn!(ctx, C_EncryptMessage),
        Function::EncryptMessageBegin => check_fn!(ctx, C_EncryptMessageBegin),
        Function::EncryptMessageNext => check_fn!(ctx, C_EncryptMessageNext),
        Function::MessageEncryptFinal => check_fn!(ctx, C_MessageEncryptFinal),
        Function::MessageDecryptInit => check_fn!(ctx, C_MessageDecryptInit),
        Function::DecryptMessage => check_fn!(ctx, C_DecryptMessage),
        Function::DecryptMessageBegin => check_fn!(ctx, C_DecryptMessageBegin),
        Function::DecryptMessageNext => check_fn!(ctx, C_DecryptMessageNext),
        Function::MessageDecryptFinal => check_fn!(ctx, C_MessageDecryptFinal),
        Function::MessageSignInit => check_fn!(ctx, C_MessageSignInit),
        Function::SignMessage => check_fn!(ctx, C_SignMessage),
        Function::SignMessageBegin => check_fn!(ctx, C_SignMessageBegin),
        Function::SignMessageNext => check_fn!(ctx, C_SignMessageNext),
        Function::MessageSignFinal => check_fn!(ctx, C_MessageSignFinal),
        Function::MessageVerifyInit => check_fn!(ctx, C_MessageVerifyInit),
        Function::VerifyMessage => check_fn!(ctx, C_VerifyMessage),
        Function::VerifyMessageBegin => check_fn!(ctx, C_VerifyMessageBegin),
        Function::VerifyMessageNext => check_fn!(ctx, C_VerifyMessageNext),
        Function::MessageVerifyFinal => check_fn!(ctx, C_MessageVerifyFinal),
        /* PKCS #11 3.2 */
        Function::EncapsulateKey => check_fn!(ctx, C_EncapsulateKey),
        Function::DecapsulateKey => check_fn!(ctx, C_DecapsulateKey),
        Function::VerifySignatureInit => check_fn!(ctx, C_VerifySignatureInit),
        Function::VerifySignature => check_fn!(ctx, C_VerifySignature),
        Function::VerifySignatureUpdate => check_fn!(ctx, C_VerifySignatureUpdate),
        Function::VerifySignatureFinal => check_fn!(ctx, C_VerifySignatureFinal),
        Function::GetSessionValidationFlags => check_fn!(ctx, C_GetSessionValidationFlags),
        Function::AsyncComplete => check_fn!(ctx, C_AsyncComplete),
        Function::AsyncGetID => check_fn!(ctx, C_AsyncGetID),
        Function::AsyncJoin => check_fn!(ctx, C_AsyncJoin),
        Function::WrapKeyAuthenticated => check_fn!(ctx, C_WrapKeyAuthenticated),
        Function::UnwrapKeyAuthenticated => check_fn!(ctx, C_UnwrapKeyAuthenticated),
    }
}
