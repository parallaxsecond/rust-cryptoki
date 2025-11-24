// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Pkcs11 context and initialization types

/// Directly get the PKCS #11 operation from the context structure and check for null pointers.
/// Note that this macro depends on the get_pkcs11_func! macro.
macro_rules! get_pkcs11 {
    ($pkcs11:expr, $func_name:ident) => {
        (get_pkcs11_func!($pkcs11, $func_name).ok_or(crate::error::Error::NullFunctionPointer)?)
    };
}

/// Same as get_pkcs11! but does not attempt to apply '?' syntactic sugar.
/// Suitable only if the caller can't return a Result.
macro_rules! get_pkcs11_func {
    ($pkcs11:expr, $func_name:ident) => {
        ($pkcs11.impl_.get_function_list().$func_name)
    };
}

mod general_purpose;
mod info;
mod locking;
mod session_management;
mod slot_token_management;

pub use general_purpose::*;
pub use info::*;
pub use locking::*;

use crate::error::{Error, Result, Rv};

use std::fmt;
use std::path::Path;
use std::ptr;

/// Enum for various function lists
/// Each following is super-set of the previous one with overlapping start so we store them
/// in the largest one so we can reference also potentially NULL/non-existing functions
#[derive(Debug)]
enum FunctionList {
    /// PKCS #11 2.40 CK_FUNCTION_LIST
    V2(cryptoki_sys::CK_FUNCTION_LIST_3_2),
    /// PKCS #11 3.0 CK_FUNCTION_LIST_3_0
    V3_0(cryptoki_sys::CK_FUNCTION_LIST_3_2),
    /// PKCS #11 3.2 CK_FUNCTION_LIST_3_2
    V3_2(cryptoki_sys::CK_FUNCTION_LIST_3_2),
}

// Implementation of Pkcs11 class that can be enclosed in a single Arc
pub(crate) struct Pkcs11Impl {
    // Even if this field is never read, it is needed for the pointers in function_list to remain
    // valid.
    _pkcs11_lib: cryptoki_sys::Pkcs11,
    function_list: FunctionList,
}

impl fmt::Debug for Pkcs11Impl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Pkcs11Impl")
            .field("function_list", &self.function_list)
            .finish()
    }
}

impl Pkcs11Impl {
    #[inline(always)]
    pub(crate) fn get_function_list(&self) -> cryptoki_sys::CK_FUNCTION_LIST_3_2 {
        match self.function_list {
            FunctionList::V2(l) => l,
            FunctionList::V3_0(l) => l,
            FunctionList::V3_2(l) => l,
        }
    }
}

/// Main PKCS11 context. Should usually be unique per application.
#[derive(Debug)]
pub struct Pkcs11 {
    pub(crate) impl_: Pkcs11Impl,
}

impl Pkcs11 {
    /// Instantiate a new context from the path of a PKCS11 dynamic library implementation.
    pub fn new<P>(filename: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        unsafe {
            let pkcs11_lib =
                cryptoki_sys::Pkcs11::new(filename.as_ref()).map_err(Error::LibraryLoading)?;
            Self::_new(pkcs11_lib)
        }
    }

    /// Instantiate a new context from current executable, the PKCS11 implementation is contained in the current executable
    pub fn new_from_self() -> Result<Self> {
        unsafe {
            #[cfg(not(windows))]
            let this_lib = libloading::os::unix::Library::this();
            #[cfg(windows)]
            let this_lib = libloading::os::windows::Library::this()?;
            let pkcs11_lib = cryptoki_sys::Pkcs11::from_library(this_lib)?;
            Self::_new(pkcs11_lib)
        }
    }

    unsafe fn _new(pkcs11_lib: cryptoki_sys::Pkcs11) -> Result<Self> {
        /* First try the 3.* API to get default interface. It might have some more functions than
         * the 2.40 API */
        let mut interface: *mut cryptoki_sys::CK_INTERFACE = ptr::null_mut();
        if pkcs11_lib.C_GetInterface.is_ok() {
            Rv::from(pkcs11_lib.C_GetInterface(
                ptr::null_mut(),
                ptr::null_mut(),
                &mut interface,
                0,
            ))
            .into_result(Function::GetInterface)?;
            if !interface.is_null() {
                let ifce: cryptoki_sys::CK_INTERFACE = *interface;

                let list_ptr: *mut cryptoki_sys::CK_FUNCTION_LIST =
                    ifce.pFunctionList as *mut cryptoki_sys::CK_FUNCTION_LIST;
                let list: cryptoki_sys::CK_FUNCTION_LIST = *list_ptr;
                if list.version.major >= 3 {
                    if list.version.minor >= 2 {
                        let list32_ptr: *mut cryptoki_sys::CK_FUNCTION_LIST_3_2 =
                            ifce.pFunctionList as *mut cryptoki_sys::CK_FUNCTION_LIST_3_2;
                        return Ok(Pkcs11 {
                            impl_: Pkcs11Impl {
                                _pkcs11_lib: pkcs11_lib,
                                function_list: FunctionList::V3_2(*list32_ptr),
                            },
                        });
                    }
                    let list30_ptr: *mut cryptoki_sys::CK_FUNCTION_LIST_3_0 =
                        ifce.pFunctionList as *mut cryptoki_sys::CK_FUNCTION_LIST_3_0;
                    return Ok(Pkcs11 {
                        impl_: Pkcs11Impl {
                            _pkcs11_lib: pkcs11_lib,
                            function_list: FunctionList::V3_0(v30tov32(*list30_ptr)),
                        },
                    });
                }
                /* fall back to the 2.* API */
            }
        }

        let mut list_ptr: *mut cryptoki_sys::CK_FUNCTION_LIST = ptr::null_mut();
        Rv::from(pkcs11_lib.C_GetFunctionList(&mut list_ptr))
            .into_result(Function::GetFunctionList)?;

        Ok(Pkcs11 {
            impl_: Pkcs11Impl {
                _pkcs11_lib: pkcs11_lib,
                function_list: FunctionList::V2(v2tov3(*list_ptr)),
            },
        })
    }

    /// Initialize the PKCS11 library
    pub fn initialize(&self, init_args: CInitializeArgs) -> Result<()> {
        initialize(self, init_args)
    }

    /// Finalize the PKCS11 library. Indicates that the application no longer needs to use PKCS11.
    pub fn finalize(self) -> Result<()> {
        finalize(self)
    }

    /// Returns the information about the library
    pub fn get_library_info(&self) -> Result<Info> {
        get_library_info(self)
    }

    /// Check whether a given PKCS11 spec-defined function is supported by this implementation
    pub fn is_fn_supported(&self, function: Function) -> bool {
        is_fn_supported(self, function)
    }
}

// This would be great to be From/Into, but it would have to live inside of the cryptoki-sys
fn v2tov3(f: cryptoki_sys::CK_FUNCTION_LIST) -> cryptoki_sys::CK_FUNCTION_LIST_3_2 {
    cryptoki_sys::CK_FUNCTION_LIST_3_2 {
        version: f.version,
        C_Initialize: f.C_Initialize,
        C_Finalize: f.C_Finalize,
        C_GetInfo: f.C_GetInfo,
        C_GetFunctionList: f.C_GetFunctionList,
        C_GetSlotList: f.C_GetSlotList,
        C_GetSlotInfo: f.C_GetSlotInfo,
        C_GetTokenInfo: f.C_GetTokenInfo,
        C_GetMechanismList: f.C_GetMechanismList,
        C_GetMechanismInfo: f.C_GetMechanismInfo,
        C_InitToken: f.C_InitToken,
        C_InitPIN: f.C_InitPIN,
        C_SetPIN: f.C_SetPIN,
        C_OpenSession: f.C_OpenSession,
        C_CloseSession: f.C_CloseSession,
        C_CloseAllSessions: f.C_CloseAllSessions,
        C_GetSessionInfo: f.C_GetSessionInfo,
        C_GetOperationState: f.C_GetOperationState,
        C_SetOperationState: f.C_SetOperationState,
        C_Login: f.C_Login,
        C_Logout: f.C_Logout,
        C_CreateObject: f.C_CreateObject,
        C_CopyObject: f.C_CopyObject,
        C_DestroyObject: f.C_DestroyObject,
        C_GetObjectSize: f.C_GetObjectSize,
        C_GetAttributeValue: f.C_GetAttributeValue,
        C_SetAttributeValue: f.C_SetAttributeValue,
        C_FindObjectsInit: f.C_FindObjectsInit,
        C_FindObjects: f.C_FindObjects,
        C_FindObjectsFinal: f.C_FindObjectsFinal,
        C_EncryptInit: f.C_EncryptInit,
        C_Encrypt: f.C_Encrypt,
        C_EncryptUpdate: f.C_EncryptUpdate,
        C_EncryptFinal: f.C_EncryptFinal,
        C_DecryptInit: f.C_DecryptInit,
        C_Decrypt: f.C_Decrypt,
        C_DecryptUpdate: f.C_DecryptUpdate,
        C_DecryptFinal: f.C_DecryptFinal,
        C_DigestInit: f.C_DigestInit,
        C_Digest: f.C_Digest,
        C_DigestUpdate: f.C_DigestUpdate,
        C_DigestKey: f.C_DigestKey,
        C_DigestFinal: f.C_DigestFinal,
        C_SignInit: f.C_SignInit,
        C_Sign: f.C_Sign,
        C_SignUpdate: f.C_SignUpdate,
        C_SignFinal: f.C_SignFinal,
        C_SignRecoverInit: f.C_SignRecoverInit,
        C_SignRecover: f.C_SignRecover,
        C_VerifyInit: f.C_VerifyInit,
        C_Verify: f.C_Verify,
        C_VerifyUpdate: f.C_VerifyUpdate,
        C_VerifyFinal: f.C_VerifyFinal,
        C_VerifyRecoverInit: f.C_VerifyRecoverInit,
        C_VerifyRecover: f.C_VerifyRecover,
        C_DigestEncryptUpdate: f.C_DigestEncryptUpdate,
        C_DecryptDigestUpdate: f.C_DecryptDigestUpdate,
        C_SignEncryptUpdate: f.C_SignEncryptUpdate,
        C_DecryptVerifyUpdate: f.C_DecryptVerifyUpdate,
        C_GenerateKey: f.C_GenerateKey,
        C_GenerateKeyPair: f.C_GenerateKeyPair,
        C_WrapKey: f.C_WrapKey,
        C_UnwrapKey: f.C_UnwrapKey,
        C_DeriveKey: f.C_DeriveKey,
        C_SeedRandom: f.C_SeedRandom,
        C_GenerateRandom: f.C_GenerateRandom,
        C_GetFunctionStatus: f.C_GetFunctionStatus,
        C_CancelFunction: f.C_CancelFunction,
        C_WaitForSlotEvent: f.C_WaitForSlotEvent,
        C_GetInterfaceList: None,
        C_GetInterface: None,
        C_LoginUser: None,
        C_SessionCancel: None,
        C_MessageEncryptInit: None,
        C_EncryptMessage: None,
        C_EncryptMessageBegin: None,
        C_EncryptMessageNext: None,
        C_MessageEncryptFinal: None,
        C_MessageDecryptInit: None,
        C_DecryptMessage: None,
        C_DecryptMessageBegin: None,
        C_DecryptMessageNext: None,
        C_MessageDecryptFinal: None,
        C_MessageSignInit: None,
        C_SignMessage: None,
        C_SignMessageBegin: None,
        C_SignMessageNext: None,
        C_MessageSignFinal: None,
        C_MessageVerifyInit: None,
        C_VerifyMessage: None,
        C_VerifyMessageBegin: None,
        C_VerifyMessageNext: None,
        C_MessageVerifyFinal: None,
        C_EncapsulateKey: None,
        C_DecapsulateKey: None,
        C_VerifySignatureInit: None,
        C_VerifySignature: None,
        C_VerifySignatureUpdate: None,
        C_VerifySignatureFinal: None,
        C_GetSessionValidationFlags: None,
        C_AsyncComplete: None,
        C_AsyncGetID: None,
        C_AsyncJoin: None,
        C_WrapKeyAuthenticated: None,
        C_UnwrapKeyAuthenticated: None,
    }
}

fn v30tov32(f: cryptoki_sys::CK_FUNCTION_LIST_3_0) -> cryptoki_sys::CK_FUNCTION_LIST_3_2 {
    cryptoki_sys::CK_FUNCTION_LIST_3_2 {
        version: f.version,
        C_Initialize: f.C_Initialize,
        C_Finalize: f.C_Finalize,
        C_GetInfo: f.C_GetInfo,
        C_GetFunctionList: f.C_GetFunctionList,
        C_GetSlotList: f.C_GetSlotList,
        C_GetSlotInfo: f.C_GetSlotInfo,
        C_GetTokenInfo: f.C_GetTokenInfo,
        C_GetMechanismList: f.C_GetMechanismList,
        C_GetMechanismInfo: f.C_GetMechanismInfo,
        C_InitToken: f.C_InitToken,
        C_InitPIN: f.C_InitPIN,
        C_SetPIN: f.C_SetPIN,
        C_OpenSession: f.C_OpenSession,
        C_CloseSession: f.C_CloseSession,
        C_CloseAllSessions: f.C_CloseAllSessions,
        C_GetSessionInfo: f.C_GetSessionInfo,
        C_GetOperationState: f.C_GetOperationState,
        C_SetOperationState: f.C_SetOperationState,
        C_Login: f.C_Login,
        C_Logout: f.C_Logout,
        C_CreateObject: f.C_CreateObject,
        C_CopyObject: f.C_CopyObject,
        C_DestroyObject: f.C_DestroyObject,
        C_GetObjectSize: f.C_GetObjectSize,
        C_GetAttributeValue: f.C_GetAttributeValue,
        C_SetAttributeValue: f.C_SetAttributeValue,
        C_FindObjectsInit: f.C_FindObjectsInit,
        C_FindObjects: f.C_FindObjects,
        C_FindObjectsFinal: f.C_FindObjectsFinal,
        C_EncryptInit: f.C_EncryptInit,
        C_Encrypt: f.C_Encrypt,
        C_EncryptUpdate: f.C_EncryptUpdate,
        C_EncryptFinal: f.C_EncryptFinal,
        C_DecryptInit: f.C_DecryptInit,
        C_Decrypt: f.C_Decrypt,
        C_DecryptUpdate: f.C_DecryptUpdate,
        C_DecryptFinal: f.C_DecryptFinal,
        C_DigestInit: f.C_DigestInit,
        C_Digest: f.C_Digest,
        C_DigestUpdate: f.C_DigestUpdate,
        C_DigestKey: f.C_DigestKey,
        C_DigestFinal: f.C_DigestFinal,
        C_SignInit: f.C_SignInit,
        C_Sign: f.C_Sign,
        C_SignUpdate: f.C_SignUpdate,
        C_SignFinal: f.C_SignFinal,
        C_SignRecoverInit: f.C_SignRecoverInit,
        C_SignRecover: f.C_SignRecover,
        C_VerifyInit: f.C_VerifyInit,
        C_Verify: f.C_Verify,
        C_VerifyUpdate: f.C_VerifyUpdate,
        C_VerifyFinal: f.C_VerifyFinal,
        C_VerifyRecoverInit: f.C_VerifyRecoverInit,
        C_VerifyRecover: f.C_VerifyRecover,
        C_DigestEncryptUpdate: f.C_DigestEncryptUpdate,
        C_DecryptDigestUpdate: f.C_DecryptDigestUpdate,
        C_SignEncryptUpdate: f.C_SignEncryptUpdate,
        C_DecryptVerifyUpdate: f.C_DecryptVerifyUpdate,
        C_GenerateKey: f.C_GenerateKey,
        C_GenerateKeyPair: f.C_GenerateKeyPair,
        C_WrapKey: f.C_WrapKey,
        C_UnwrapKey: f.C_UnwrapKey,
        C_DeriveKey: f.C_DeriveKey,
        C_SeedRandom: f.C_SeedRandom,
        C_GenerateRandom: f.C_GenerateRandom,
        C_GetFunctionStatus: f.C_GetFunctionStatus,
        C_CancelFunction: f.C_CancelFunction,
        C_WaitForSlotEvent: f.C_WaitForSlotEvent,
        C_GetInterfaceList: f.C_GetInterfaceList,
        C_GetInterface: f.C_GetInterface,
        C_LoginUser: f.C_LoginUser,
        C_SessionCancel: f.C_SessionCancel,
        C_MessageEncryptInit: f.C_MessageEncryptInit,
        C_EncryptMessage: f.C_EncryptMessage,
        C_EncryptMessageBegin: f.C_EncryptMessageBegin,
        C_EncryptMessageNext: f.C_EncryptMessageNext,
        C_MessageEncryptFinal: f.C_MessageEncryptFinal,
        C_MessageDecryptInit: f.C_MessageDecryptInit,
        C_DecryptMessage: f.C_DecryptMessage,
        C_DecryptMessageBegin: f.C_DecryptMessageBegin,
        C_DecryptMessageNext: f.C_DecryptMessageNext,
        C_MessageDecryptFinal: f.C_MessageDecryptFinal,
        C_MessageSignInit: f.C_MessageSignInit,
        C_SignMessage: f.C_SignMessage,
        C_SignMessageBegin: f.C_SignMessageBegin,
        C_SignMessageNext: f.C_SignMessageNext,
        C_MessageSignFinal: f.C_MessageSignFinal,
        C_MessageVerifyInit: f.C_MessageVerifyInit,
        C_VerifyMessage: f.C_VerifyMessage,
        C_VerifyMessageBegin: f.C_VerifyMessageBegin,
        C_VerifyMessageNext: f.C_VerifyMessageNext,
        C_MessageVerifyFinal: f.C_MessageVerifyFinal,
        C_EncapsulateKey: None,
        C_DecapsulateKey: None,
        C_VerifySignatureInit: None,
        C_VerifySignature: None,
        C_VerifySignatureUpdate: None,
        C_VerifySignatureFinal: None,
        C_GetSessionValidationFlags: None,
        C_AsyncComplete: None,
        C_AsyncGetID: None,
        C_AsyncJoin: None,
        C_WrapKeyAuthenticated: None,
        C_UnwrapKeyAuthenticated: None,
    }
}
