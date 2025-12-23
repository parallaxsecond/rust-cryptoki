// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//
// Mock PKCS#11 library for testing Drop error handling.
// This library simulates token removal scenarios.

#include "pkcs11.h"
#include <string.h>
#include <stdbool.h>

// ============================================================================
// Global state
// ============================================================================

static bool token_removed = false;
static CK_SESSION_HANDLE current_session = 0;

// ============================================================================
// Test API (exported for Rust tests to call)
// ============================================================================

__attribute__((visibility("default")))
void mock_simulate_token_removal(void) {
    token_removed = true;
}

__attribute__((visibility("default")))
void mock_simulate_token_insertion(void) {
    token_removed = false;
}

__attribute__((visibility("default")))
void mock_reset(void) {
    token_removed = false;
    current_session = 0;
}

// ============================================================================
// PKCS#11 Functions
// ============================================================================

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
    (void)pInitArgs;
    mock_reset();
    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
    (void)pReserved;
    return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo) {
    if (pInfo == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    memset(pInfo, 0, sizeof(CK_INFO));
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 40;
    memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
    memcpy(pInfo->manufacturerID, "Mock PKCS#11", 12);
    memset(pInfo->libraryDescription, ' ', sizeof(pInfo->libraryDescription));
    memcpy(pInfo->libraryDescription, "Test Mock Library", 17);
    pInfo->libraryVersion.major = 1;
    pInfo->libraryVersion.minor = 0;
    return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
    (void)tokenPresent;
    if (pulCount == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    if (pSlotList == NULL) {
        *pulCount = 1;
    } else {
        if (*pulCount < 1) {
            return CKR_BUFFER_TOO_SMALL;
        }
        pSlotList[0] = 0;
        *pulCount = 1;
    }
    return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
    (void)slotID;
    if (pInfo == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    memset(pInfo, 0, sizeof(CK_SLOT_INFO));
    memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
    memcpy(pInfo->slotDescription, "Mock Slot", 9);
    memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
    memcpy(pInfo->manufacturerID, "Mock", 4);
    pInfo->flags = token_removed ? 0 : CKF_TOKEN_PRESENT;
    pInfo->hardwareVersion.major = 1;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 1;
    pInfo->firmwareVersion.minor = 0;
    return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
    (void)slotID;
    if (token_removed) {
        return CKR_TOKEN_NOT_PRESENT;
    }
    if (pInfo == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    memset(pInfo, 0, sizeof(CK_TOKEN_INFO));
    memset(pInfo->label, ' ', sizeof(pInfo->label));
    memcpy(pInfo->label, "Mock Token", 10);
    memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
    memcpy(pInfo->manufacturerID, "Mock", 4);
    memset(pInfo->model, ' ', sizeof(pInfo->model));
    memcpy(pInfo->model, "Mock Model", 10);
    memset(pInfo->serialNumber, ' ', sizeof(pInfo->serialNumber));
    memcpy(pInfo->serialNumber, "0001", 4);
    pInfo->flags = CKF_TOKEN_INITIALIZED;
    pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
    pInfo->ulSessionCount = 0;
    pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
    pInfo->ulRwSessionCount = 0;
    pInfo->ulMaxPinLen = 32;
    pInfo->ulMinPinLen = 4;
    pInfo->hardwareVersion.major = 1;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 1;
    pInfo->firmwareVersion.minor = 0;
    return CKR_OK;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
                    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) {
    (void)slotID;
    (void)flags;
    (void)pApplication;
    (void)Notify;
    if (token_removed) {
        return CKR_TOKEN_NOT_PRESENT;
    }
    if (phSession == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    current_session = 1;
    *phSession = current_session;
    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
    if (token_removed) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (hSession != current_session || current_session == 0) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    current_session = 0;
    return CKR_OK;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) {
    (void)slotID;
    current_session = 0;
    return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
    if (token_removed) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (hSession != current_session || current_session == 0) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (pInfo == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    memset(pInfo, 0, sizeof(CK_SESSION_INFO));
    pInfo->slotID = 0;
    pInfo->state = CKS_RO_PUBLIC_SESSION;
    pInfo->flags = CKF_SERIAL_SESSION;
    pInfo->ulDeviceError = 0;
    return CKR_OK;
}

// ============================================================================
// Function list
// ============================================================================

static CK_FUNCTION_LIST functionList = {
    .version = { 2, 40 },
    .C_Initialize = C_Initialize,
    .C_Finalize = C_Finalize,
    .C_GetInfo = C_GetInfo,
    .C_GetFunctionList = NULL,  // Set below
    .C_GetSlotList = C_GetSlotList,
    .C_GetSlotInfo = C_GetSlotInfo,
    .C_GetTokenInfo = C_GetTokenInfo,
    .C_GetMechanismList = NULL,
    .C_GetMechanismInfo = NULL,
    .C_InitToken = NULL,
    .C_InitPIN = NULL,
    .C_SetPIN = NULL,
    .C_OpenSession = C_OpenSession,
    .C_CloseSession = C_CloseSession,
    .C_CloseAllSessions = C_CloseAllSessions,
    .C_GetSessionInfo = C_GetSessionInfo,
    .C_GetOperationState = NULL,
    .C_SetOperationState = NULL,
    .C_Login = NULL,
    .C_Logout = NULL,
    .C_CreateObject = NULL,
    .C_CopyObject = NULL,
    .C_DestroyObject = NULL,
    .C_GetObjectSize = NULL,
    .C_GetAttributeValue = NULL,
    .C_SetAttributeValue = NULL,
    .C_FindObjectsInit = NULL,
    .C_FindObjects = NULL,
    .C_FindObjectsFinal = NULL,
    .C_EncryptInit = NULL,
    .C_Encrypt = NULL,
    .C_EncryptUpdate = NULL,
    .C_EncryptFinal = NULL,
    .C_DecryptInit = NULL,
    .C_Decrypt = NULL,
    .C_DecryptUpdate = NULL,
    .C_DecryptFinal = NULL,
    .C_DigestInit = NULL,
    .C_Digest = NULL,
    .C_DigestUpdate = NULL,
    .C_DigestKey = NULL,
    .C_DigestFinal = NULL,
    .C_SignInit = NULL,
    .C_Sign = NULL,
    .C_SignUpdate = NULL,
    .C_SignFinal = NULL,
    .C_SignRecoverInit = NULL,
    .C_SignRecover = NULL,
    .C_VerifyInit = NULL,
    .C_Verify = NULL,
    .C_VerifyUpdate = NULL,
    .C_VerifyFinal = NULL,
    .C_VerifyRecoverInit = NULL,
    .C_VerifyRecover = NULL,
    .C_DigestEncryptUpdate = NULL,
    .C_DecryptDigestUpdate = NULL,
    .C_SignEncryptUpdate = NULL,
    .C_DecryptVerifyUpdate = NULL,
    .C_GenerateKey = NULL,
    .C_GenerateKeyPair = NULL,
    .C_WrapKey = NULL,
    .C_UnwrapKey = NULL,
    .C_DeriveKey = NULL,
    .C_SeedRandom = NULL,
    .C_GenerateRandom = NULL,
    .C_GetFunctionStatus = NULL,
    .C_CancelFunction = NULL,
    .C_WaitForSlotEvent = NULL,
};

__attribute__((visibility("default")))
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
    if (ppFunctionList == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    functionList.C_GetFunctionList = C_GetFunctionList;
    *ppFunctionList = &functionList;
    return CKR_OK;
}
