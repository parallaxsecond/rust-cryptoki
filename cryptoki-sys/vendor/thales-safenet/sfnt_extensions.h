/***************************************************************************
 *
 *  Filename:      sfnt_extensions.h
 *
 *  Description:   Function prototypes, typedefs, etc. for PKCS #11 API.
 *
 * This file is protected by laws protecting trade secrets and confidential
 * information, as well as copyright laws and international treaties.
 * Copyright (c) 2004 SafeNet, Inc. All rights reserved.
 *
 * This file contains confidential and proprietary information of
 * SafeNet, Inc. and its licensors and may not be
 * copied (in any manner), distributed (by any means) or transferred
 * without prior written consent from SafeNet, Inc.
 ********************VERY IMPORTANT******************************************
 * DO NOT ADD ANY NEW SAFENET EXTENSIONS TO ./cryptoki/cryptoki.h
 * ADD ALL NEW TYPE DEFINITION EXTENSIONS TO /cryptoki/cryptoki_v2.h
 * ADD ALL CA_ FUNCTION EXTENSIONS TO /cryptoki/sfnt_extensions.h
 ****************************************************************************/
// add all SafeNet CA_ extension functions here

CK_RV CK_ENTRY
CA_GetFunctionList(CK_SFNT_CA_FUNCTION_LIST_PTR_PTR ppSfntFunctionList);

CK_RV CK_ENTRY CA_WaitForSlotEvent(CK_FLAGS flags, CK_ULONG history[2],
                                   CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved);

CK_RV CK_ENTRY CA_InitIndirectToken(CK_SLOT_ID slotID, CK_CHAR_PTR pPin,
                                    CK_ULONG usPinLen, CK_CHAR_PTR pLabel,
                                    CK_SESSION_HANDLE hPrimarySession);

CK_RV CK_ENTRY CA_InitIndirectPIN(CK_SESSION_HANDLE hSession, CK_CHAR_PTR pPin,
                                  CK_ULONG usPinLen,
                                  CK_SESSION_HANDLE hPrimarySession);

CK_RV CK_ENTRY CA_ResetPIN(CK_SESSION_HANDLE hSession, CK_CHAR_PTR pPin,
                           CK_ULONG usPinLen);

CK_RV CK_ENTRY CA_CreateLoginChallenge(CK_SESSION_HANDLE hSession,
                                       CK_USER_TYPE userType,
                                       CK_ULONG ulChallengeDataSize,
                                       CK_CHAR_PTR pChallengeData,
                                       CK_ULONG_PTR ulOutputDataSize,
                                       CK_CHAR_PTR pOutputData);

CK_RV CK_ENTRY CA_Deactivate(CK_SLOT_ID slotId, CK_USER_TYPE userType);

/****************************************************************************\
*                                                                            *
* Session management                                                         *
*                                                                            *
\****************************************************************************/

CK_RV CK_ENTRY CA_OpenSession(CK_SLOT_ID slotID, CK_ULONG ulContainerNumber,
                              CK_FLAGS flags, CK_VOID_PTR pApplication,
                              CK_NOTIFY Notify,
                              CK_SESSION_HANDLE_PTR phSession);

CK_RV CK_ENTRY CA_IndirectLogin(CK_SESSION_HANDLE hSession,
                                CK_USER_TYPE userType,
                                CK_SESSION_HANDLE hPrimarySession);

/****************************************************************************\
*                                                                            *
* Remote PED                                                                 *
*                                                                            *
\****************************************************************************/
CK_RV CK_ENTRY CA_InitializeRemotePEDVector(CK_SESSION_HANDLE hSession);

CK_RV CK_ENTRY CA_DeleteRemotePEDVector(CK_SESSION_HANDLE hSession);

CK_RV CK_ENTRY CA_GetRemotePEDVectorStatus(CK_SLOT_ID slotID,
                                           CK_ULONG_PTR pulStatus);

CK_RV CK_ENTRY CA_ConfigureRemotePED(CK_SLOT_ID slotId, CK_CHAR_PTR pHostName,
                                     CK_ULONG ulPort, CK_ULONG_PTR pulPedId);

CK_RV CK_ENTRY CA_DismantleRemotePED(CK_SLOT_ID slotId, CK_ULONG ulPedId);

/****************************************************************************\
*                                                                            *
* Application access management                                              *
*                                                                            *
\****************************************************************************/
CK_RV CK_ENTRY CA_Restart(CK_SLOT_ID slotID);
CK_RV CK_ENTRY CA_RestartForContainer(CK_SLOT_ID slotID,
                                      CK_ULONG ulContainerNumber);
CK_RV CK_ENTRY CA_CloseApplicationID(CK_SLOT_ID slotID, CK_ULONG ulHigh,
                                     CK_ULONG ulLow);
CK_RV CK_ENTRY CA_CloseApplicationIDForContainer(CK_SLOT_ID slotID,
                                                 CK_ULONG ulHigh,
                                                 CK_ULONG ulLow,
                                                 CK_ULONG ulContainerNumber);

CK_RV CK_ENTRY CA_OpenApplicationID(CK_SLOT_ID slotID, CK_ULONG ulHigh,
                                    CK_ULONG ulLow);
CK_RV CK_ENTRY CA_OpenApplicationIDForContainer(CK_SLOT_ID slotID,
                                                CK_ULONG ulHigh, CK_ULONG ulLow,
                                                CK_ULONG ulContainerNumber);

CK_RV CK_ENTRY CA_SetApplicationID(CK_ULONG ulHigh, CK_ULONG ulLow);

/****************************************************************************\
*                                                                            *
* Callbacks                                                                  *
*                                                                            *
\****************************************************************************/
/*CK_RV CK_ENTRY Notify(CK_SESSION_HANDLE hSession,
                      CK_NOTIFICATION event,
                      CK_VOID_PTR pApplication);*/

/****************************************************************************\
*
* Certificate Authority
*
\****************************************************************************/
CK_RV CK_ENTRY CA_ManualKCV(CK_SESSION_HANDLE hSession);
CK_RV CK_ENTRY CA_SetLKCV(CK_SESSION_HANDLE hSession,
                          CK_BYTE_PTR pLegacyCloningDomainString,
                          CK_ULONG ulLegacyCloningDomainStringLen);
CK_RV CK_ENTRY CA_SetKCV(CK_SESSION_HANDLE hSession,
                         CK_BYTE_PTR pCloningDomainString,
                         CK_ULONG ulCloningDomainStringLen);
CK_RV CK_ENTRY CA_SetCloningDomain(CK_BYTE_PTR pCloningDomainString,
                                   CK_ULONG ulCloningDomainStringLen);
CK_RV CK_ENTRY CA_ClonePrivateKey(CK_SESSION_HANDLE hTargetSession,
                                  CK_SESSION_HANDLE hSourceSession,
                                  CK_OBJECT_HANDLE hObjectToCloneHandle,
                                  CK_OBJECT_HANDLE_PTR phClonedKey);
CK_RV CK_ENTRY CA_CloneObject(CK_SESSION_HANDLE hTargetSession,
                              CK_SESSION_HANDLE hSourceSession,
                              CK_ULONG ulObjectType,
                              CK_OBJECT_HANDLE hObjectHandle,
                              CK_OBJECT_HANDLE_PTR phClonedObject);

CK_RV CK_ENTRY CA_GenerateCloningKEV(CK_SESSION_HANDLE hSession,
                                     CK_BYTE_PTR pKEV, CK_ULONG_PTR pulKEVSize);

CK_RV CK_ENTRY CA_CloneAsTargetInit(CK_SESSION_HANDLE hSession,
                                    CK_BYTE_PTR pTWC, CK_ULONG ulTWCSize,
                                    CK_BYTE_PTR pKEV, CK_ULONG ulKEVSize,
                                    CK_BBOOL bReplicate, CK_BYTE_PTR pPart1,
                                    CK_ULONG_PTR pulPart1Size);

CK_RV CK_ENTRY CA_CloneAsSource(CK_SESSION_HANDLE hSession, CK_ULONG hType,
                                CK_ULONG hHandle, CK_BYTE_PTR pPart1,
                                CK_ULONG ulPart1Size, CK_BBOOL bReplicate,
                                CK_BYTE_PTR pPart2, CK_ULONG_PTR pulPart2Size);

CK_RV CK_ENTRY CA_CloneAsTarget(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pKEV,
                                CK_ULONG ulKEVSize, CK_BYTE_PTR pPart2,
                                CK_ULONG ulPart2Size, CK_ULONG hType,
                                CK_ULONG hHandle, CK_BBOOL bReplicate,
                                CK_OBJECT_HANDLE_PTR phClonedHandle);

CK_RV CK_ENTRY CA_SetMofN(CK_BBOOL bFlag);
CK_RV CK_ENTRY CA_GenerateMofN(CK_SESSION_HANDLE hSession, CK_ULONG ulM,
                               CA_MOFN_GENERATION_PTR pVectors,
                               CK_ULONG ulVectorCount,
                               CK_ULONG isSecurePortUsed,
                               CK_VOID_PTR pReserved);
CK_RV CK_ENTRY CA_GenerateCloneableMofN(
    CK_SESSION_HANDLE hSession, CK_ULONG ulM, CA_MOFN_GENERATION_PTR pVectors,
    CK_ULONG ulVectorCount, CK_ULONG isSecurePortUsed, CK_VOID_PTR pReserved);
CK_RV CK_ENTRY CA_ModifyMofN(CK_SESSION_HANDLE hSession, CK_ULONG ulM,
                             CA_MOFN_GENERATION_PTR pVectors,
                             CK_ULONG ulVectorCount, CK_ULONG isSecurePortUsed,
                             CK_VOID_PTR pReserved);
CK_RV CK_ENTRY CA_CloneMofN(CK_SESSION_HANDLE hSession,
                            CK_SESSION_HANDLE hPrimarySession,
                            CK_VOID_PTR pReserved);
CK_RV CK_ENTRY CA_CloneModifyMofN(CK_SESSION_HANDLE hSession,
                                  CK_SESSION_HANDLE hPrimarySession,
                                  CK_VOID_PTR pReserved);
CK_RV CK_ENTRY CA_ActivateMofN(CK_SESSION_HANDLE hSession,
                               CA_MOFN_ACTIVATION_PTR pVectors,
                               CK_ULONG ulVectorCount);
CK_RV CK_ENTRY CA_DeactivateMofN(CK_SESSION_HANDLE hSession);

CK_RV CK_ENTRY CA_GetMofNStatus(CK_SLOT_ID slotID,
                                CA_MOFN_STATUS_PTR pMofNStatus);

CK_RV CK_ENTRY CA_DuplicateMofN(CK_SESSION_HANDLE hSession);

CK_RV CK_ENTRY CA_IsMofNEnabled(CK_SLOT_ID slotID, CK_ULONG_PTR enabled);

CK_RV CK_ENTRY CA_IsMofNRequired(CK_SLOT_ID slotID, CK_ULONG_PTR required);

/****************************************************************************\
*
* Token Certificate Management
*
\****************************************************************************/
CK_RV CK_ENTRY CA_GenerateTokenKeys(CK_SESSION_HANDLE hSession,
                                    CK_ATTRIBUTE_PTR pTemplate,
                                    CK_ULONG usTemplateLen);
CK_RV CK_ENTRY CA_GetTokenCertificateInfo(CK_SLOT_ID slotID,
                                          CK_ULONG ulAccessLevel,
                                          CK_BYTE_PTR pCertificate,
                                          CK_ULONG_PTR pulCertificateLen);
CK_RV CK_ENTRY CA_SetTokenCertificateSignature(
    CK_SESSION_HANDLE hSession, CK_ULONG ulAccessLevel, CK_ULONG ulCustomerId,
    CK_ATTRIBUTE_PTR pPublicTemplate, CK_ULONG usPublicTemplateLen,
    CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);

CK_RV CK_ENTRY CA_GetModuleList(CK_SLOT_ID slotId, CKCA_MODULE_ID_PTR pList,
                                CK_ULONG ulListLen,
                                CK_ULONG_PTR pulReturnedSize);

CK_RV CK_ENTRY CA_GetModuleInfo(CK_SLOT_ID slotId, CKCA_MODULE_ID moduleId,
                                CKCA_MODULE_INFO_PTR pInfo);

CK_RV CK_ENTRY
CA_LoadModule(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pModuleCode,
              CK_ULONG ulModuleCodeSize, CK_BYTE_PTR pModuleSignature,
              CK_ULONG ulModuleSignatureSize, CK_BYTE_PTR pCertificate,
              CK_ULONG ulCertificateSize, CK_BYTE_PTR pControlData,
              CK_ULONG ulControlDataSize, CKCA_MODULE_ID_PTR pModuleId);

CK_RV CK_ENTRY CA_LoadEncryptedModule(
    CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pIv,
    CK_ULONG ulIvLen, CK_BYTE_PTR pModuleCode, CK_ULONG ulModuleCodeSize,
    CK_BYTE_PTR pModuleSignature, CK_ULONG ulModuleSignatureSize,
    CK_BYTE_PTR pCertificate, CK_ULONG ulCertificateSize,
    CKCA_MODULE_ID_PTR pModuleId);

CK_RV CK_ENTRY CA_UnloadModule(CK_SESSION_HANDLE hSession,
                               CKCA_MODULE_ID moduleId);

CK_RV CK_ENTRY CA_PerformModuleCall(CK_SESSION_HANDLE hSession,
                                    CKCA_MODULE_ID moduleId,
                                    CK_BYTE_PTR pRequest,
                                    CK_ULONG ulRequestSize, CK_BYTE_PTR pAnswer,
                                    CK_ULONG ulAnswerSize,
                                    CK_ULONG_PTR pulAnswerAvailable);

CK_RV CK_ENTRY C_PerformSelfTest(CK_SLOT_ID slotID, CK_ULONG typeOfTest,
                                 CK_BYTE_PTR inputData,
                                 CK_ULONG sizeOfInputData,
                                 CK_BYTE_PTR outputData,
                                 CK_ULONG_PTR sizeOfOutputData);

/****************************************************************************\
*
* HSM Update
*
\****************************************************************************/
CK_RV CK_ENTRY CA_FirmwareUpdate(CK_SESSION_HANDLE hSession,
                                 CK_ULONG ulTargetHardwarePlatform,
                                 CK_ULONG ulAuthCodeLen, CK_BYTE_PTR pAuthCode,
                                 CK_ULONG ulManifestLen, CK_BYTE_PTR pManifest,
                                 CK_ULONG ulFirmwareLen, CK_BYTE_PTR pFirmware);

CK_RV CK_ENTRY CA_FirmwareRollback(CK_SESSION_HANDLE hSession);

CK_RV CK_ENTRY CA_CapabilityUpdate(CK_SESSION_HANDLE hSession,
                                   CK_ULONG ulManifestLen,
                                   CK_BYTE_PTR pManifest,
                                   CK_ULONG ulAuthcodeLen,
                                   CK_BYTE_PTR pAuthcode);

/****************************************************************************\
*
* Policy bit manipulations
*
\****************************************************************************/

CK_RV CK_ENTRY CA_GetUserContainerNumber(CK_SLOT_ID slotID,
                                         CK_ULONG_PTR pulContainerNumber);

CK_RV CK_ENTRY CA_GetUserContainerName(CK_SLOT_ID slotID, CK_BYTE_PTR pName,
                                       CK_ULONG_PTR pulNameLen);

CK_RV CK_ENTRY CA_SetUserContainerName(CK_SLOT_ID slotID, CK_BYTE_PTR pName,
                                       CK_ULONG ulNameLen);

CK_RV CK_ENTRY CA_GetTokenInsertionCount(CK_SLOT_ID slotID,
                                         CK_ULONG_PTR pulCount);

CK_RV CK_ENTRY CA_GetRollbackFirmwareVersion(CK_SLOT_ID slotID,
                                             CK_ULONG_PTR pulVersion);

CK_RV CK_ENTRY CA_GetFPV(CK_SLOT_ID slotID, CK_ULONG_PTR pulFpv);

CK_RV CK_ENTRY CA_GetTPV(CK_SLOT_ID slotID, CK_ULONG_PTR pulTpv);

CK_RV CK_ENTRY CA_GetExtendedTPV(CK_SLOT_ID slotID, CK_ULONG_PTR pulTpv,
                                 CK_ULONG_PTR pulTpvExt);

CK_RV CK_ENTRY CA_GetConfigurationElementDescription(
    CK_SLOT_ID slotID, CK_ULONG ulIsContainerElement,
    CK_ULONG ulIsCapabilityElement, CK_ULONG ulElementId,
    CK_ULONG_PTR pulElementBitLength, CK_ULONG_PTR pulElementDestructive,
    CK_ULONG_PTR pulElementWriteRestricted, CK_CHAR_PTR pDescription);

CK_RV CK_ENTRY CA_GetHSMCapabilitySet(CK_SLOT_ID uPhysicalSlot,
                                      CK_ULONG_PTR pulCapIdArray,
                                      CK_ULONG_PTR pulCapIdSize,
                                      CK_ULONG_PTR pulCapValArray,
                                      CK_ULONG_PTR pulCapValSize);

CK_RV CK_ENTRY CA_GetHSMCapabilitySetting(CK_SLOT_ID slotID,
                                          CK_ULONG ulPolicyId,
                                          CK_ULONG_PTR pulPolicyValue);

CK_RV CK_ENTRY CA_GetHSMPolicySet(CK_SLOT_ID uPhysicalSlot,
                                  CK_ULONG_PTR pulPolicyIdArray,
                                  CK_ULONG_PTR pulPolicyIdSize,
                                  CK_ULONG_PTR pulPolicyValArray,
                                  CK_ULONG_PTR pulPolicyValSize);

CK_RV CK_ENTRY CA_GetHSMPolicySetting(CK_SLOT_ID slotID, CK_ULONG ulPolicyId,
                                      CK_ULONG_PTR pulPolicyValue);

CK_RV CK_ENTRY CA_GetContainerCapabilitySet(CK_SLOT_ID uPhysicalSlot,
                                            CK_ULONG ulContainerNumber,
                                            CK_ULONG_PTR pulCapIdArray,
                                            CK_ULONG_PTR pulCapIdSize,
                                            CK_ULONG_PTR pulCapValArray,
                                            CK_ULONG_PTR pulCapValSize);

CK_RV CK_ENTRY CA_GetContainerCapabilitySetting(CK_SLOT_ID slotID,
                                                CK_ULONG ulContainerNumber,
                                                CK_ULONG ulPolicyId,
                                                CK_ULONG_PTR pulPolicyValue);

CK_RV CK_ENTRY CA_GetContainerPolicySet(CK_SLOT_ID uPhysicalSlot,
                                        CK_ULONG ulContainerNumber,
                                        CK_ULONG_PTR pulPolicyIdArray,
                                        CK_ULONG_PTR pulPolicyIdSize,
                                        CK_ULONG_PTR pulPolicyValArray,
                                        CK_ULONG_PTR pulPolicyValSize);

CK_RV CK_ENTRY CA_GetContainerPolicySetting(CK_SLOT_ID uPhysicalSlot,
                                            CK_ULONG ulContainerNumber,
                                            CK_ULONG ulPolicyId,
                                            CK_ULONG_PTR pulPolicyValue);

CK_RV CK_ENTRY CA_SetTPV(CK_SESSION_HANDLE hSession, CK_ULONG ulTpv);

CK_RV CK_ENTRY CA_SetExtendedTPV(CK_SESSION_HANDLE hSession, CK_ULONG ulTpv,
                                 CK_ULONG ulTpvExt);

CK_RV CK_ENTRY CA_SetHSMPolicy(CK_SESSION_HANDLE hSession, CK_ULONG ulPolicyId,
                               CK_ULONG ulPolicyValue);

CK_RV CK_ENTRY CA_SetHSMPolicies(CK_SESSION_HANDLE hSession,
                                 CK_ULONG ulPolicyCount,
                                 CK_ULONG_PTR pulPolicyIdArray,
                                 CK_ULONG_PTR pulPolicyValueArray);

CK_RV CK_ENTRY CA_SetDestructiveHSMPolicy(CK_SESSION_HANDLE hSession,
                                          CK_ULONG ulPolicyId,
                                          CK_ULONG ulPolicyValue);

CK_RV CK_ENTRY CA_SetDestructiveHSMPolicies(CK_SESSION_HANDLE hSession,
                                            CK_ULONG ulPolicyCount,
                                            CK_ULONG_PTR pulPolicyIdArray,
                                            CK_ULONG_PTR pulPolicyValueArray);

CK_RV CK_ENTRY CA_SetContainerPolicy(CK_SESSION_HANDLE hSession,
                                     CK_ULONG ulContainer, CK_ULONG ulPolicyId,
                                     CK_ULONG ulPolicyValue);

CK_RV CK_ENTRY CA_SetContainerPolicies(CK_SESSION_HANDLE hSession,
                                       CK_ULONG ulContainer,
                                       CK_ULONG ulPolicyCount,
                                       CK_ULONG_PTR pulPolicyIdArray,
                                       CK_ULONG_PTR pulPolicyValueArray);

/****************************************************************************\
*
* SafeNet functions
*
* These functions are implemented for use by SafeNet, Inc. tools.  They
* should not be used by Toolkit customers
*
\****************************************************************************/
CK_RV CK_ENTRY CA_RetrieveLicenseList(CK_SLOT_ID slotID,
                                      CK_ULONG_PTR pulidArraySize,
                                      CK_ULONG_PTR pulidArray);
CK_RV CK_ENTRY CA_QueryLicense(CK_SLOT_ID slotID, CK_ULONG licenseIdLow,
                               CK_ULONG licenseIdHigh,
                               CK_ULONG_PTR pulLicenseType,
                               CK_ULONG_PTR pulDescVersion,
                               CK_ULONG_PTR pulDescSize,
                               CK_BYTE_PTR pbDescBuffer);

CK_RV CK_ENTRY CA_GetContainerStatus(CK_SLOT_ID slotID,
                                     CK_ULONG ulContainerNumber,
                                     CK_ULONG_PTR pulContainerStatusFlags,
                                     CK_ULONG_PTR pulFailedSOLogins,
                                     CK_ULONG_PTR pulFailedUserLogins,
                                     CK_ULONG_PTR pulFailedLimitedUserLogins);

CK_RV CK_ENTRY CA_GetSessionInfo(CK_SESSION_HANDLE hSession,
                                 CK_ULONG_PTR pulAidHigh,
                                 CK_ULONG_PTR pulAidLow,
                                 CK_ULONG_PTR pulContainerNumber,
                                 CK_ULONG_PTR pulAuthenticationLevel);

CK_RV CK_ENTRY CA_ReadCommonStore(CK_ULONG index, CK_BYTE_PTR pBuffer,
                                  CK_ULONG_PTR pulBufferSize);
CK_RV CK_ENTRY CA_WriteCommonStore(CK_ULONG index, CK_BYTE_PTR pBuffer,
                                   CK_ULONG ulBufferSize);

CK_RV CK_ENTRY CA_GetPrimarySlot(CK_SESSION_HANDLE hSession,
                                 CK_SLOT_ID_PTR slotId_p);
CK_RV CK_ENTRY CA_GetSecondarySlot(CK_SESSION_HANDLE hSession,
                                   CK_SLOT_ID_PTR slotId_p);
CK_RV CK_ENTRY CA_SwitchSecondarySlot(CK_SESSION_HANDLE hSession,
                                      CK_SLOT_ID slotID, CK_ULONG slotInstance);
CK_RV CK_ENTRY CA_CloseSecondarySession(CK_SESSION_HANDLE hSession,
                                        CK_SLOT_ID slotID,
                                        CK_ULONG slotInstance);
CK_RV CK_ENTRY CA_CloseAllSecondarySessions(CK_SESSION_HANDLE hSession);
CK_RV CK_ENTRY CA_ChoosePrimarySlot(CK_SESSION_HANDLE hSession);
CK_RV CK_ENTRY CA_ChooseSecondarySlot(CK_SESSION_HANDLE hSession);

CK_RV CK_ENTRY CA_CloneObjectToAllSessions(CK_SESSION_HANDLE hSession,
                                           CK_OBJECT_HANDLE hObject);
CK_RV CK_ENTRY CA_CloneAllObjectsToSession(CK_SESSION_HANDLE hSession,
                                           CK_SLOT_ID slotId);

CK_RV CK_ENTRY GetTotalOperations(CK_SLOT_ID slotId, int *operations);
CK_RV CK_ENTRY ResetTotalOperations(CK_SLOT_ID slotId);

CK_RV CK_ENTRY CA_ResetDevice(CK_SLOT_ID slotId, CK_FLAGS flags);

CK_RV CK_ENTRY CA_FactoryReset(CK_SLOT_ID slotId, CK_FLAGS flags);

CK_RV CK_ENTRY CA_SetPedId(CK_SLOT_ID slotId, CK_ULONG usPedId);

CK_RV CK_ENTRY CA_GetPedId(CK_SLOT_ID slotId, CK_ULONG *usPedId);

CK_RV CK_ENTRY CA_SpRawRead(CK_SLOT_ID slotId, CK_ULONG_PTR data);

CK_RV CK_ENTRY CA_SpRawWrite(CK_SLOT_ID slotId, CK_ULONG_PTR data);

CK_RV CK_ENTRY CA_CheckOperationState(CK_SESSION_HANDLE hSession,
                                      CK_ULONG operation, CK_BBOOL *pactive);

CK_RV CK_ENTRY CA_SinglePartSign(CK_SESSION_HANDLE hSession,
                                 CK_MECHANISM_PTR pMechanism,
                                 CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pData,
                                 CK_ULONG usDataLen, CK_BYTE_PTR pSignature,
                                 CK_ULONG_PTR pusSignatureLen);

CK_RV CK_ENTRY CA_SinglePartDecrypt(CK_SESSION_HANDLE hSession,
                                    CK_MECHANISM_PTR pMechanism,
                                    CK_OBJECT_HANDLE hUnwrappingKey,
                                    CK_BYTE_PTR pWrappedKey,
                                    CK_ULONG usWrappedKeyLen,
                                    CK_BYTE_PTR pUnwrappedKey,
                                    CK_ULONG_PTR pusUnwrappedKeyLen);

CK_RV CK_ENTRY CA_DestroyMultipleObjects(CK_SESSION_HANDLE hSession,
                                         CK_ULONG ulHandleCount,
                                         CK_OBJECT_HANDLE_PTR pHandleList,
                                         CK_ULONG_PTR pulIndex);

/****************************************************************************\
*
* SafeNet High Availability Recovery functions
*
\****************************************************************************/
CK_RV CK_ENTRY CA_HAInit(CK_SESSION_HANDLE hSession,
                         CK_OBJECT_HANDLE hLoginPrivateKey);

CK_RV CK_ENTRY CA_HAGetMasterPublic(CK_SLOT_ID slotId, CK_BYTE_PTR pCertificate,
                                    CK_ULONG_PTR pulCertificate);

CK_RV CK_ENTRY CA_HAGetLoginChallenge(CK_SESSION_HANDLE hSession,
                                      CK_USER_TYPE userType,
                                      CK_BYTE_PTR pCertificate,
                                      CK_ULONG ulCertificateLen,
                                      CK_BYTE_PTR pChallengeBlob,
                                      CK_ULONG_PTR pulChallengeBlobLen);

CK_RV CK_ENTRY CA_HAAnswerLoginChallenge(CK_SESSION_HANDLE hSession,
                                         CK_OBJECT_HANDLE hLoginPrivateKey,
                                         CK_BYTE_PTR pChallengeBlob,
                                         CK_ULONG ulChallengeBlobLen,
                                         CK_BYTE_PTR pEncryptedPin,
                                         CK_ULONG_PTR pulEncryptedPinLen);

CK_RV CK_ENTRY CA_HALogin(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPin,
                          CK_ULONG ulEncryptedPinLen, CK_BYTE_PTR pMofNBlob,
                          CK_ULONG_PTR pulMofNBlobLen);

CK_RV CK_ENTRY CA_HAAnswerMofNChallenge(CK_SESSION_HANDLE hSession,
                                        CK_BYTE_PTR pMofNBlob,
                                        CK_ULONG ulMofNBlobLen,
                                        CK_BYTE_PTR pMofNSecretBlob,
                                        CK_ULONG_PTR pulMofNSecretBlobLen);

CK_RV CK_ENTRY CA_HAActivateMofN(CK_SESSION_HANDLE hSession,
                                 CK_BYTE_PTR pMofNSecretBlob,
                                 CK_ULONG ulMofNSecretBlobLen);

CK_RV CK_ENTRY CA_GetHAState(CK_SLOT_ID slotId, CK_HA_STATE_PTR pState);

CK_RV CK_ENTRY CA_GetTokenCertificates(CK_SLOT_ID slotID, CK_ULONG ulCertType,
                                       CK_BYTE_PTR pCertificate,
                                       CK_ULONG_PTR pulCertificateLen);

/****************************************************************************\
*
* SafeNet Offboard Key Storage Functions
*
\****************************************************************************/

CK_RV CK_ENTRY CA_ExtractMaskedObject(CK_SESSION_HANDLE hSession,
                                      CK_ULONG ulObjectHandle,
                                      CK_BYTE_PTR pMaskedKey,
                                      CK_ULONG_PTR pusMaskedKeyLen);

CK_RV CK_ENTRY CA_InsertMaskedObject(CK_SESSION_HANDLE hSession,
                                     CK_ULONG_PTR pulObjectHandle,
                                     CK_BYTE_PTR pMaskedKey,
                                     CK_ULONG usMaskedKeyLen);

CK_RV CK_ENTRY CA_MultisignValue(
    CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_ULONG ulMaskedKeyLen, CK_BYTE_PTR pMaskedKey, CK_ULONG_PTR pulBlobCount,
    CK_ULONG_PTR pulBlobLens, CK_BYTE_PTR CK_PTR ppBlobs,
    CK_ULONG_PTR pulSignatureLens, CK_BYTE_PTR CK_PTR ppSignatures);

//////////////////////////////////////////////////////////////////////
//
// Function: CA_SIMExtract
//
// Description: Use the SIM functionality to extract a set of objects
//     from the HSM.  The objects are returned as a "blob".  This
//     blob may be reinserted later (using CA_SIMInsert) or used with
//     the CA_SIMMultiSign function.
//
//     Note that this function supports the ability to return the size
//     of the blob and the blob itself in two separate calls.  If the
//     function is invoked with a null pBlob pointer, only the size of
//     the blob will be returned.  A subsequent call with identical
//     parameters will return the blob itself.  If the blob is to
//     be retrieved, the *pulBlobSize value should be initialized with
//     the size of the buffer available to receive the blob.
//
//     The blob is protected by authorization data, as specified by
//     the parameters.  The ulAuthSecretCount specifies how many
//     authorization secrets are defined, and the ulAuthSubsetCount
//     parameter specifies how many must be presented before the
//     blob may be used with CA_SIMInsert or CA_SIMMultiSign.
//
//     Any number of objects may be extracted with a single call to
//     CA_SIMExtract.  The ulHandleCount and pHandleList parameters
//     specify a list of handles of the objects to be extracted.
//     If a ulHandleCount of zero is given, all objects within the
//     HSM are extracted.
//
//     The deleteAfterExtract parameter indicates whether or not the
//     objects should be left on the HSM after they are extracted.
//     If this parameter is given a value of TRUE, all indicated
//     objects are deleted after the extract is complete.  Note that
//     this might be a dangerous use of the function, as the objects
//     are deleted before the calling application gets an opportunity
//     to store the resulting key blob -- a power failure at this
//     point could result in lost data.
//
//////////////////////////////////////////////////////////////////////
CK_RV CK_ENTRY CA_SIMExtract(CK_SESSION_HANDLE hSession, CK_ULONG ulHandleCount,
                             CK_OBJECT_HANDLE_PTR pHandleList,
                             CK_ULONG ulAuthSecretCount, // N value
                             CK_ULONG ulAuthSubsetCount, // M value
                             CKA_SIM_AUTH_FORM authForm,
                             CK_ULONG_PTR pulAuthSecretSizes,
                             CK_BYTE_PTR *ppbAuthSecretList,
                             CK_BBOOL deleteAfterExtract,
                             CK_ULONG_PTR pulBlobSize, CK_BYTE_PTR pBlob);

//////////////////////////////////////////////////////////////////////
//
// Function: CA_SIMInsert
//
// Description: Insert a set of objects that had previously been extracted
//      using the CA_SIMExtract function.
//
//      The SIM blob is provided along with authorization data.  If the
//      authorization data is correct and sufficient, the objects contained
//      in the blob are inserted into the HSM.  Note that a number of
//      authorization secrets equal to the ulAuthSubsetCount of the
//      CA_SIMExtract call must be provided.
//
//      If the pHandleList parameter is null, only the handle count will
//      be returned.  The handle list itself may be retrieved on a subsequent
//      call.  If the handle list is to be retrieved, the *pulHandleCount
//      value should be initialized to the size of the pHandleList buffer
//      provided.
//
//      Object handles in the handle list will be ordered as they were
//      in the CA_SIMExtract call.  That is, if a particular object was
//      specified in the nth place in the handle list given to CA_SIMExtract,
//      it will be returned in the nth place in the list when CA_SIMInsert
//      returns.
//
//////////////////////////////////////////////////////////////////////
CK_RV CK_ENTRY CA_SIMInsert(CK_SESSION_HANDLE hSession,
                            CK_ULONG ulAuthSecretCount, // M value
                            CKA_SIM_AUTH_FORM authForm,
                            CK_ULONG_PTR pulAuthSecretSizes,
                            CK_BYTE_PTR *ppbAuthSecretList, CK_ULONG ulBlobSize,
                            CK_BYTE_PTR pBlob, CK_ULONG_PTR pulHandleCount,
                            CK_OBJECT_HANDLE_PTR pHandleList);

//////////////////////////////////////////////////////////////////////
//
// Function: CA_SIMMultiSign
//
// Description: This function uses a key extracted from the HSM using
//      the CA_SIMExtract function to perform signature operations on
//      a set of input data.
//
//      The input SIM blob may only contain a single object.  This
//      object must be a key of the appropriate type for the given
//      mechanism.
//
//      If the authorization data is correct for the given blob, the
//      key is used to sign each element of the input data list.  The
//      resulting signatures are stored in the signature list output
//      buffers.
//
//      Note that this function does *NOT* support providing null
//      pointers for the output signature buffers.  The provided
//      buffers must be large enough to accept the given signature.
//
//////////////////////////////////////////////////////////////////////
CK_RV CK_ENTRY CA_SIMMultiSign(
    CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_ULONG ulAuthSecretCount, // M value
    CKA_SIM_AUTH_FORM authForm, CK_ULONG_PTR pulAuthSecretSizes,
    CK_BYTE_PTR *ppbAuthSecretList, CK_ULONG ulBlobSize, CK_BYTE_PTR pBlob,
    CK_ULONG ulInputDataCount, CK_ULONG_PTR pulInputDataLengths,
    CK_BYTE_PTR *ppbInputDataList, CK_ULONG_PTR pulSignatureLengths,
    CK_BYTE_PTR *ppbSignatureList);

//////////////////////////////////////////////////////////////////////
// SIM3 Functions
//////////////////////////////////////////////////////////////////////
CK_RV CK_ENTRY CA_Extract(CK_SESSION_HANDLE hSession,
                          CK_MECHANISM_PTR pMechanism);

CK_RV CK_ENTRY CA_Insert(CK_SESSION_HANDLE hSession,
                         CK_MECHANISM_PTR pMechanism);

CK_RV CK_ENTRY CA_GetObjectUID(CK_SLOT_ID slotID, CK_ULONG ulContainerNum,
                               CK_ULONG ulObjectType, CK_ULONG ulObjectHandle,
                               CK_BYTE ouid[12]);

CK_RV CK_ENTRY CA_GetObjectHandle(CK_SLOT_ID slotID, CK_ULONG ulContainerNum,
                                  CK_BYTE ouid[12], CK_ULONG_PTR pulObjectType,
                                  CK_ULONG_PTR pulObjectHandle);

CK_RV CK_ENTRY CA_DeleteContainer(CK_SESSION_HANDLE hSession);

CK_RV CK_ENTRY CA_MTKSetStorage(CK_SESSION_HANDLE ulSessionNumber,
                                CK_ULONG ulStorageSetting);
CK_RV CK_ENTRY CA_MTKRestore(CK_SLOT_ID slotID);
CK_RV CK_ENTRY CA_MTKResplit(CK_SLOT_ID slotID);
CK_RV CK_ENTRY CA_MTKZeroize(CK_SLOT_ID slotID);
CK_RV CK_ENTRY CA_MTKGetState(CK_SLOT_ID slotID, CK_ULONG_PTR state);

CK_RV CK_ENTRY CA_GetTSV(CK_SLOT_ID slotID, CK_ULONG_PTR pTSV);

//
/****************************************************************************\
*
* SafeNet High Availability Recovery functions
*
\****************************************************************************/

CK_RV CK_ENTRY CA_InvokeServiceInit(CK_SESSION_HANDLE hSession,
                                    CK_ULONG ulPortNumber);

CK_RV CK_ENTRY CA_InvokeService(CK_SESSION_HANDLE hSession,
                                CK_BYTE_PTR pBufferIn,
                                CK_ULONG ulBufferInLength,
                                CK_ULONG_PTR pulBufferOutLength);

CK_RV CK_ENTRY CA_InvokeServiceFinal(CK_SESSION_HANDLE hSession,
                                     CK_BYTE_PTR pBufferOut,
                                     CK_ULONG_PTR pulBufferOutLength);

CK_RV CK_ENTRY CA_InvokeServiceAsynch(CK_SESSION_HANDLE hSession,
                                      CK_ULONG ulPortNumber,
                                      CK_BYTE_PTR pBufferIn,
                                      CK_ULONG ulBufferInLength);

CK_RV CK_ENTRY CA_InvokeServiceSinglePart(CK_SESSION_HANDLE hSession,
                                          CK_ULONG ulPortNumber,
                                          CK_BYTE_PTR pBufferIn,
                                          CK_ULONG ulBufferInLength,
                                          CK_BYTE_PTR pBufferOut,
                                          CK_ULONG_PTR pulBufferOutLength);

CK_RV CK_ENTRY CA_EncodeECPrimeParams(
    CK_BYTE_PTR DerECParams, CK_ULONG_PTR DerECParamsLen, CK_BYTE_PTR prime,
    CK_ULONG primelen, CK_BYTE_PTR a, CK_ULONG alen, CK_BYTE_PTR b,
    CK_ULONG blen,
    CK_BYTE_PTR seed, // Can be NULL
    CK_ULONG seedlen, CK_BYTE_PTR x, CK_ULONG xlen, CK_BYTE_PTR y,
    CK_ULONG ylen, CK_BYTE_PTR order, CK_ULONG orderlen,
    CK_BYTE_PTR cofactor, // Can be NULL
    CK_ULONG cofactorlen);
CK_RV CK_ENTRY CA_EncodeECChar2Params(
    CK_BYTE_PTR DerECParams, CK_ULONG_PTR DerECParamsLen, CK_ULONG m,
    CK_ULONG k1, CK_ULONG k2, CK_ULONG k3, CK_BYTE_PTR a, CK_ULONG alen,
    CK_BYTE_PTR b, CK_ULONG blen,
    CK_BYTE_PTR seed, // Can be NULL
    CK_ULONG seedlen, CK_BYTE_PTR x, CK_ULONG xlen, CK_BYTE_PTR y,
    CK_ULONG ylen, CK_BYTE_PTR order, CK_ULONG orderlen,
    CK_BYTE_PTR cofactor, // Can be NULL
    CK_ULONG cofactorlen);

CK_RV CK_ENTRY CA_EncodeECParamsFromFile(CK_BYTE_PTR DerECParams,
                                         CK_ULONG_PTR DerECParamsLen,
                                         CK_BYTE_PTR paramsFile);

CK_RV CK_ENTRY CA_GetHSMStorageInformation(CK_SLOT_ID slotID,
                                           CK_ULONG_PTR pulContainerOverhead,
                                           CK_ULONG_PTR pulTotal,
                                           CK_ULONG_PTR pulUsed,
                                           CK_ULONG_PTR pulFree);

CK_RV CK_ENTRY CA_GetContainerStorageInformation(
    CK_SLOT_ID slotID, CK_ULONG ulContainerNumber,
    CK_ULONG_PTR pulContainerOverhead, CK_ULONG_PTR pulTotal,
    CK_ULONG_PTR pulUsed, CK_ULONG_PTR pulFree, CK_ULONG_PTR pulObjectCount);

CK_RV CK_ENTRY CA_SetContainerSize(CK_SESSION_HANDLE hSession,
                                   CK_ULONG ulContainerNumber, CK_ULONG ulSize);

CK_RV CK_ENTRY CA_CreateContainer(CK_SESSION_HANDLE hSession, CK_ULONG ulUSV,
                                  CK_CHAR_PTR pContainerName,
                                  CK_ULONG usContainerNameLen, CK_CHAR_PTR pPin,
                                  CK_ULONG usPinLen, CK_ULONG ulIDHigh,
                                  CK_ULONG ulIDLow, CK_ULONG ulOwnerHandle,
                                  CK_ULONG ulStorageFlags,
                                  CK_ULONG ulContainerSize,
                                  CK_ULONG_PTR pulContainerNumber);

CK_RV CK_ENTRY CA_InitAudit(CK_SLOT_ID slotID, CK_CHAR_PTR pPin,
                            CK_ULONG usPinLen, CK_CHAR_PTR pLabel);

CK_RV CK_ENTRY CA_LogVerify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLogMsgs,
                            CK_ULONG ulMsgCount, CK_ULONG bChainToHSM,
                            CK_ULONG_PTR pulNumVerified);

CK_RV CK_ENTRY CA_LogVerifyFile(CK_SESSION_HANDLE hSession,
                                CK_CHAR_PTR pFileName,
                                CK_ULONG_PTR ulNumVerified);

CK_RV CK_ENTRY CA_LogExternal(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession,
                              CK_CHAR_PTR pStr, CK_ULONG ulLen);

CK_RV CK_ENTRY CA_LogImportSecret(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pStr);

CK_RV CK_ENTRY CA_LogExportSecret(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pStr);

CK_RV CK_ENTRY CA_TimeSync(CK_SESSION_HANDLE hSession, CK_ULONG ulTime);

CK_RV CK_ENTRY CA_GetTime(CK_SESSION_HANDLE hSession, CK_ULONG_PTR pulTime);

CK_RV CK_ENTRY CA_LogSetConfig(CK_SESSION_HANDLE hSession, CK_ULONG mask,
                               CK_ULONG logRotateOffset,
                               CK_ULONG logRotateInterval, CK_ULONG maxLogSize,
                               CK_BYTE_PTR pLogPath);

CK_RV CK_ENTRY CA_LogGetConfig(CK_SESSION_HANDLE hSession, CK_ULONG *mask,
                               CK_ULONG *logRotateOffset,
                               CK_ULONG *logRotateInterval,
                               CK_ULONG *maxLogSize, CK_BYTE_PTR pLogPath);

CK_RV CK_ENTRY CA_LogEraseAll(CK_SESSION_HANDLE hSession);

CK_RV CK_ENTRY CA_LogGetStatus(CK_SLOT_ID slotId, CK_ULONG *auditInitStatus,
                               CK_ULONG *lastPollResult,
                               CK_ULONG *lastSetConfigResult,
                               CK_ULONG *isConfigInParamArea,
                               CK_ULONG *numRecordsInFlash);

CK_RV CK_ENTRY CA_DeleteContainerWithHandle(CK_SESSION_HANDLE hSession,
                                            CK_ULONG ulContainerNumber);

CK_RV CK_ENTRY CA_GetContainerList(CK_SLOT_ID slotID, CK_ULONG ulGroupHandle,
                                   CK_ULONG ulContainerType,
                                   CK_ULONG_PTR pulContainerHandles,
                                   CK_ULONG_PTR pulNumberOfHandles);

CK_RV CK_ENTRY CA_GetContainerName(CK_SLOT_ID slotID,
                                   CK_ULONG ulContainerHandle,
                                   CK_BYTE_PTR pContainerName,
                                   CK_ULONG_PTR pulContainerNameLen);

CK_RV CK_ENTRY CA_GetNumberOfAllowedContainers(
    CK_SLOT_ID slot, CK_ULONG_PTR pulAllowedContainers);

CK_RV CK_ENTRY CA_GetTunnelSlotNumber(CK_SLOT_ID slotID,
                                      CK_SLOT_ID_PTR pTunnelSlotID);

CK_RV CK_ENTRY CA_GetClusterState(CK_SLOT_ID slotId,
                                  CK_CLUSTER_STATE_PTR pState);
CK_RV CK_ENTRY CA_LockClusteredSlot(CK_SLOT_ID slotId);
CK_RV CK_ENTRY CA_UnlockClusteredSlot(CK_SLOT_ID slotId);

CK_RV CK_ENTRY CA_LKMInitiatorChallenge(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hAKObjectHandle, // Authentication key
    CK_OBJECT_HANDLE hDKObjectHandle, // Derivation key
    CK_ULONG ulHashMech,              // Hashing mechanism
    CK_LKM_TOKEN_ID_PTR pInitiatorID, // Initiator ID info
    CK_LKM_TOKEN_ID_PTR pReceiverID,  // Receiver ID info
    CK_CHAR_PTR pChallengeBuf,        // Returned challenge message
    CK_ULONG_PTR
        pulChallengeBufSize); // Max. size of challenge buffer & returned size

CK_RV CK_ENTRY CA_LKMReceiverResponse(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hAKObjectHandle, // Authentication key
    CK_OBJECT_HANDLE hDKObjectHandle, // Derivation key
    CK_ULONG ulHashMech,              // Hashing mechanism
    CK_LKM_TOKEN_ID_PTR pReceiverID,  // Receiver ID info
    CK_CHAR_PTR pChallengeBuf,        // Challenge message from Initiator
    CK_ULONG ulChallengeBufSize,      // Size of challenge buffer
    CK_CHAR_PTR pResponseBuf,         // Returned response message from Receiver
    CK_ULONG_PTR
        pulResponseBufSize); // Max. size of response buffer & returned size

CK_RV CK_ENTRY CA_LKMInitiatorComplete(
    CK_SESSION_HANDLE hSession,
    CK_CHAR_PTR pResponseBuf,      // Response message from Receiver
    CK_ULONG ulResponseBufSize,    // Size of response buffer
    CK_ATTRIBUTE_PTR pSCKTemplate, // Session Confidentiality Key Template
    CK_ULONG usSCKAttributeCount,  // no. attributes in key template
    CK_ATTRIBUTE_PTR pSAKTemplate, // Session Authentication Key Template
    CK_ULONG usSAKAttributeCount,  // no. attributes in key template
    CK_CHAR_PTR pCompleteBuf,      // Returned complete message from Initiator
    CK_ULONG_PTR
        pulCompleteBufSize, // Max. size of challenge buffer & returned size
    CK_OBJECT_HANDLE_PTR phSCKObjectHandle,  // Returned handle for SC Key
    CK_OBJECT_HANDLE_PTR phSAKObjectHandle); // Returned handle for SA Key

CK_RV CK_ENTRY CA_LKMReceiverComplete(
    CK_SESSION_HANDLE hSession,
    CK_CHAR_PTR pCompleteBuf,      // Complete message from Initiator
    CK_ULONG ulCompleteBufSize,    // Size of complete buffer
    CK_ATTRIBUTE_PTR pSCKTemplate, // Session Confidentiality Key Template
    CK_ULONG usSCKAttributeCount,  // no. attributes in key template
    CK_ATTRIBUTE_PTR pSAKTemplate, // Session Authentication Key Template
    CK_ULONG usSAKAttributeCount,  // no. attributes in key template
    CK_OBJECT_HANDLE_PTR phSCKObjectHandle,  // Returned handle for SC Key
    CK_OBJECT_HANDLE_PTR phSAKObjectHandle); // Returned handle for SA Key

CK_RV CK_ENTRY CA_ModifyUsageCount(CK_SESSION_HANDLE hSession,
                                   CK_OBJECT_HANDLE hObject,
                                   CK_ULONG ulCommandType, CK_ULONG ulValue);

// functions we want to part of the function list structure
//
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
//
//    Add all the necessary type defs for the CA extension functions
//
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
//
//////////////////////////////////////////////////////////////////////

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetFunctionList)(
    CK_SFNT_CA_FUNCTION_LIST_PTR_PTR ppSfntFunctionList);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_WaitForSlotEvent)(CK_FLAGS flags,
                                                      CK_ULONG history[2],
                                                      CK_SLOT_ID_PTR pSlot,
                                                      CK_VOID_PTR pReserved);

typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_InitIndirectToken)(CK_SLOT_ID slotID, CK_CHAR_PTR pPin,
                                         CK_ULONG usPinLen, CK_CHAR_PTR pLabel,
                                         CK_SESSION_HANDLE hPrimarySession);

typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_InitIndirectPIN)(CK_SESSION_HANDLE hSession,
                                       CK_CHAR_PTR pPin, CK_ULONG usPinLen,
                                       CK_SESSION_HANDLE hPrimarySession);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_ResetPIN)(CK_SESSION_HANDLE hSession,
                                              CK_CHAR_PTR pPin,
                                              CK_ULONG usPinLen);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_CreateLoginChallenge)(
    CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
    CK_ULONG ulChallengeDataSize, CK_CHAR_PTR pChallengeData,
    CK_ULONG_PTR ulOutputDataSize, CK_CHAR_PTR pOutputData);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_Deactivate)(CK_SLOT_ID slotId,
                                                CK_USER_TYPE userType);

typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_OpenSession)(CK_SLOT_ID slotID,
                                   CK_ULONG ulContainerNumber, CK_FLAGS flags,
                                   CK_VOID_PTR pApplication, CK_NOTIFY Notify,
                                   CK_SESSION_HANDLE_PTR phSession);

typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_IndirectLogin)(CK_SESSION_HANDLE hSession,
                                     CK_USER_TYPE userType,
                                     CK_SESSION_HANDLE hPrimarySession);

typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_InitializeRemotePEDVector)(CK_SESSION_HANDLE hSession);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_LogVerify)(CK_SESSION_HANDLE hSession,
                                               CK_BYTE_PTR pTextMsgs,
                                               CK_ULONG ulMsgCount,
                                               CK_ULONG bChainToHSM,
                                               CK_ULONG_PTR pulNumVerified);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_LogVerifyFile)(CK_SESSION_HANDLE hSession,
                                                   CK_CHAR_PTR pFileName,
                                                   CK_ULONG_PTR ulNumVerified);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_LogExternal)(CK_SLOT_ID slotID,
                                                 CK_SESSION_HANDLE hSession,
                                                 CK_CHAR_PTR pStr,
                                                 CK_ULONG ulLen);
typedef CK_RV CK_ENTRY(CK_PTR CK_CA_LogImportSecret)(CK_SESSION_HANDLE hSession,
                                                     CK_BYTE_PTR pStr);
typedef CK_RV CK_ENTRY(CK_PTR CK_CA_LogExportSecret)(CK_SESSION_HANDLE hSession,
                                                     CK_BYTE_PTR pStr);
typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_DeleteRemotePEDVector)(CK_SESSION_HANDLE hSession);
typedef CK_RV CK_ENTRY(CK_PTR CK_CA_ConfigureRemotePED)(CK_SLOT_ID slotID,
                                                        CK_CHAR_PTR pHostName,
                                                        CK_ULONG ulPort,
                                                        CK_ULONG_PTR pulPedId);
typedef CK_RV CK_ENTRY(CK_PTR CK_CA_DismantleRemotePED)(CK_SLOT_ID slotID,
                                                        CK_ULONG ulPedId);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_LogSetConfig)(
    CK_SESSION_HANDLE hSession, CK_ULONG mask, CK_ULONG logRotateOffset,
    CK_ULONG logRotateInterval, CK_ULONG maxLogSize, CK_BYTE_PTR pLogPath);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_LogGetconfig)(
    CK_SESSION_HANDLE hSession, CK_ULONG *mask, CK_ULONG *logRotateOffset,
    CK_ULONG *logRotateInterval, CK_ULONG *maxLogSize, CK_BYTE_PTR pLogPath);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_LogEraseAll)(CK_SESSION_HANDLE hSession);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_LogGetStatus)(CK_SLOT_ID slotId,
                                                  CK_ULONG *auditInitStatus,
                                                  CK_ULONG *lastPollResult,
                                                  CK_ULONG *lastSetConfigResult,
                                                  CK_ULONG *isConfigInParamArea,
                                                  CK_ULONG *numRecordsInFlash);

typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_GetRemotePEDVectorStatus)(CK_SLOT_ID slotID,
                                                CK_ULONG_PTR pulStatus);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_Restart)(CK_SLOT_ID slotID);
typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_RestartForContainer)(CK_SLOT_ID slotID,
                                           CK_ULONG ulContainerNumber);
typedef CK_RV CK_ENTRY(CK_PTR CK_CA_CloseApplicationID)(CK_SLOT_ID slotID,
                                                        CK_ULONG ulHigh,
                                                        CK_ULONG ulLow);
typedef CK_RV CK_ENTRY(CK_PTR CK_CA_CloseApplicationIDForContainer)(
    CK_SLOT_ID slotID, CK_ULONG ulHigh, CK_ULONG ulLow,
    CK_ULONG ulContainerNumber);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_OpenApplicationID)(CK_SLOT_ID slotID,
                                                       CK_ULONG ulHigh,
                                                       CK_ULONG ulLow);
typedef CK_RV CK_ENTRY(CK_PTR CK_CA_OpenApplicationIDForContainer)(
    CK_SLOT_ID slotID, CK_ULONG ulHigh, CK_ULONG ulLow,
    CK_ULONG ulContainerNumber);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_SetApplicationID)(CK_ULONG ulHigh,
                                                      CK_ULONG ulLow);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_ManualKCV)(CK_SESSION_HANDLE hSession);
typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_SetLKCV)(CK_SESSION_HANDLE hSession,
                               CK_BYTE_PTR pLegacyCloningDomainString,
                               CK_ULONG ulLegacyCloningDomainStringLen);
typedef CK_RV CK_ENTRY(CK_PTR CK_CA_SetKCV)(CK_SESSION_HANDLE hSession,
                                            CK_BYTE_PTR pCloningDomainString,
                                            CK_ULONG ulCloningDomainStringLen);
typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_SetCloningDomain)(CK_BYTE_PTR pCloningDomainString,
                                        CK_ULONG ulCloningDomainStringLen);
typedef CK_RV CK_ENTRY(CK_PTR CK_CA_ClonePrivateKey)(
    CK_SESSION_HANDLE hTargetSession, CK_SESSION_HANDLE hSourceSession,
    CK_OBJECT_HANDLE hObjectToCloneHandle, CK_OBJECT_HANDLE_PTR phClonedKey);
typedef CK_RV CK_ENTRY(CK_PTR CK_CA_CloneObject)(
    CK_SESSION_HANDLE hTargetSession, CK_SESSION_HANDLE hSourceSession,
    CK_ULONG ulObjectType, CK_OBJECT_HANDLE hObjectHandle,
    CK_OBJECT_HANDLE_PTR phClonedObject);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GenerateCloningKEV)(
    CK_SESSION_HANDLE hSession, CK_BYTE_PTR pKEV, CK_ULONG_PTR pulKEVSize);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_CloneAsTargetInit)(
    CK_SESSION_HANDLE hSession, CK_BYTE_PTR pTWC, CK_ULONG ulTWCSize,
    CK_BYTE_PTR pKEV, CK_ULONG ulKEVSize, CK_BBOOL bReplicate,
    CK_BYTE_PTR pPart1, CK_ULONG_PTR pulPart1Size);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_CloneAsSource)(
    CK_SESSION_HANDLE hSession, CK_ULONG hType, CK_ULONG hHandle,
    CK_BYTE_PTR pPart1, CK_ULONG ulPart1Size, CK_BBOOL bReplicate,
    CK_BYTE_PTR pPart2, CK_ULONG_PTR pulPart2Size);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_CloneAsTarget)(
    CK_SESSION_HANDLE hSession, CK_BYTE_PTR pKEV, CK_ULONG ulKEVSize,
    CK_BYTE_PTR pPart2, CK_ULONG ulPart2Size, CK_ULONG hType, CK_ULONG hHandle,
    CK_BBOOL bReplicate, CK_OBJECT_HANDLE_PTR phClonedHandle);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_SetMofN)(CK_BBOOL bFlag);
typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GenerateMofN)(
    CK_SESSION_HANDLE hSession, CK_ULONG ulM, CA_MOFN_GENERATION_PTR pVectors,
    CK_ULONG ulVectorCount, CK_ULONG isSecurePortUsed, CK_VOID_PTR pReserved);
typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GenerateCloneableMofN)(
    CK_SESSION_HANDLE hSession, CK_ULONG ulM, CA_MOFN_GENERATION_PTR pVectors,
    CK_ULONG ulVectorCount, CK_ULONG isSecurePortUsed, CK_VOID_PTR pReserved);
typedef CK_RV CK_ENTRY(CK_PTR CK_CA_ModifyMofN)(
    CK_SESSION_HANDLE hSession, CK_ULONG ulM, CA_MOFN_GENERATION_PTR pVectors,
    CK_ULONG ulVectorCount, CK_ULONG isSecurePortUsed, CK_VOID_PTR pReserved);
typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_CloneMofN)(CK_SESSION_HANDLE hSession,
                                 CK_SESSION_HANDLE hPrimarySession,
                                 CK_VOID_PTR pReserved);
typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_CloneModifyMofN)(CK_SESSION_HANDLE hSession,
                                       CK_SESSION_HANDLE hPrimarySession,
                                       CK_VOID_PTR pReserved);
typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_ActivateMofN)(CK_SESSION_HANDLE hSession,
                                    CA_MOFN_ACTIVATION_PTR pVectors,
                                    CK_ULONG ulVectorCount);
typedef CK_RV CK_ENTRY(CK_PTR CK_CA_DeactivateMofN)(CK_SESSION_HANDLE hSession);

typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_GetMofNStatus)(CK_SLOT_ID slotID,
                                     CA_MOFN_STATUS_PTR pMofNStatus);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_DuplicateMofN)(CK_SESSION_HANDLE hSession);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_IsMofNEnabled)(CK_SLOT_ID slotID,
                                                   CK_ULONG_PTR enabled);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_IsMofNRequired)(CK_SLOT_ID slotID,
                                                    CK_ULONG_PTR required);

typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_GenerateTokenKeys)(CK_SESSION_HANDLE hSession,
                                         CK_ATTRIBUTE_PTR pTemplate,
                                         CK_ULONG usTemplateLen);
typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetTokenCertificateInfo)(
    CK_SLOT_ID slotID, CK_ULONG ulAccessLevel, CK_BYTE_PTR pCertificate,
    CK_ULONG_PTR pulCertificateLen);
typedef CK_RV CK_ENTRY(CK_PTR CK_CA_SetTokenCertificateSignature)(
    CK_SESSION_HANDLE hSession, CK_ULONG ulAccessLevel, CK_ULONG ulCustomerId,
    CK_ATTRIBUTE_PTR pPublicTemplate, CK_ULONG usPublicTemplateLen,
    CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetModuleList)(
    CK_SLOT_ID slotId, CKCA_MODULE_ID_PTR pList, CK_ULONG ulListLen,
    CK_ULONG_PTR pulReturnedSize);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetModuleInfo)(CK_SLOT_ID slotId,
                                                   CKCA_MODULE_ID moduleId,
                                                   CKCA_MODULE_INFO_PTR pInfo);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_LoadModule)(
    CK_SESSION_HANDLE hSession, CK_BYTE_PTR pModuleCode,
    CK_ULONG ulModuleCodeSize, CK_BYTE_PTR pModuleSignature,
    CK_ULONG ulModuleSignatureSize, CK_BYTE_PTR pCertificate,
    CK_ULONG ulCertificateSize, CK_BYTE_PTR pControlData,
    CK_ULONG ulControlDataSize, CKCA_MODULE_ID_PTR pModuleId);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_LoadEncryptedModule)(
    CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pIv,
    CK_ULONG ulIvLen, CK_BYTE_PTR pModuleCode, CK_ULONG ulModuleCodeSize,
    CK_BYTE_PTR pModuleSignature, CK_ULONG ulModuleSignatureSize,
    CK_BYTE_PTR pCertificate, CK_ULONG ulCertificateSize,
    CKCA_MODULE_ID_PTR pModuleId);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_UnloadModule)(CK_SESSION_HANDLE hSession,
                                                  CKCA_MODULE_ID moduleId);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_PerformModuleCall)(
    CK_SESSION_HANDLE hSession, CKCA_MODULE_ID moduleId, CK_BYTE_PTR pRequest,
    CK_ULONG ulRequestSize, CK_BYTE_PTR pAnswer, CK_ULONG ulAnswerSize,
    CK_ULONG_PTR pulAnswerAvailable);

typedef CK_RV CK_ENTRY(CK_PTR CK_C_PerformSelfTest)(
    CK_SLOT_ID slotID, CK_ULONG typeOfTest, CK_BYTE_PTR inputData,
    CK_ULONG sizeOfInputData, CK_BYTE_PTR outputData,
    CK_ULONG_PTR sizeOfOutputData);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_FirmwareUpdate)(
    CK_SESSION_HANDLE hSession, CK_ULONG ulTargetHardwarePlatform,
    CK_ULONG ulAuthCodeLen, CK_BYTE_PTR pAuthCode, CK_ULONG ulManifestLen,
    CK_BYTE_PTR pManifest, CK_ULONG ulFirmwareLen, CK_BYTE_PTR pFirmware);

typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_FirmwareRollback)(CK_SESSION_HANDLE hSession);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_CapabilityUpdate)(
    CK_SESSION_HANDLE hSession, CK_ULONG ulManifestLen, CK_BYTE_PTR pManifest,
    CK_ULONG ulAuthcodeLen, CK_BYTE_PTR pAuthcode);

typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_GetUserContainerNumber)(CK_SLOT_ID slotID,
                                              CK_ULONG_PTR pulContainerNumber);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetUserContainerName)(
    CK_SLOT_ID slotID, CK_BYTE_PTR pName, CK_ULONG_PTR pulNameLen);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_SetUserContainerName)(CK_SLOT_ID slotID,
                                                          CK_BYTE_PTR pName,
                                                          CK_ULONG ulNameLen);

typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_GetTokenInsertionCount)(CK_SLOT_ID slotID,
                                              CK_ULONG_PTR pulCount);

typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_GetRollbackFirmwareVersion)(CK_SLOT_ID slotID,
                                                  CK_ULONG_PTR pulVersion);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetFPV)(CK_SLOT_ID slotID,
                                            CK_ULONG_PTR pulFpv);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetTPV)(CK_SLOT_ID slotID,
                                            CK_ULONG_PTR pulTpv);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetExtendedTPV)(CK_SLOT_ID slotID,
                                                    CK_ULONG_PTR pulTpv,
                                                    CK_ULONG_PTR pulTpvExt);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetConfigurationElementDescription)(
    CK_SLOT_ID slotID, CK_ULONG ulIsContainerElement,
    CK_ULONG ulIsCapabilityElement, CK_ULONG ulElementId,
    CK_ULONG_PTR pulElementBitLength, CK_ULONG_PTR pulElementDestructive,
    CK_ULONG_PTR pulElementWriteRestricted, CK_CHAR_PTR pDescription);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetHSMCapabilitySet)(
    CK_SLOT_ID uPhysicalSlot, CK_ULONG_PTR pulCapIdArray,
    CK_ULONG_PTR pulCapIdSize, CK_ULONG_PTR pulCapValArray,
    CK_ULONG_PTR pulCapValSize);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetHSMCapabilitySetting)(
    CK_SLOT_ID slotID, CK_ULONG ulPolicyId, CK_ULONG_PTR pulPolicyValue);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetHSMPolicySet)(
    CK_SLOT_ID uPhysicalSlot, CK_ULONG_PTR pulPolicyIdArray,
    CK_ULONG_PTR pulPolicyIdSize, CK_ULONG_PTR pulPolicyValArray,
    CK_ULONG_PTR pulPolicyValSize);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetHSMPolicySetting)(
    CK_SLOT_ID slotID, CK_ULONG ulPolicyId, CK_ULONG_PTR pulPolicyValue);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetContainerCapabilitySet)(
    CK_SLOT_ID uPhysicalSlot, CK_ULONG ulContainerNumber,
    CK_ULONG_PTR pulCapIdArray, CK_ULONG_PTR pulCapIdSize,
    CK_ULONG_PTR pulCapValArray, CK_ULONG_PTR pulCapValSize);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetContainerCapabilitySetting)(
    CK_SLOT_ID slotID, CK_ULONG ulContainerNumber, CK_ULONG ulPolicyId,
    CK_ULONG_PTR pulPolicyValue);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetContainerPolicySet)(
    CK_SLOT_ID uPhysicalSlot, CK_ULONG ulContainerNumber,
    CK_ULONG_PTR pulPolicyIdArray, CK_ULONG_PTR pulPolicyIdSize,
    CK_ULONG_PTR pulPolicyValArray, CK_ULONG_PTR pulPolicyValSize);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetContainerPolicySetting)(
    CK_SLOT_ID uPhysicalSlot, CK_ULONG ulContainerNumber, CK_ULONG ulPolicyId,
    CK_ULONG_PTR pulPolicyValue);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_SetTPV)(CK_SESSION_HANDLE hSession,
                                            CK_ULONG ulTpv);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_SetExtendedTPV)(CK_SESSION_HANDLE hSession,
                                                    CK_ULONG ulTpv,
                                                    CK_ULONG ulTpvExt);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_SetHSMPolicy)(CK_SESSION_HANDLE hSession,
                                                  CK_ULONG ulPolicyId,
                                                  CK_ULONG ulPolicyValue);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_SetHSMPolicies)(
    CK_SESSION_HANDLE hSession, CK_ULONG ulPolicyCount,
    CK_ULONG_PTR pulPolicyIdArray, CK_ULONG_PTR pulPolicyValueArray);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_SetDestructiveHSMPolicy)(
    CK_SESSION_HANDLE hSession, CK_ULONG ulPolicyId, CK_ULONG ulPolicyValue);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_SetDestructiveHSMPolicies)(
    CK_SESSION_HANDLE hSession, CK_ULONG ulPolicyCount,
    CK_ULONG_PTR pulPolicyIdArray, CK_ULONG_PTR pulPolicyValueArray);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_SetContainerPolicy)(
    CK_SESSION_HANDLE hSession, CK_ULONG ulContainer, CK_ULONG ulPolicyId,
    CK_ULONG ulPolicyValue);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_SetContainerPolicies)(
    CK_SESSION_HANDLE hSession, CK_ULONG ulContainer, CK_ULONG ulPolicyCount,
    CK_ULONG_PTR pulPolicyIdArray, CK_ULONG_PTR pulPolicyValueArray);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_RetrieveLicenseList)(
    CK_SLOT_ID slotID, CK_ULONG_PTR pulidArraySize, CK_ULONG_PTR pulidArray);
typedef CK_RV CK_ENTRY(CK_PTR CK_CA_QueryLicense)(
    CK_SLOT_ID slotID, CK_ULONG licenseIdLow, CK_ULONG licenseIdHigh,
    CK_ULONG_PTR pulLicenseType, CK_ULONG_PTR pulDescVersion,
    CK_ULONG_PTR pulDescSize, CK_BYTE_PTR pbDescBuffer);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetContainerStatus)(
    CK_SLOT_ID slotID, CK_ULONG ulContainerNumber,
    CK_ULONG_PTR pulContainerStatusFlags, CK_ULONG_PTR pulFailedSOLogins,
    CK_ULONG_PTR pulFailedUserLogins, CK_ULONG_PTR pulFailedLimitedUserLogins);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetSessionInfo)(
    CK_SESSION_HANDLE hSession, CK_ULONG_PTR pulAidHigh, CK_ULONG_PTR pulAidLow,
    CK_ULONG_PTR pulContainerNumber, CK_ULONG_PTR pulAuthenticationLevel);

typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_ReadCommonStore)(CK_ULONG index, CK_BYTE_PTR pBuffer,
                                       CK_ULONG_PTR pulBufferSize);
typedef CK_RV CK_ENTRY(CK_PTR CK_CA_WriteCommonStore)(CK_ULONG index,
                                                      CK_BYTE_PTR pBuffer,
                                                      CK_ULONG ulBufferSize);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetPrimarySlot)(CK_SESSION_HANDLE hSession,
                                                    CK_SLOT_ID_PTR slotId_p);
typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_GetSecondarySlot)(CK_SESSION_HANDLE hSession,
                                        CK_SLOT_ID_PTR slotId_p);
typedef CK_RV CK_ENTRY(CK_PTR CK_CA_SwitchSecondarySlot)(
    CK_SESSION_HANDLE hSession, CK_SLOT_ID slotID, CK_ULONG slotInstance);
typedef CK_RV CK_ENTRY(CK_PTR CK_CA_CloseSecondarySession)(
    CK_SESSION_HANDLE hSession, CK_SLOT_ID slotID, CK_ULONG slotInstance);
typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_CloseAllSecondarySessions)(CK_SESSION_HANDLE hSession);
typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_ChoosePrimarySlot)(CK_SESSION_HANDLE hSession);
typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_ChooseSecondarySlot)(CK_SESSION_HANDLE hSession);

typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_CloneObjectToAllSessions)(CK_SESSION_HANDLE hSession,
                                                CK_OBJECT_HANDLE hObject);
typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_CloneAllObjectsToSession)(CK_SESSION_HANDLE hSession,
                                                CK_SLOT_ID slotId);

typedef CK_RV CK_ENTRY(CK_PTR CK_GetTotalOperations)(CK_SLOT_ID slotId,
                                                     int *operations);
typedef CK_RV CK_ENTRY(CK_PTR CK_ResetTotalOperations)(CK_SLOT_ID slotId);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_ResetDevice)(CK_SLOT_ID slotId,
                                                 CK_FLAGS flags);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_FactoryReset)(CK_SLOT_ID slotId,
                                                  CK_FLAGS flags);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_SetPedId)(CK_SLOT_ID slotId,
                                              CK_ULONG usPedId);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetPedId)(CK_SLOT_ID slotId,
                                              CK_ULONG *usPedId);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_SpRawRead)(CK_SLOT_ID slotId,
                                               CK_ULONG_PTR data);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_SpRawWrite)(CK_SLOT_ID slotId,
                                                CK_ULONG_PTR data);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_CheckOperationState)(
    CK_SESSION_HANDLE hSession, CK_ULONG operation, CK_BBOOL *pactive);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_SinglePartSign)(
    CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pData, CK_ULONG usDataLen,
    CK_BYTE_PTR pSignature, CK_ULONG_PTR pusSignatureLen);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_SinglePartDecrypt)(
    CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
    CK_ULONG usWrappedKeyLen, CK_BYTE_PTR pUnwrappedKey,
    CK_ULONG_PTR pusUnwrappedKeyLen);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_DestroyMultipleObjects)(
    CK_SESSION_HANDLE hSession, CK_ULONG ulHandleCount,
    CK_OBJECT_HANDLE_PTR pHandleList, CK_ULONG_PTR pulIndex);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_HAInit)(CK_SESSION_HANDLE hSession,
                                            CK_OBJECT_HANDLE hLoginPrivateKey);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_HAGetMasterPublic)(
    CK_SLOT_ID slotId, CK_BYTE_PTR pCertificate, CK_ULONG_PTR pulCertificate);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_HAGetLoginChallenge)(
    CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_BYTE_PTR pCertificate,
    CK_ULONG ulCertificateLen, CK_BYTE_PTR pChallengeBlob,
    CK_ULONG_PTR pulChallengeBlobLen);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_HAAnswerLoginChallenge)(
    CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hLoginPrivateKey,
    CK_BYTE_PTR pChallengeBlob, CK_ULONG ulChallengeBlobLen,
    CK_BYTE_PTR pEncryptedPin, CK_ULONG_PTR pulEncryptedPinLen);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_HALogin)(CK_SESSION_HANDLE hSession,
                                             CK_BYTE_PTR pEncryptedPin,
                                             CK_ULONG ulEncryptedPinLen,
                                             CK_BYTE_PTR pMofNBlob,
                                             CK_ULONG_PTR pulMofNBlobLen);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_HAAnswerMofNChallenge)(
    CK_SESSION_HANDLE hSession, CK_BYTE_PTR pMofNBlob, CK_ULONG ulMofNBlobLen,
    CK_BYTE_PTR pMofNSecretBlob, CK_ULONG_PTR pulMofNSecretBlobLen);

typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_HAActivateMofN)(CK_SESSION_HANDLE hSession,
                                      CK_BYTE_PTR pMofNSecretBlob,
                                      CK_ULONG ulMofNSecretBlobLen);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetHAState)(CK_SLOT_ID slotId,
                                                CK_HA_STATE_PTR pState);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetTokenCertificates)(
    CK_SLOT_ID slotID, CK_ULONG ulCertType, CK_BYTE_PTR pCertificate,
    CK_ULONG_PTR pulCertificateLen);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_ExtractMaskedObject)(
    CK_SESSION_HANDLE hSession, CK_ULONG ulObjectHandle, CK_BYTE_PTR pMaskedKey,
    CK_ULONG_PTR pusMaskedKeyLen);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_InsertMaskedObject)(
    CK_SESSION_HANDLE hSession, CK_ULONG_PTR pulObjectHandle,
    CK_BYTE_PTR pMaskedKey, CK_ULONG usMaskedKeyLen);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_MultisignValue)(
    CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_ULONG ulMaskedKeyLen, CK_BYTE_PTR pMaskedKey, CK_ULONG_PTR pulBlobCount,
    CK_ULONG_PTR pulBlobLens, CK_BYTE_PTR CK_PTR ppBlobs,
    CK_ULONG_PTR pulSignatureLens, CK_BYTE_PTR CK_PTR ppSignatures);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_SIMExtract)(
    CK_SESSION_HANDLE hSession, CK_ULONG ulHandleCount,
    CK_OBJECT_HANDLE_PTR pHandleList,
    CK_ULONG ulAuthSecretCount, // N value
    CK_ULONG ulAuthSubsetCount, // M value
    CKA_SIM_AUTH_FORM authForm, CK_ULONG_PTR pulAuthSecretSizes,
    CK_BYTE_PTR *ppbAuthSecretList, CK_BBOOL deleteAfterExtract,
    CK_ULONG_PTR pulBlobSize, CK_BYTE_PTR pBlob);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_SIMInsert)(
    CK_SESSION_HANDLE hSession,
    CK_ULONG ulAuthSecretCount, // M value
    CKA_SIM_AUTH_FORM authForm, CK_ULONG_PTR pulAuthSecretSizes,
    CK_BYTE_PTR *ppbAuthSecretList, CK_ULONG ulBlobSize, CK_BYTE_PTR pBlob,
    CK_ULONG_PTR pulHandleCount, CK_OBJECT_HANDLE_PTR pHandleList);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_SIMMultiSign)(
    CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_ULONG ulAuthSecretCount, // M value
    CKA_SIM_AUTH_FORM authForm, CK_ULONG_PTR pulAuthSecretSizes,
    CK_BYTE_PTR *ppbAuthSecretList, CK_ULONG ulBlobSize, CK_BYTE_PTR pBlob,
    CK_ULONG ulInputDataCount, CK_ULONG_PTR pulInputDataLengths,
    CK_BYTE_PTR *ppbInputDataList, CK_ULONG_PTR pulSignatureLengths,
    CK_BYTE_PTR *ppbSignatureList);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_Extract)(CK_SESSION_HANDLE hSession,
                                             CK_MECHANISM_PTR pMechanism);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_Insert)(CK_SESSION_HANDLE hSession,
                                            CK_MECHANISM_PTR pMechanism);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetObjectUID)(CK_SLOT_ID slotID,
                                                  CK_ULONG ulContainerNum,
                                                  CK_ULONG ulObjectType,
                                                  CK_ULONG ulObjectHandle,
                                                  CK_BYTE ouid[12]);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetObjectHandle)(
    CK_SLOT_ID slotID, CK_ULONG ulContainerNum, CK_BYTE ouid[12],
    CK_ULONG_PTR pulObjectType, CK_ULONG_PTR pulObjectHandle);

typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_DeleteContainer)(CK_SESSION_HANDLE hSession);

typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_MTKSetStorage)(CK_SESSION_HANDLE ulSessionNumber,
                                     CK_ULONG ulStorageSetting);
typedef CK_RV CK_ENTRY(CK_PTR CK_CA_MTKRestore)(CK_SLOT_ID slotID);
typedef CK_RV CK_ENTRY(CK_PTR CK_CA_MTKResplit)(CK_SLOT_ID slotID);
typedef CK_RV CK_ENTRY(CK_PTR CK_CA_MTKZeroize)(CK_SLOT_ID slotID);
typedef CK_RV CK_ENTRY(CK_PTR CK_CA_MTKGetState)(CK_SLOT_ID slotID,
                                                 CK_ULONG_PTR state);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetTSV)(CK_SLOT_ID slotID,
                                            CK_ULONG_PTR pTSV);

typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_InvokeServiceInit)(CK_SESSION_HANDLE hSession,
                                         CK_ULONG ulPortNumber);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_InvokeService)(
    CK_SESSION_HANDLE hSession, CK_BYTE_PTR pBufferIn,
    CK_ULONG ulBufferInLength, CK_ULONG_PTR pulBufferOutLength);

typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_InvokeServiceFinal)(CK_SESSION_HANDLE hSession,
                                          CK_BYTE_PTR pBufferOut,
                                          CK_ULONG_PTR pulBufferOutLength);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_InvokeServiceAsynch)(
    CK_SESSION_HANDLE hSession, CK_ULONG ulPortNumber, CK_BYTE_PTR pBufferIn,
    CK_ULONG ulBufferInLength);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_InvokeServiceSinglePart)(
    CK_SESSION_HANDLE hSession, CK_ULONG ulPortNumber, CK_BYTE_PTR pBufferIn,
    CK_ULONG ulBufferInLength, CK_BYTE_PTR pBufferOut,
    CK_ULONG_PTR pulBufferOutLength);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_EncodeECPrimeParams)(
    CK_BYTE_PTR DerECParams, CK_ULONG_PTR DerECParamsLen, CK_BYTE_PTR prime,
    CK_ULONG primelen, CK_BYTE_PTR a, CK_ULONG alen, CK_BYTE_PTR b,
    CK_ULONG blen,
    CK_BYTE_PTR seed, // Can be NULL
    CK_ULONG seedlen, CK_BYTE_PTR x, CK_ULONG xlen, CK_BYTE_PTR y,
    CK_ULONG ylen, CK_BYTE_PTR order, CK_ULONG orderlen,
    CK_BYTE_PTR cofactor, // Can be NULL
    CK_ULONG cofactorlen);
typedef CK_RV CK_ENTRY(CK_PTR CK_CA_EncodeECChar2Params)(
    CK_BYTE_PTR DerECParams, CK_ULONG_PTR DerECParamsLen, CK_ULONG m,
    CK_ULONG k1, CK_ULONG k2, CK_ULONG k3, CK_BYTE_PTR a, CK_ULONG alen,
    CK_BYTE_PTR b, CK_ULONG blen,
    CK_BYTE_PTR seed, // Can be NULL
    CK_ULONG seedlen, CK_BYTE_PTR x, CK_ULONG xlen, CK_BYTE_PTR y,
    CK_ULONG ylen, CK_BYTE_PTR order, CK_ULONG orderlen,
    CK_BYTE_PTR cofactor, // Can be NULL
    CK_ULONG cofactorlen);

typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_EncodeECParamsFromFile)(CK_BYTE_PTR DerECParams,
                                              CK_ULONG_PTR DerECParamsLen,
                                              CK_BYTE_PTR paramsFile);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetHSMStorageInformation)(
    CK_SLOT_ID slotID, CK_ULONG_PTR pulContainerOverhead, CK_ULONG_PTR pulTotal,
    CK_ULONG_PTR pulUsed, CK_ULONG_PTR pulFree);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetContainerStorageInformation)(
    CK_SLOT_ID slotID, CK_ULONG ulContainerNumber,
    CK_ULONG_PTR pulContainerOverhead, CK_ULONG_PTR pulTotal,
    CK_ULONG_PTR pulUsed, CK_ULONG_PTR pulFree, CK_ULONG_PTR pulObjectCount);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_SetContainerSize)(
    CK_SESSION_HANDLE hSession, CK_ULONG ulContainerNumber, CK_ULONG ulSize);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_CreateContainer)(
    CK_SESSION_HANDLE hSession, CK_ULONG ulUSV, CK_CHAR_PTR pContainerName,
    CK_ULONG usContainerNameLen, CK_CHAR_PTR pPin, CK_ULONG usPinLen,
    CK_ULONG ulIDHigh, CK_ULONG ulIDLow, CK_ULONG ulOwnerHandle,
    CK_ULONG ulStorageFlags, CK_ULONG ulContainerSize,
    CK_ULONG_PTR pulContainerNumber);

typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_DeleteContainerWithHandle)(CK_SESSION_HANDLE hSession,
                                                 CK_ULONG ulContainerNumber);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetContainerList)(
    CK_SLOT_ID slotID, CK_ULONG ulGroupHandle, CK_ULONG ulContainerType,
    CK_ULONG_PTR pulContainerHandles, CK_ULONG_PTR pulNumberOfHandles);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetContainerName)(
    CK_SLOT_ID slotID, CK_ULONG ulContainerHandle, CK_BYTE_PTR pContainerName,
    CK_ULONG_PTR pulContainerNameLen);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetNumberOfAllowedContainers)(
    CK_SLOT_ID slot, CK_ULONG_PTR pulAllowedContainers);

typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_GetTunnelSlotNumber)(CK_SLOT_ID slotID,
                                           CK_SLOT_ID_PTR pTunnelSlotID);

typedef CK_RV
CK_ENTRY(CK_PTR CK_CA_GetClusterState)(CK_SLOT_ID slotId,
                                       CK_CLUSTER_STATE_PTR pState);
typedef CK_RV CK_ENTRY(CK_PTR CK_CA_LockClusteredSlot)(CK_SLOT_ID slotId);
typedef CK_RV CK_ENTRY(CK_PTR CK_CA_UnlockClusteredSlot)(CK_SLOT_ID slotId);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_LKMInitiatorChallenge)(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hAKObjectHandle, // Authentication key
    CK_OBJECT_HANDLE hDKObjectHandle, // Derivation key
    CK_ULONG ulHashMech,              // Hashing mechanism
    CK_LKM_TOKEN_ID_PTR pInitiatorID, // Initiator ID info
    CK_LKM_TOKEN_ID_PTR pReceiverID,  // Receiver ID info
    CK_CHAR_PTR pChallengeBuf,        // Returned challenge message
    CK_ULONG_PTR
        pulChallengeBufSize); // Max. size of challenge buffer & returned size

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_LKMReceiverResponse)(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hAKObjectHandle, // Authentication key
    CK_OBJECT_HANDLE hDKObjectHandle, // Derivation key
    CK_ULONG ulHashMech,              // Hashing mechanism
    CK_LKM_TOKEN_ID_PTR pReceiverID,  // Receiver ID info
    CK_CHAR_PTR pChallengeBuf,        // Challenge message from Initiator
    CK_ULONG ulChallengeBufSize,      // Size of challenge buffer
    CK_CHAR_PTR pResponseBuf,         // Returned response message from Receiver
    CK_ULONG_PTR
        pulResponseBufSize); // Max. size of response buffer & returned size

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_LKMInitiatorComplete)(
    CK_SESSION_HANDLE hSession,
    CK_CHAR_PTR pResponseBuf,      // Response message from Receiver
    CK_ULONG ulResponseBufSize,    // Size of response buffer
    CK_ATTRIBUTE_PTR pSCKTemplate, // Session Confidentiality Key Template
    CK_ULONG usSCKAttributeCount,  // no. attributes in key template
    CK_ATTRIBUTE_PTR pSAKTemplate, // Session Authentication Key Template
    CK_ULONG usSAKAttributeCount,  // no. attributes in key template
    CK_CHAR_PTR pCompleteBuf,      // Returned complete message from Initiator
    CK_ULONG_PTR
        pulCompleteBufSize, // Max. size of challenge buffer & returned size
    CK_OBJECT_HANDLE_PTR phSCKObjectHandle,  // Returned handle for SC Key
    CK_OBJECT_HANDLE_PTR phSAKObjectHandle); // Returned handle for SA Key

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_LKMReceiverComplete)(
    CK_SESSION_HANDLE hSession,
    CK_CHAR_PTR pCompleteBuf,      // Complete message from Initiator
    CK_ULONG ulCompleteBufSize,    // Size of complete buffer
    CK_ATTRIBUTE_PTR pSCKTemplate, // Session Confidentiality Key Template
    CK_ULONG usSCKAttributeCount,  // no. attributes in key template
    CK_ATTRIBUTE_PTR pSAKTemplate, // Session Authentication Key Template
    CK_ULONG usSAKAttributeCount,  // no. attributes in key template
    CK_OBJECT_HANDLE_PTR phSCKObjectHandle,  // Returned handle for SC Key
    CK_OBJECT_HANDLE_PTR phSAKObjectHandle); // Returned handle for SA Key

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_ModifyUsageCount)(
    CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ULONG ulCommandType, CK_ULONG ulValue);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_InitAudit)(CK_SLOT_ID slotID,
                                               CK_CHAR_PTR pPin,
                                               CK_ULONG usPinLen,
                                               CK_CHAR_PTR pLabel);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_TimeSync)(CK_SESSION_HANDLE hSession,
                                              CK_ULONG ulTime);

typedef CK_RV CK_ENTRY(CK_PTR CK_CA_GetTime)(CK_SESSION_HANDLE hSession,
                                             CK_ULONG_PTR pulTime);
