/***************************************************************************
 *
 *  Filename:      cryptoki_v2.h
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

#ifndef _CRYPTOKI_H_
#define _CRYPTOKI_H_

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************\
*                                                                            *
* Operating System/Platform linking constructs                               *
*                                                                            *
\****************************************************************************/
#if defined(VXD)
#define CK_ENTRY
#define CK_POINTER *
#pragma pack(push, 1)
#elif defined(OS_WIN32)
#define CK_ENTRY __declspec(dllexport)
#define CK_POINTER *

#define CK_DEFINE_FUNCTION(returnType, name)                                   \
  returnType __declspec(dllexport) name

#define CK_DECLARE_FUNCTION(returnType, name)                                  \
  returnType __declspec(dllexport) name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name)                          \
  returnType __declspec(dllexport) (*name)

#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)

#pragma pack(push, cryptoki, 1)

#elif defined(OS_UNIX) || defined(OS_LINUX)
#define CK_ENTRY
#define CK_POINTER *

#define CK_DEFINE_FUNCTION(returnType, name) returnType name

#define CK_DECLARE_FUNCTION(returnType, name) returnType name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)

#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)

//   #pragma pack(1)
#else
#error "Unknown platform!"
#endif

#define ulMaxSessionCount usMaxSessionCount
#define ulSessionCount usSessionCount
#define ulMaxRwSessionCount usMaxRwSessionCount
#define ulRwSessionCount usRwSessionCount
#define ulMaxPinLen usMaxPinLen
#define ulMinPinLen usMinPinLen
#define ulDeviceError usDeviceError
#define ulValueLen usValueLen
#define ulParameterLen usParameterLen
#define ulEffectiveBits usEffectiveBits
#define ulPasswordLen usPasswordLen
#define sLen ulSaltLen
#define ulSaltLen usSaltLen
#define ulIteration usIteration

#define NULL_PTR 0

#define CK_PTR *

#include "pkcs11.h"

// Define same as ulong
typedef unsigned long int CK_USHORT;
typedef CK_USHORT CK_PTR CK_USHORT_PTR;

#ifndef CK_MAKE_C_VERSION
#define CK_MAKE_C_VERSION(_major, _minor) (((_major) << 8) + (_minor))
#endif

#define C_VERSION                                                              \
  CK_MAKE_C_VERSION(CRYPTOKI_VERSION_MAJOR,                                    \
                    CRYPTOKI_VERSION_MINOR) /* v2.20 decimal */
#define C_LIBRARY_VERSION 0x510             /* v5.10 decimal */

/* some special values for certain CK_ULONG variables */
#define CK_UNAVAILABLE_INFORMATION (~0UL)
#define CK_EFFECTIVELY_INFINITE 0

#define CKU_CRYPTO_OFFICER CKU_USER
#define CKU_LIMITED_USER 0x80000001
#define CKU_LIMITED_USER_OLD 0x8000001
#define CKU_CRYPTO_USER CKU_LIMITED_USER
#define CKU_AUDIT 0x80000002

#define CKF_EXCLUSIVE_SESSION 0x0001
#define CKF_EXCLUSIVE_EXISTS 0x0010
#define CKF_SO_SESSION 0x8000
#define CKF_AUDIT_SESSION 0x10000

#define CKA_START_DATE_OLD_XXX                                                 \
  0x0083 // Kept temporarily for backward compatibility with Beta version. Use
         // CKA_START_DATE
#define CKA_END_DATE_OLD_XXX                                                   \
  0x0084 // Kept temporarily for backward compatibility with Beta version. Use
         // CKA_END_DATE

#define CKD_SHA224_KDF 0x00000005
#define CKD_SHA224_KDF_OLD 0x80000003
#define CKD_SHA256_KDF 0x00000006
#define CKD_SHA256_KDF_OLD 0x80000004
#define CKD_SHA384_KDF 0x00000007
#define CKD_SHA384_KDF_OLD 0x80000005
#define CKD_SHA512_KDF 0x00000008
#define CKD_SHA512_KDF_OLD 0x80000006
#define CKD_RIPEMD160_KDF 0x80000007

#define CKD_SHA1_NIST_KDF 0x00000012
#define CKD_SHA224_NIST_KDF 0x80000013
#define CKD_SHA256_NIST_KDF 0x80000014
#define CKD_SHA384_NIST_KDF 0x80000015
#define CKD_SHA512_NIST_KDF 0x80000016
#define CKD_RIPEMD160_NIST_KDF 0x80000017

#define CKD_SHA1_SES_KDF 0x82000000
#define CKD_SHA224_SES_KDF 0x83000000
#define CKD_SHA256_SES_KDF 0x84000000
#define CKD_SHA384_SES_KDF 0x85000000
#define CKD_SHA512_SES_KDF 0x86000000
#define CKD_RIPEMD160_SES_KDF 0x87000000
#define CKD_SES_ENC_CTR 0x00000001
#define CKD_SES_AUTH_CTR 0x00000002
#define CKD_SES_ALT_ENC_CTR 0x00000003
#define CKD_SES_ALT_AUTH_CTR 0x00000004

/* X9.42 Diffie-Hellman Key Derivation Functions */
#define CKD_SHA1_KDF_ASN1 0x00000003 // not supported
#define CKD_SHA1_KDF_CONCATENATE 0x00000004

#define CKD_SHA1_KDF_CONCATENATE_X9_42 CKD_SHA1_KDF_CONCATENATE
#define CKD_SHA1_KDF_CONCATENATE_NIST 0x80000001

#define CKD_SHA1_KDF_ASN1_X9_42 CKD_SHA1_KDF_ASN1 // not supported
#define CKD_SHA1_KDF_ASN1_NIST 0x80000002         // not supported

/* AES GCM */
typedef struct CK_AES_GCM_PARAMS {
  CK_BYTE_PTR pIv;
  CK_ULONG ulIvLen;
  CK_ULONG ulIvBits;
  CK_BYTE_PTR pAAD;
  CK_ULONG ulAADLen;
  CK_ULONG ulTagBits;
} CK_AES_GCM_PARAMS;

typedef CK_AES_GCM_PARAMS CK_AES_GCM_PARAMS_PTR;

// XOR data with KDF of base key and shared data encryption mechanism parameters
typedef struct CK_XOR_BASE_DATA_KDF_PARAMS {
  CK_EC_KDF_TYPE kdf;       // KDF to use
  CK_ULONG ulSharedDataLen; // optional shared data to add to base key data
  CK_BYTE_PTR pSharedData;
} CK_XOR_BASE_DATA_KDF_PARAMS;

typedef CK_XOR_BASE_DATA_KDF_PARAMS CK_PTR CK_XOR_BASE_DATA_KDF_PARAMS_PTR;

// CKK_VENDOR_DEFINED
#define CKK_KCDSA CKK_VENDOR_DEFINED + 0x10
#define CKK_SEED CKK_VENDOR_DEFINED + 0x11

// CKA_VENDOR_DEFINED
#define CKA_CCM_PRIVATE (CKA_VENDOR_DEFINED | 0x0001)
#define CKA_FINGERPRINT_SHA1 (CKA_VENDOR_DEFINED | 0x0002)
#define CKA_PKC_TCTRUST (CKA_VENDOR_DEFINED | 0x0003)
#define CKA_PKC_CITS (CKA_VENDOR_DEFINED | 0x0004)
#define CKA_OUID (CKA_VENDOR_DEFINED | 0x0005)
#define CKA_X9_31_GENERATED (CKA_VENDOR_DEFINED | 0x0006)
#define CKA_PKC_ECC (CKA_VENDOR_DEFINED | 0x0007)
#define CKA_EKM_UID (CKA_VENDOR_DEFINED | 0x0008)
// These two match the ones already defined for PTK
#define CKA_USAGE_COUNT (CKA_VENDOR_DEFINED + 0x0101)
#define CKA_USAGE_LIMIT (CKA_VENDOR_DEFINED + 0x0200)
#define CKA_GENERIC_1 (CKA_VENDOR_DEFINED + 0x1000)
#define CKA_GENERIC_2 (CKA_VENDOR_DEFINED + 0x1001)
#define CKA_GENERIC_3 (CKA_VENDOR_DEFINED + 0x1002)

// CKM_VENDOR_DEFINED

#define CKM_VENDOR_DEFINED_OLD_XXX 0x00008000
#define CKM_CAST_KEY_GEN_OLD_XXX                                               \
  CKM_VENDOR_DEFINED_OLD_XXX + 0 // Entrust added capabilities
#define CKM_CAST_ECB_OLD_XXX                                                   \
  CKM_VENDOR_DEFINED_OLD_XXX + 1 // Entrust added capabilities
#define CKM_CAST_CBC_OLD_XXX                                                   \
  CKM_VENDOR_DEFINED_OLD_XXX + 2 // Entrust added capabilities
#define CKM_CAST_MAC_OLD_XXX                                                   \
  CKM_VENDOR_DEFINED_OLD_XXX + 3 // Entrust added capabilities
#define CKM_CAST3_KEY_GEN_OLD_XXX                                              \
  CKM_VENDOR_DEFINED_OLD_XXX + 4 // Entrust added capabilities
#define CKM_CAST3_ECB_OLD_XXX                                                  \
  CKM_VENDOR_DEFINED_OLD_XXX + 5 // Entrust added capabilities
#define CKM_CAST3_CBC_OLD_XXX                                                  \
  CKM_VENDOR_DEFINED_OLD_XXX + 6 // Entrust added capabilities
#define CKM_CAST3_MAC_OLD_XXX                                                  \
  CKM_VENDOR_DEFINED_OLD_XXX + 7 // Entrust added capabilities
#define CKM_PBE_MD2_DES_CBC_OLD_XXX                                            \
  CKM_VENDOR_DEFINED_OLD_XXX + 8 // Password based encryption
#define CKM_PBE_MD5_DES_CBC_OLD_XXX                                            \
  CKM_VENDOR_DEFINED_OLD_XXX + 9 // Password based encryption
#define CKM_PBE_MD5_CAST_CBC_OLD_XXX                                           \
  CKM_VENDOR_DEFINED_OLD_XXX + 10 // Password based encryption
#define CKM_PBE_MD5_CAST3_CBC_OLD_XXX                                          \
  CKM_VENDOR_DEFINED_OLD_XXX + 11 // Password based encryption
#define CKM_CONCATENATE_BASE_AND_KEY_OLD_XXX                                   \
  CKM_VENDOR_DEFINED_OLD_XXX + 12 // SPKM & SLL added capabilities
#define CKM_CONCATENATE_KEY_AND_BASE_OLD_XXX                                   \
  CKM_VENDOR_DEFINED_OLD_XXX + 13 // SPKM & SLL added capabilities
#define CKM_CONCATENATE_BASE_AND_DATA_OLD_XXX                                  \
  CKM_VENDOR_DEFINED_OLD_XXX + 14 // SPKM & SLL added capabilities
#define CKM_CONCATENATE_DATA_AND_BASE_OLD_XXX                                  \
  CKM_VENDOR_DEFINED_OLD_XXX + 15 // SPKM & SLL added capabilities
#define CKM_XOR_BASE_AND_DATA_OLD_XXX                                          \
  CKM_VENDOR_DEFINED_OLD_XXX + 16 // SPKM & SLL added capabilities
#define CKM_EXTRACT_KEY_FROM_KEY_OLD_XXX                                       \
  CKM_VENDOR_DEFINED_OLD_XXX + 17 // SPKM & SLL added capabilities
#define CKM_MD5_KEY_DERIVATION_OLD_XXX                                         \
  CKM_VENDOR_DEFINED_OLD_XXX + 18 // SPKM & SLL added capabilities
#define CKM_MD2_KEY_DERIVATION_OLD_XXX                                         \
  CKM_VENDOR_DEFINED_OLD_XXX + 19 // SPKM & SLL added capabilities
#define CKM_SHA1_KEY_DERIVATION_OLD_XXX                                        \
  CKM_VENDOR_DEFINED_OLD_XXX + 20 // SPKM & SLL added capabilities
#define CKM_GENERIC_SECRET_KEY_GEN_OLD_XXX                                     \
  CKM_VENDOR_DEFINED_OLD_XXX + 21 // Generation of secret keys
#define CKM_CAST5_KEY_GEN_OLD_XXX                                              \
  CKM_VENDOR_DEFINED_OLD_XXX + 22 // Entrust added capabilities
#define CKM_CAST5_ECB_OLD_XXX                                                  \
  CKM_VENDOR_DEFINED_OLD_XXX + 23 // Entrust added capabilities
#define CKM_CAST5_CBC_OLD_XXX                                                  \
  CKM_VENDOR_DEFINED_OLD_XXX + 24 // Entrust added capabilities
#define CKM_CAST5_MAC_OLD_XXX                                                  \
  CKM_VENDOR_DEFINED_OLD_XXX + 25 // Entrust added capabilities
#define CKM_PBE_SHA1_CAST5_CBC_OLD_XXX                                         \
  CKM_VENDOR_DEFINED_OLD_XXX + 26 // Entrust added capabilities
#define CKM_KEY_TRANSLATION                                                    \
  CKM_VENDOR_DEFINED_OLD_XXX + 27 // Entrust added capabilities
#define CKM_XOR_BASE_AND_KEY CKM_VENDOR_DEFINED + 27

#define CKM_2DES_KEY_DERIVATION                                                \
  CKM_VENDOR_DEFINED_OLD_XXX + 28 // Custom Gemplus Capabilities

#define CKM_INDIRECT_LOGIN_REENCRYPT                                           \
  CKM_VENDOR_DEFINED_OLD_XXX + 29 // Used for indirect login

// Old DES PBE Mechanism
#define CKM_PBE_SHA1_DES3_EDE_CBC_OLD CKM_VENDOR_DEFINED_OLD_XXX + 30
#define CKM_PBE_SHA1_DES2_EDE_CBC_OLD CKM_VENDOR_DEFINED_OLD_XXX + 31

// Korean algorithms
#define CKM_HAS160 (CKM_VENDOR_DEFINED + 0x100)
#define CKM_KCDSA_KEY_PAIR_GEN (CKM_VENDOR_DEFINED + 0x101)
#define CKM_KCDSA_HAS160 (CKM_VENDOR_DEFINED + 0x102)
#define CKM_SEED_KEY_GEN (CKM_VENDOR_DEFINED + 0x103)
#define CKM_SEED_ECB (CKM_VENDOR_DEFINED + 0x104)
#define CKM_SEED_CBC (CKM_VENDOR_DEFINED + 0x105)
#define CKM_SEED_CBC_PAD (CKM_VENDOR_DEFINED + 0x106)
#define CKM_SEED_MAC (CKM_VENDOR_DEFINED + 0x107)
#define CKM_SEED_MAC_GENERAL (CKM_VENDOR_DEFINED + 0x108)
#define CKM_KCDSA_SHA1 (CKM_VENDOR_DEFINED + 0x109)
#define CKM_KCDSA_SHA224 (CKM_VENDOR_DEFINED + 0x10A)
#define CKM_KCDSA_SHA256 (CKM_VENDOR_DEFINED + 0x10B)
#define CKM_KCDSA_SHA384 (CKM_VENDOR_DEFINED + 0x10C)
#define CKM_KCDSA_SHA512 (CKM_VENDOR_DEFINED + 0x10D)
#define CKM_KCDSA_PARAMETER_GEN (CKM_VENDOR_DEFINED + 0x10F)

// Defined prior PKCS#11. Must be redefined when PKCS#11 is updated
// Defined prior PKCS#11 and renamed to CKM_SHA224_xxx_OLD after PKCS#11 was
// updated
#define CKM_SHA224_RSA_PKCS_OLD (CKM_VENDOR_DEFINED + 0x110)
#define CKM_SHA224_RSA_PKCS_PSS_OLD (CKM_VENDOR_DEFINED + 0x111)
#define CKM_SHA224_OLD (CKM_VENDOR_DEFINED + 0x112)
#define CKM_SHA224_HMAC_OLD (CKM_VENDOR_DEFINED + 0x113)
#define CKM_SHA224_HMAC_GENERAL_OLD (CKM_VENDOR_DEFINED + 0x114)
#define CKM_SHA224_KEY_DERIVATION_OLD (CKM_VENDOR_DEFINED + 0x115)

#define CKM_DES3_CTR (CKM_VENDOR_DEFINED + 0x116)
#define CKM_AES_CFB8 (CKM_VENDOR_DEFINED + 0x118)
#define CKM_AES_CFB128 (CKM_VENDOR_DEFINED + 0x119)
#define CKM_AES_OFB (CKM_VENDOR_DEFINED + 0x11a)
#define CKM_AES_GCM (CKM_VENDOR_DEFINED + 0x11c)
#define CKM_ARIA_CFB8 (CKM_VENDOR_DEFINED + 0x11d)
#define CKM_ARIA_CFB128 (CKM_VENDOR_DEFINED + 0x11e)
#define CKM_ARIA_OFB (CKM_VENDOR_DEFINED + 0x11f)
#define CKM_ARIA_CTR (CKM_VENDOR_DEFINED + 0x120)
#define CKM_ARIA_GCM (CKM_VENDOR_DEFINED + 0x121)

#define CKM_ECDSA_SHA224 (CKM_VENDOR_DEFINED + 0x122)
#define CKM_ECDSA_SHA256 (CKM_VENDOR_DEFINED + 0x123)
#define CKM_ECDSA_SHA384 (CKM_VENDOR_DEFINED + 0x124)
#define CKM_ECDSA_SHA512 (CKM_VENDOR_DEFINED + 0x125)
#define CKM_AES_GMAC (CKM_VENDOR_DEFINED + 0x126)

#define CKM_ARIA_CMAC (CKM_VENDOR_DEFINED + 0x128)
#define CKM_ARIA_CMAC_GENERAL (CKM_VENDOR_DEFINED + 0x129)
#define CKM_SEED_CMAC (CKM_VENDOR_DEFINED + 0x12c)
#define CKM_SEED_CMAC_GENERAL (CKM_VENDOR_DEFINED + 0x12d)

#define CKM_DES3_CBC_PAD_IPSEC_OLD 0x00000137
#define CKM_DES3_CBC_PAD_IPSEC (CKM_VENDOR_DEFINED + 0x12e)
#define CKM_AES_CBC_PAD_IPSEC_OLD 0x00001089
#define CKM_AES_CBC_PAD_IPSEC (CKM_VENDOR_DEFINED + 0x12f)

#define CKM_ARIA_L_ECB (CKM_VENDOR_DEFINED + 0x130)
#define CKM_ARIA_L_CBC (CKM_VENDOR_DEFINED + 0x131)
#define CKM_ARIA_L_CBC_PAD (CKM_VENDOR_DEFINED + 0x132)
#define CKM_ARIA_L_MAC (CKM_VENDOR_DEFINED + 0x133)
#define CKM_ARIA_L_MAC_GENERAL (CKM_VENDOR_DEFINED + 0x134)

#define CKM_SHA224_RSA_X9_31 (CKM_VENDOR_DEFINED + 0x135)
#define CKM_SHA256_RSA_X9_31 (CKM_VENDOR_DEFINED + 0x136)
#define CKM_SHA384_RSA_X9_31 (CKM_VENDOR_DEFINED + 0x137)
#define CKM_SHA512_RSA_X9_31 (CKM_VENDOR_DEFINED + 0x138)

#define CKM_SHA1_RSA_X9_31_NON_FIPS (CKM_VENDOR_DEFINED + 0x139)
#define CKM_SHA224_RSA_X9_31_NON_FIPS (CKM_VENDOR_DEFINED + 0x13a)
#define CKM_SHA256_RSA_X9_31_NON_FIPS (CKM_VENDOR_DEFINED + 0x13b)
#define CKM_SHA384_RSA_X9_31_NON_FIPS (CKM_VENDOR_DEFINED + 0x13c)
#define CKM_SHA512_RSA_X9_31_NON_FIPS (CKM_VENDOR_DEFINED + 0x13d)
#define CKM_RSA_X9_31_NON_FIPS (CKM_VENDOR_DEFINED + 0x13e)

#define CKM_DSA_SHA224                                                         \
  (CKM_VENDOR_DEFINED + 0x140) // DH -moved here to keep ECDSA SHA 2 same as FW4
#define CKM_DSA_SHA256 (CKM_VENDOR_DEFINED + 0x141)

#define CKM_RSA_FIPS_186_3_AUX_PRIME_KEY_PAIR_GEN (CKM_VENDOR_DEFINED + 0x142)
#define CKM_RSA_FIPS_186_3_PRIME_KEY_PAIR_GEN (CKM_VENDOR_DEFINED + 0x143)
#define CKM_SEED_CTR (CKM_VENDOR_DEFINED + 0x144)

// SIM3 mechanisms
#define CKM_AES_CBC_PAD_EXTRACT (CKM_VENDOR_DEFINED + 0x200)
#define CKM_AES_CBC_PAD_INSERT (CKM_VENDOR_DEFINED + 0x201)
#define CKM_AES_CBC_PAD_EXTRACT_FLATTENED (CKM_VENDOR_DEFINED + 0x202)
#define CKM_AES_CBC_PAD_INSERT_FLATTENED (CKM_VENDOR_DEFINED + 0x203)

// defined as CKM_DES3_DERIVE_ECB in Eracom PTKC
#define CKM_PLACE_HOLDER_FOR_ERACOME_DEF_IN_SHIM (CKM_VENDOR_DEFINED + 0x502)

/*** EC IES mechanism (X9.63) */
#define CKM_ECIES (CKM_VENDOR_DEFINED + 0xA00)
#define CKM_XOR_BASE_AND_DATA_W_KDF (CKM_VENDOR_DEFINED + 0xA01)

#define CKM_NIST_PRF_KDF (CKM_VENDOR_DEFINED + 0xA02)
#define CKM_PRF_KDF (CKM_VENDOR_DEFINED + 0xA03)

/**
 * Mechanism parameters for CKM_ECIES.
 */
/** EC Diffie-Hellman (DH) primitive to use for shared secret derivation */
typedef CK_ULONG CK_EC_DH_PRIMITIVE;

/** EC DH primitives */
#define CKDHP_STANDARD 0x00000001
#define CKDHP_ECDH1_COFACTOR 0x00000001
#define CKDHP_MODIFIED 0x00000002 /* Not implemented */
#define CKDHP_ECDH1 0x00000003

/** Inner encryption scheme to use for ECIES */
typedef CK_ULONG CK_EC_ENC_SCHEME;

/** Inner encryption schemes */
#define CKES_XOR 0x00000001
#define CKES_DES3_CBC_PAD 0x00000002
#define CKES_AES_CBC_PAD 0x00000003
#define CKES_DES3_CBC 0x00000004
#define CKES_AES_CBC 0x00000005

/** Message Authentication Code (MAC) scheme to use for ECIES */
typedef CK_ULONG CK_EC_MAC_SCHEME;

/** MAC schemes */
#define CKMS_HMAC_SHA1 0x00000001
#define CKMS_SHA1 0x00000002
#define CKMS_HMAC_SHA224 0x00000003
#define CKMS_SHA224 0x00000004
#define CKMS_HMAC_SHA256 0x00000005
#define CKMS_SHA256 0x00000006
#define CKMS_HMAC_SHA384 0x00000007
#define CKMS_SHA384 0x00000008
#define CKMS_HMAC_SHA512 0x00000009
#define CKMS_SHA512 0x0000000a
#define CKMS_HMAC_RIPEMD160 0x0000000b
#define CKMS_RIPEMD160 0x0000000c

/** Mechanism parameter structure for ECIES */
typedef struct CK_ECIES_PARAMS {
  /** Diffie-Hellman primitive used to derive the shared secret value */
  CK_EC_DH_PRIMITIVE dhPrimitive;

  /**   key derivation function used on the shared secret value */
  CK_EC_KDF_TYPE kdf;

  /** the length in bytes of the key derivation shared data */
  CK_ULONG ulSharedDataLen1;

  /** the key derivation padding data shared between the two parties */
  CK_BYTE_PTR pSharedData1;

  /** the encryption scheme used to transform the input data */
  CK_EC_ENC_SCHEME encScheme;

  /** the bit length of the key to use for the encryption scheme */
  CK_ULONG ulEncKeyLenInBits;

  /** the MAC scheme used for MAC generation or validation */
  CK_EC_MAC_SCHEME macScheme;

  /** the bit length of the key to use for the MAC scheme */
  CK_ULONG ulMacKeyLenInBits;

  /** the bit length of the MAC scheme output */
  CK_ULONG ulMacLenInBits;

  /** the length in bytes of the MAC shared data */
  CK_ULONG ulSharedDataLen2;

  /** the MAC padding data shared between the two parties */
  CK_BYTE_PTR pSharedData2;
} CK_ECIES_PARAMS;

typedef CK_ECIES_PARAMS CK_PTR CK_ECIES_PARAMS_PTR;

/* Parameter and values used with CKM_PRF_KDF and
 * CKM_NIST_PRF_KDF. */

typedef CK_ULONG CK_KDF_PRF_TYPE;
typedef CK_ULONG CK_KDF_PRF_ENCODING_SCHEME;

/** PRF KDF schemes */
#define CK_NIST_PRF_KDF_DES3_CMAC 0x00000001
#define CK_NIST_PRF_KDF_AES_CMAC 0x00000002
#define CK_PRF_KDF_ARIA_CMAC 0x00000003
#define CK_PRF_KDF_SEED_CMAC 0x00000004

#define LUNA_PRF_KDF_ENCODING_SCHEME_1 0x00000000
#define LUNA_PRF_KDF_ENCODING_SCHEME_2 0x00000001

typedef struct CK_KDF_PRF_PARAMS {
  CK_KDF_PRF_TYPE prfType;
  CK_BYTE_PTR pLabel;
  CK_ULONG ulLabelLen;
  CK_BYTE_PTR pContext;
  CK_ULONG ulContextLen;
  CK_ULONG ulCounter;
  CK_KDF_PRF_ENCODING_SCHEME ulEncodingScheme;
} CK_PRF_KDF_PARAMS;

typedef CK_PRF_KDF_PARAMS CK_PTR CK_KDF_PRF_PARAMS_PTR;

/*
Additional CTR parameter structures based on CK_AES_CTR_PARAMS
PKCS has not defined these yet.
*/
#ifndef CK_SEED_CTR_PARAMS
typedef CK_AES_CTR_PARAMS CK_SEED_CTR_PARAMS;
typedef CK_SEED_CTR_PARAMS CK_PTR CK_SEED_CTR_PARAMS_PTR;
#endif

#ifndef CK_SEED_CTR_PARAMS
typedef CK_AES_CTR_PARAMS CK_ARIA_CTR_PARAMS;
typedef CK_ARIA_CTR_PARAMS CK_PTR CK_ARIA_CTR_PARAMS_PTR;
#endif

#ifndef CK_DES_CTR_PARAMS
typedef struct CK_DES_CTR_PARAMS {
  CK_ULONG ulCounterBits;
  CK_BYTE cb[8];
} CK_DES_CTR_PARAMS;
typedef CK_DES_CTR_PARAMS CK_PTR CK_DES_CTR_PARAMS_PTR;
#endif

/*
Additional GMAC parameter structures based on CK_AES_GCM_PARAMS
PKCS has not defined these yet.
*/
#ifndef CK_AES_GMAC_PARAMS
typedef CK_AES_GCM_PARAMS CK_AES_GMAC_PARAMS;
typedef CK_AES_GMAC_PARAMS CK_PTR CK_AES_GMAC_PARAMS_PTR;
#endif

#define CKR_INSERTION_CALLBACK_NOT_SUPPORTED 0x00000141
#define CKR_FUNCTION_PARALLEL 0x0052
#define CKR_SESSION_EXCLUSIVE_EXISTS 0x00B2

#define CKR_RC_ERROR (CKR_VENDOR_DEFINED + 0x04)
#define CKR_CONTAINER_HANDLE_INVALID (CKR_VENDOR_DEFINED + 0x05)
#define CKR_TOO_MANY_CONTAINERS (CKR_VENDOR_DEFINED + 0x06)
#define CKR_USER_LOCKED_OUT (CKR_VENDOR_DEFINED + 0x07)
#define CKR_CLONING_PARAMETER_ALREADY_EXISTS (CKR_VENDOR_DEFINED + 0x08)
#define CKR_CLONING_PARAMETER_MISSING (CKR_VENDOR_DEFINED + 0x09)
#define CKR_CERTIFICATE_DATA_MISSING (CKR_VENDOR_DEFINED + 0x0a)
#define CKR_CERTIFICATE_DATA_INVALID (CKR_VENDOR_DEFINED + 0x0b)
#define CKR_ACCEL_DEVICE_ERROR (CKR_VENDOR_DEFINED + 0x0c)
#define CKR_WRAPPING_ERROR (CKR_VENDOR_DEFINED + 0x0d)
#define CKR_UNWRAPPING_ERROR (CKR_VENDOR_DEFINED + 0x0e)
#define CKR_MAC_MISSING (CKR_VENDOR_DEFINED + 0x0f)
#define CKR_DAC_POLICY_PID_MISMATCH (CKR_VENDOR_DEFINED + 0x10)
#define CKR_DAC_MISSING (CKR_VENDOR_DEFINED + 0x11)
#define CKR_BAD_DAC (CKR_VENDOR_DEFINED + 0x12)
#define CKR_SSK_MISSING (CKR_VENDOR_DEFINED + 0x13)
#define CKR_BAD_MAC (CKR_VENDOR_DEFINED + 0x14)
#define CKR_DAK_MISSING (CKR_VENDOR_DEFINED + 0x15)
#define CKR_BAD_DAK (CKR_VENDOR_DEFINED + 0x16)
#define CKR_SIM_AUTHORIZATION_FAILED (CKR_VENDOR_DEFINED + 0x17)
#define CKR_SIM_VERSION_UNSUPPORTED (CKR_VENDOR_DEFINED + 0x18)
#define CKR_SIM_CORRUPT_DATA (CKR_VENDOR_DEFINED + 0x19)
#define CKR_USER_NOT_AUTHORIZED (CKR_VENDOR_DEFINED + 0x1a)
#define CKR_MAX_OBJECT_COUNT_EXCEEDED (CKR_VENDOR_DEFINED + 0x1b)
#define CKR_SO_LOGIN_FAILURE_THRESHOLD (CKR_VENDOR_DEFINED + 0x1c)
#define CKR_SIM_AUTHFORM_INVALID (CKR_VENDOR_DEFINED + 0x1d)
#define CKR_CITS_DAK_MISSING (CKR_VENDOR_DEFINED + 0x1e)
#define CKR_UNABLE_TO_CONNECT (CKR_VENDOR_DEFINED + 0x1f)
#define CKR_PARTITION_DISABLED (CKR_VENDOR_DEFINED + 0x20)
#define CKR_CALLBACK_ERROR (CKR_VENDOR_DEFINED + 0x21)
#define CKR_SECURITY_PARAMETER_MISSING (CKR_VENDOR_DEFINED + 0x22)
#define CKR_SP_TIMEOUT (CKR_VENDOR_DEFINED + 0x23)
#define CKR_TIMEOUT (CKR_VENDOR_DEFINED + 0x24)
#define CKR_ECC_UNKNOWN_CURVE (CKR_VENDOR_DEFINED + 0x25)
#define CKR_MTK_ZEROIZED (CKR_VENDOR_DEFINED + 0x26)
#define CKR_MTK_STATE_INVALID (CKR_VENDOR_DEFINED + 0x27)
#define CKR_INVALID_ENTRY_TYPE (CKR_VENDOR_DEFINED + 0x28)
#define CKR_MTK_SPLIT_INVALID (CKR_VENDOR_DEFINED + 0x29)
#define CKR_HSM_STORAGE_FULL (CKR_VENDOR_DEFINED + 0x2a)
#define CKR_DEVICE_TIMEOUT (CKR_VENDOR_DEFINED + 0x2b)
#define CKR_CONTAINER_OBJECT_STORAGE_FULL (CKR_VENDOR_DEFINED + 0x2C)
#define CKR_PED_CLIENT_NOT_RUNNING (CKR_VENDOR_DEFINED + 0x2D)
#define CKR_PED_UNPLUGGED (CKR_VENDOR_DEFINED + 0x2E)
#define CKR_ECC_POINT_INVALID (CKR_VENDOR_DEFINED + 0x2F)
#define CKR_OPERATION_NOT_ALLOWED (CKR_VENDOR_DEFINED + 0x30)
#define CKR_LICENSE_CAPACITY_EXCEEDED (CKR_VENDOR_DEFINED + 0x31)
#define CKR_LOG_FILE_NOT_OPEN (CKR_VENDOR_DEFINED + 0x32)
#define CKR_LOG_FILE_WRITE_ERROR (CKR_VENDOR_DEFINED + 0x33)
#define CKR_LOG_BAD_FILE_NAME (CKR_VENDOR_DEFINED + 0x34)
#define CKR_LOG_FULL (CKR_VENDOR_DEFINED + 0x35)
#define CKR_LOG_NO_KCV (CKR_VENDOR_DEFINED + 0x36)
#define CKR_LOG_BAD_RECORD_HMAC (CKR_VENDOR_DEFINED + 0x37)
#define CKR_LOG_BAD_TIME (CKR_VENDOR_DEFINED + 0x38)
#define CKR_LOG_AUDIT_NOT_INITIALIZED (CKR_VENDOR_DEFINED + 0x39)
#define CKR_LOG_RESYNC_NEEDED (CKR_VENDOR_DEFINED + 0x3A)
#define CKR_AUDIT_LOGIN_TIMEOUT_IN_PROGRESS (CKR_VENDOR_DEFINED + 0x3B)
#define CKR_AUDIT_LOGIN_FAILURE_THRESHOLD (CKR_VENDOR_DEFINED + 0x3C)
#define CKR_INVALID_FUF_TARGET (CKR_VENDOR_DEFINED + 0x3D)
#define CKR_INVALID_FUF_HEADER (CKR_VENDOR_DEFINED + 0x3E)
#define CKR_INVALID_FUF_VERSION (CKR_VENDOR_DEFINED + 0x3F)
#define CKR_ECC_ECC_RESULT_AT_INF (CKR_VENDOR_DEFINED + 0x40)

// This matches the one already defined for the PTK
#define CKR_KEY_NOT_ACTIVE (CKR_VENDOR_DEFINED + 0x136)

/****************************************************************************\
*
* M of N
*
\****************************************************************************/
typedef struct {
  CK_ULONG ulWeight;
  CK_BYTE_PTR pVector;
  CK_ULONG ulVectorLen;
} CA_MOFN_GENERATION;
typedef CA_MOFN_GENERATION *CA_MOFN_GENERATION_PTR;

typedef struct {
  CK_BYTE_PTR pVector;
  CK_ULONG ulVectorLen;
} CA_MOFN_ACTIVATION;
typedef CA_MOFN_ACTIVATION *CA_MOFN_ACTIVATION_PTR;

typedef struct CA_M_OF_N_STATUS {
  CK_ULONG ulID;
  CK_ULONG ulM;
  CK_ULONG ulN;
  CK_ULONG ulSecretSize;
  CK_ULONG ulFlag; // contains 3 bits: bActive, bGenerated, and bRequired,
                   // bMofNCloneable
} CA_MOFN_STATUS;
typedef CA_MOFN_STATUS *CA_MOFN_STATUS_PTR;

#define CAF_M_OF_N_REQUIRED 0x00000001
#define CAF_M_OF_N_ACTIVATED 0x00000002
#define CAF_M_OF_N_GENERATED 0x00000004
#define CAF_M_OF_N_CLONEABLE 0x00000008

/****************************************************************************\
*
* Custom module loading and management
*
\****************************************************************************/
typedef CK_ULONG CKCA_MODULE_ID;
typedef CKCA_MODULE_ID CK_POINTER CKCA_MODULE_ID_PTR;

typedef struct CKCA_MODULE_INFO {
  CK_ULONG ulModuleSize;
  CK_CHAR developerName[32];
  CK_CHAR moduleDescription[32];
  CK_VERSION moduleVersion;
} CKCA_MODULE_INFO;
typedef CKCA_MODULE_INFO CK_POINTER CKCA_MODULE_INFO_PTR;

#define CKCAO_Encrypt 0
#define CKCAO_Decrypt 1
#define CKCAO_Sign 2
#define CKCAO_Verify 3
#define CKCAO_Digest 4

/****************************************************************************\
*
* SafeNet High Availability Status function
*
\****************************************************************************/
// assume a client doesn't look at more than 32 Vipers
#define CK_HA_MAX_MEMBERS 32

typedef struct CK_HA_MEMBER {
  CK_ULONG memberSerial;
  CK_RV memberStatus;
} CK_HA_MEMBER;

typedef struct CK_HA_STATUS {
  CK_ULONG groupSerial;
  CK_HA_MEMBER memberList[CK_HA_MAX_MEMBERS];
  CK_ULONG listSize;
} CK_HA_STATUS;

typedef CK_HA_MEMBER CK_POINTER CK_HA_MEMBER_PTR;

typedef CK_HA_STATUS CK_POINTER CK_HA_STATE_PTR;

/****************************************************************************\
*
* SafeNet Hardware Secured Certificate functions
*
\****************************************************************************/

#define CKHSC_CERT_TYPE_TCTRUST_MAC 0x00000001
#define CKHSC_CERT_TYPE_TCTRUST_DAC 0x00000002
#define CKHSC_CERT_TYPE_CITS_ROOT 0x00000003
#define CKHSC_CERT_TYPE_CITS_MICHOC 0x00000004
#define CKHSC_CERT_TYPE_CITS_DAC 0x00000005

#define CKHSC_CERT_TYPE_ECC_MIC 0x00000006
#define CKHSC_CERT_TYPE_ECC_HOC 0x00000007
#define CKHSC_CERT_TYPE_ECC_DAC 0x00000008

#define CKHSC_CERT_TYPE_TWC 0x00000009
#define CKHSC_CERT_TYPE_TWC2 0x0000000A
#define CKHSC_CERT_TYPE_TWC3 0x0000000B

typedef CK_ULONG CKA_SIM_AUTH_FORM;

#define CKA_SIM_NO_AUTHORIZATION 0 // no authorization needed
#define CKA_SIM_PASSWORD 1         // plain-text passwords
#define CKA_SIM_CHALLENGE 2 // challenge secrets emitted through the secure port
#define CKA_SIM_SECURE_PORT 3 // PED keys

// Portable SIM
#define CKA_SIM_PORTABLE_NO_AUTHORIZATION 4 // no authorization needed, portable
#define CKA_SIM_PORTABLE_PASSWORD 5         // plain-text passwords, portable
#define CKA_SIM_PORTABLE_CHALLENGE                                             \
  6 // challenge secrets emitted through the secure port, portable
#define CKA_SIM_PORTABLE_SECURE_PORT 7 // PED keys, portable

//////////////////////////////////////////////////////////////////////
// SIM3 Mechanisms
//
// Note: These are defined in the standard cryptoki mechanism list,
//       elsewhere in this file, they're copied here to ease their use
//////////////////////////////////////////////////////////////////////.

// CKM_AES_CBC_PAD_EXTRACT                (CKM_VENDOR_DEFINED + 0x200)
// CKM_AES_CBC_PAD_INSERT                 (CKM_VENDOR_DEFINED + 0x201)
// CKM_AES_CBC_PAD_EXTRACT_FLATTENED      (CKM_VENDOR_DEFINED + 0x202)
// CKM_AES_CBC_PAD_INSERT_FLATTENED       (CKM_VENDOR_DEFINED + 0x203)

//////////////////////////////////////////////////////////////////////
// SIM3 Element types
//////////////////////////////////////////////////////////////////////

#define CK_NULL_ELEMENT (-1)
#define CK_CRYPTOKI_ELEMENT 0x00000000
#define CK_PARAM_ELEMENT 0x00000001
#define CK_CONTAINER_ACTIVATION_ELEMENT 0x00000002
#define CK_MOFN_ACTIVATION_ELEMENT 0x00000003
#define CK_CONTAINER_ELEMENT 0x00000004

//////////////////////////////////////////////////////////////////////
// Various Cloning size definitions
//////////////////////////////////////////////////////////////////////
#define CK_CLONING_PART1_OVERHEAD 8192
#define CK_CLONING_PART2_OVERHEAD 76
#define CK_FLATTENED_OBJECT_OVERHEAD 3264

//////////////////////////////////////////////////////////////////////
// SIM3 Mechanism parameters
//////////////////////////////////////////////////////////////////////

typedef struct CK_AES_CBC_PAD_EXTRACT_PARAMS {
  CK_ULONG ulType;               // in
  CK_ULONG ulHandle;             // in
  CK_ULONG ulDeleteAfterExtract; // in
  CK_BYTE_PTR pBuffer;           // out
  CK_ULONG_PTR pulBufferLen;     // out
  //      Additional PED CF related parameters:
  CK_ULONG ulStorage; // in: place of HSM object storage: HSM_T, HSM_PED_T, etc.
                      // See luna2if.h .
  CK_ULONG pedId;     // in: PED ID: 0 (local), 1, 2,...
  CK_BYTE_PTR
  pbFileName; // in: name of the file at ulStorage, where the object stored.
} CK_AES_CBC_PAD_EXTRACT_PARAMS;

typedef CK_AES_CBC_PAD_EXTRACT_PARAMS CK_POINTER
    CK_AES_CBC_PAD_EXTRACT_PARAMS_PTR;

typedef struct CK_AES_CBC_PAD_INSERT_PARAMS {
  CK_ULONG ulStorageType;    // in
  CK_ULONG ulContainerState; // in
  CK_BYTE_PTR pBuffer;       // in
  CK_ULONG ulBufferLen;      // in
  CK_ULONG_PTR pulType;      // out
  CK_ULONG_PTR pulHandle;    // out
  //      Additional PED CF related parameters:
  CK_ULONG ulStorage; // in: place of HSM object storage: HSM_T, HSM_PED_T, etc.
                      // See luna2if.h .
  CK_ULONG pedId;     // in: PED ID: 0 (local), 1, 2,...
  CK_BYTE_PTR
  pbFileName; // in: name of the file at ulStorage, where the object stored.
} CK_AES_CBC_PAD_INSERT_PARAMS;

typedef CK_AES_CBC_PAD_INSERT_PARAMS CK_POINTER
    CK_AES_CBC_PAD_INSERT_PARAMS_PTR;

//////////////////////////////////////////////////////////////////////////////
// SIM3:
// List of available storage location (tokens) for keeping extracted objects.
//////////////////////////////////////////////////////////////////////////////
#define CK_STORAGE_HOST 0x00000000
#define CK_STORAGE_PED_USB_MEMORY 0x00000001
#define CK_STORAGE_HSM_USB_MEMORY 0x00000002

/****************************************************************************\
*                                                                            *
* MTK management                                                          *
*                                                                            *
\****************************************************************************/
#define CK_MTK_STATE_FLAG_RESPLIT_ABORTED 0x00000001
#define CK_MTK_STATE_FLAG_HARD_ZEROIZE 0x00000002
#define CK_MTK_STATE_FLAG_SOFT_ZEROIZE 0x00000004
#define CK_MTK_STATE_FLAG_LOCKED 0x00000008

/****************************************************************************************/

/****************************************************************************\
*
* SafeNet Cluster functions
*
\****************************************************************************/
#ifndef CK_MAX_CLUSTER_MEMBERS
#define CK_MAX_CLUSTER_MEMBERS 8

typedef struct CK_CLUSTER_STATE {
  CK_BYTE bMembers[CK_MAX_CLUSTER_MEMBERS][32];
  CK_ULONG ulMemberStatus[CK_MAX_CLUSTER_MEMBERS];
} CK_CLUSTER_STATE;

typedef CK_CLUSTER_STATE CK_POINTER CK_CLUSTER_STATE_PTR;

#endif

/****************************************************************************\
*
* SafeNet LKM definitions and functions
*
\****************************************************************************/
#define AKEP2_XDH_SIZE 128 // size of LKM public key

/* Maximum size of digest generated by AKEP2's hash algorithms */
#define AKEP2_MAX_DIGEST_SIZE 32

/* Node ID size */
#define AKEP2_NID_SIZE 20

typedef struct CK_LKM_TOKEN_ID_S {
  CK_BYTE id[AKEP2_NID_SIZE];
} CK_LKM_TOKEN_ID;

typedef CK_LKM_TOKEN_ID CK_POINTER CK_LKM_TOKEN_ID_PTR;

/****************************************************************************\
*
* SafeNet PED ID constants
*
\****************************************************************************/
#define CK_PED_ID_LOCAL 0x0000

#define CK_PED_ID_MAX 0xFFFE

/****************************************************************************\
*
* SafeNet Usage Counter definitions and functions
*
\****************************************************************************/
#define CK_MODIFY_USAGE_COUNT_COMMAND_TYPE_INCREMENT 0x00000001
#define CK_MODIFY_USAGE_COUNT_COMMAND_TYPE_SET 0x00000002

/****************************************************************************\
*
* SafeNet function list for CA_ function pointers
*
\****************************************************************************/

/* CK_SFNT_CA_FUNCTION_LIST is a structure holding a Cryptoki spec
 * version and pointers of appropriate types to all the
 * Cryptoki functions */
typedef struct CK_SFNT_CA_FUNCTION_LIST CK_SFNT_CA_FUNCTION_LIST;

typedef CK_SFNT_CA_FUNCTION_LIST CK_PTR CK_SFNT_CA_FUNCTION_LIST_PTR;

typedef CK_SFNT_CA_FUNCTION_LIST_PTR CK_PTR CK_SFNT_CA_FUNCTION_LIST_PTR_PTR;

#include "sfnt_extensions.h"

struct CK_SFNT_CA_FUNCTION_LIST {

  CK_VERSION version; /* Cryptoki version */

  CK_CA_GetFunctionList CA_GetFunctionList;
  CK_CA_WaitForSlotEvent CA_WaitForSlotEvent;
  CK_CA_InitIndirectToken CA_InitIndirectToken;
  CK_CA_InitIndirectPIN CA_InitIndirectPIN;
  CK_CA_ResetPIN CA_ResetPIN;
  CK_CA_CreateLoginChallenge CA_CreateLoginChallenge;
  CK_CA_Deactivate CA_Deactivate;
  CK_CA_OpenSession CA_OpenSession;
  CK_CA_IndirectLogin CA_IndirectLogin;
  CK_CA_InitializeRemotePEDVector CA_InitializeRemotePEDVector;
  CK_CA_DeleteRemotePEDVector CA_DeleteRemotePEDVector;
  CK_CA_GetRemotePEDVectorStatus CA_GetRemotePEDVectorStatus;
  CK_CA_ConfigureRemotePED CA_ConfigureRemotePED;
  CK_CA_DismantleRemotePED CA_DismantleRemotePED;
  CK_CA_Restart CA_Restart;
  CK_CA_RestartForContainer CA_RestartForContainer;
  CK_CA_CloseApplicationID CA_CloseApplicationID;
  CK_CA_CloseApplicationIDForContainer CA_CloseApplicationIDForContainer;
  CK_CA_OpenApplicationID CA_OpenApplicationID;
  CK_CA_OpenApplicationIDForContainer CA_OpenApplicationIDForContainer;
  CK_CA_SetApplicationID CA_SetApplicationID;
  CK_CA_ManualKCV CA_ManualKCV;
  CK_CA_SetLKCV CA_SetLKCV;
  CK_CA_SetKCV CA_SetKCV;
  CK_CA_SetCloningDomain CA_SetCloningDomain;
  CK_CA_ClonePrivateKey CA_ClonePrivateKey;
  CK_CA_CloneObject CA_CloneObject;
  CK_CA_GenerateCloningKEV CA_GenerateCloningKEV;
  CK_CA_CloneAsTargetInit CA_CloneAsTargetInit;
  CK_CA_CloneAsSource CA_CloneAsSource;
  CK_CA_CloneAsTarget CA_CloneAsTarget;
  CK_CA_SetMofN CA_SetMofN;
  CK_CA_GenerateMofN CA_GenerateMofN;
  CK_CA_GenerateCloneableMofN CA_GenerateCloneableMofN;
  CK_CA_ModifyMofN CA_ModifyMofN;
  CK_CA_CloneMofN CA_CloneMofN;
  CK_CA_CloneModifyMofN CA_CloneModifyMofN;
  CK_CA_ActivateMofN CA_ActivateMofN;
  CK_CA_DeactivateMofN CA_DeactivateMofN;
  CK_CA_GetMofNStatus CA_GetMofNStatus;
  CK_CA_DuplicateMofN CA_DuplicateMofN;
  CK_CA_IsMofNEnabled CA_IsMofNEnabled;
  CK_CA_IsMofNRequired CA_IsMofNRequired;
  CK_CA_GenerateTokenKeys CA_GenerateTokenKeys;
  CK_CA_GetTokenCertificateInfo CA_GetTokenCertificateInfo;
  CK_CA_SetTokenCertificateSignature CA_SetTokenCertificateSignature;
  CK_CA_GetModuleList CA_GetModuleList;
  CK_CA_GetModuleInfo CA_GetModuleInfo;
  CK_CA_LoadModule CA_LoadModule;
  CK_CA_LoadEncryptedModule CA_LoadEncryptedModule;
  CK_CA_UnloadModule CA_UnloadModule;
  CK_CA_PerformModuleCall CA_PerformModuleCall;
  CK_C_PerformSelfTest C_PerformSelfTest;
  CK_CA_FirmwareUpdate CA_FirmwareUpdate;
  CK_CA_FirmwareRollback CA_FirmwareRollback;
  CK_CA_CapabilityUpdate CA_CapabilityUpdate;
  CK_CA_GetUserContainerNumber CA_GetUserContainerNumber;
  CK_CA_GetUserContainerName CA_GetUserContainerName;
  CK_CA_SetUserContainerName CA_SetUserContainerName;
  CK_CA_GetTokenInsertionCount CA_GetTokenInsertionCount;
  CK_CA_GetRollbackFirmwareVersion CA_GetRollbackFirmwareVersion;
  CK_CA_GetFPV CA_GetFPV;
  CK_CA_GetTPV CA_GetTPV;
  CK_CA_GetExtendedTPV CA_GetExtendedTPV;
  CK_CA_GetConfigurationElementDescription
      CA_GetConfigurationElementDescription;
  CK_CA_GetHSMCapabilitySet CA_GetHSMCapabilitySet;
  CK_CA_GetHSMCapabilitySetting CA_GetHSMCapabilitySetting;
  CK_CA_GetHSMPolicySet CA_GetHSMPolicySet;
  CK_CA_GetHSMPolicySetting CA_GetHSMPolicySetting;
  CK_CA_GetContainerCapabilitySet CA_GetContainerCapabilitySet;
  CK_CA_GetContainerCapabilitySetting CA_GetContainerCapabilitySetting;
  CK_CA_GetContainerPolicySet CA_GetContainerPolicySet;
  CK_CA_GetContainerPolicySetting CA_GetContainerPolicySetting;
  CK_CA_SetTPV CA_SetTPV;
  CK_CA_SetExtendedTPV CA_SetExtendedTPV;
  CK_CA_SetHSMPolicy CA_SetHSMPolicy;
  CK_CA_SetHSMPolicies CA_SetHSMPolicies;
  CK_CA_SetDestructiveHSMPolicy CA_SetDestructiveHSMPolicy;
  CK_CA_SetDestructiveHSMPolicies CA_SetDestructiveHSMPolicies;
  CK_CA_SetContainerPolicy CA_SetContainerPolicy;
  CK_CA_SetContainerPolicies CA_SetContainerPolicies;
  CK_CA_RetrieveLicenseList CA_RetrieveLicenseList;
  CK_CA_QueryLicense CA_QueryLicense;
  CK_CA_GetContainerStatus CA_GetContainerStatus;
  CK_CA_GetSessionInfo CA_GetSessionInfo;
  CK_CA_ReadCommonStore CA_ReadCommonStore;
  CK_CA_WriteCommonStore CA_WriteCommonStore;
  CK_CA_GetPrimarySlot CA_GetPrimarySlot;
  CK_CA_GetSecondarySlot CA_GetSecondarySlot;
  CK_CA_SwitchSecondarySlot CA_SwitchSecondarySlot;
  CK_CA_CloseSecondarySession CA_CloseSecondarySession;
  CK_CA_CloseAllSecondarySessions CA_CloseAllSecondarySessions;
  CK_CA_ChoosePrimarySlot CA_ChoosePrimarySlot;
  CK_CA_ChooseSecondarySlot CA_ChooseSecondarySlot;
  CK_CA_CloneObjectToAllSessions CA_CloneObjectToAllSessions;
  CK_CA_CloneAllObjectsToSession CA_CloneAllObjectsToSession;
  CK_CA_ResetDevice CA_ResetDevice;
  CK_CA_FactoryReset CA_FactoryReset;
  CK_CA_SetPedId CA_SetPedId;
  CK_CA_GetPedId CA_GetPedId;
  CK_CA_SpRawRead CA_SpRawRead;
  CK_CA_SpRawWrite CA_SpRawWrite;
  CK_CA_CheckOperationState CA_CheckOperationState;
  CK_CA_DestroyMultipleObjects CA_DestroyMultipleObjects;
  CK_CA_HAInit CA_HAInit;
  CK_CA_HAGetMasterPublic CA_HAGetMasterPublic;
  CK_CA_HAGetLoginChallenge CA_HAGetLoginChallenge;
  CK_CA_HAAnswerLoginChallenge CA_HAAnswerLoginChallenge;
  CK_CA_HALogin CA_HALogin;
  CK_CA_HAAnswerMofNChallenge CA_HAAnswerMofNChallenge;
  CK_CA_HAActivateMofN CA_HAActivateMofN;
  CK_CA_GetHAState CA_GetHAState;
  CK_CA_GetTokenCertificates CA_GetTokenCertificates;
  CK_CA_ExtractMaskedObject CA_ExtractMaskedObject;
  CK_CA_InsertMaskedObject CA_InsertMaskedObject;
  CK_CA_MultisignValue CA_MultisignValue;
  CK_CA_SIMExtract CA_SIMExtract;
  CK_CA_SIMInsert CA_SIMInsert;
  CK_CA_SIMMultiSign CA_SIMMultiSign;
  CK_CA_Extract CA_Extract;
  CK_CA_Insert CA_Insert;
  CK_CA_GetObjectUID CA_GetObjectUID;
  CK_CA_GetObjectHandle CA_GetObjectHandle;
  CK_CA_DeleteContainer CA_DeleteContainer;
  CK_CA_MTKSetStorage CA_MTKSetStorage;
  CK_CA_MTKRestore CA_MTKRestore;
  CK_CA_MTKResplit CA_MTKResplit;
  CK_CA_MTKZeroize CA_MTKZeroize;
  CK_CA_MTKGetState CA_MTKGetState;
  CK_CA_GetTSV CA_GetTSV;
  CK_CA_InvokeServiceInit CA_InvokeServiceInit;
  CK_CA_InvokeService CA_InvokeService;
  CK_CA_InvokeServiceFinal CA_InvokeServiceFinal;
  CK_CA_InvokeServiceAsynch CA_InvokeServiceAsynch;
  CK_CA_InvokeServiceSinglePart CA_InvokeServiceSinglePart;
  CK_CA_EncodeECPrimeParams CA_EncodeECPrimeParams;
  CK_CA_EncodeECChar2Params CA_EncodeECChar2Params;
  CK_CA_EncodeECParamsFromFile CA_EncodeECParamsFromFile;
  CK_CA_GetHSMStorageInformation CA_GetHSMStorageInformation;
  CK_CA_GetContainerStorageInformation CA_GetContainerStorageInformation;
  CK_CA_SetContainerSize CA_SetContainerSize;
  CK_CA_CreateContainer CA_CreateContainer;
  CK_CA_DeleteContainerWithHandle CA_DeleteContainerWithHandle;
  CK_CA_GetContainerList CA_GetContainerList;
  CK_CA_GetContainerName CA_GetContainerName;
  CK_CA_GetNumberOfAllowedContainers CA_GetNumberOfAllowedContainers;
  CK_CA_GetTunnelSlotNumber CA_GetTunnelSlotNumber;
  CK_CA_GetClusterState CA_GetClusterState;
  CK_CA_LockClusteredSlot CA_LockClusteredSlot;
  CK_CA_UnlockClusteredSlot CA_UnlockClusteredSlot;
  CK_CA_LKMInitiatorChallenge CA_LKMInitiatorChallenge;
  CK_CA_LKMReceiverResponse CA_LKMReceiverResponse;
  CK_CA_LKMInitiatorComplete CA_LKMInitiatorComplete;
  CK_CA_LKMReceiverComplete CA_LKMReceiverComplete;
  CK_CA_ModifyUsageCount CA_ModifyUsageCount;
  CK_CA_LogVerify CA_LogVerify;
  CK_CA_LogVerifyFile CA_LogVerifyFile;
  CK_CA_LogExternal CA_LogExternal;
  CK_CA_LogImportSecret CA_LogImportSecret;
  CK_CA_LogExportSecret CA_LogExportSecret;
  CK_CA_LogSetConfig CA_LogSetConfig;
  CK_CA_LogGetconfig CA_LogGetConfig;
  CK_CA_LogEraseAll CA_LogEraseAll;
  CK_CA_LogGetStatus CA_LogGetStatus;
  CK_CA_InitAudit CA_InitAudit;
  CK_CA_GetTime CA_GetTime;
  CK_CA_TimeSync CA_TimeSync;
};

#if defined(VXD)
#pragma pack(pop)
#elif defined(OS_WIN32)
#pragma pack(pop, cryptoki)
#elif defined(OS_UNIX) || defined(OS_LINUX)
//   #pragma pack
#else
#error "Unknown platform!"
#endif

#ifdef __cplusplus
}
#endif

#ifndef OS_HPUX
#pragma deprecated(CK_USHORT, CK_USHORT_PTR)
#endif // OS_HPUX

#endif /* CRYPTOKI_H_ */
