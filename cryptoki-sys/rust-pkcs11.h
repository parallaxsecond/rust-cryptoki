#ifndef CRYPTOKI_SYS_RUST_PKCS11_H
#define CRYPTOKI_SYS_RUST_PKCS11_H

#ifdef _MSC_VER
#pragma pack(push, cryptoki, 1)
#endif

// Define UNIX defaults for PKCS11 interface

/// 1. CK_PTR: The indirection string for making a pointer to an object.
#define CK_PTR *

/// 2. CK_DECLARE_FUNCTION(returnType, name): A macro which makes an importable
/// Cryptoki library function declaration out of a return type and a function
/// name.
#define CK_DECLARE_FUNCTION(returnType, name) \
    returnType name

/// 3. CK_DECLARE_FUNCTION_POINTER(returnType, name): A macro which makes a
/// Cryptoki API function pointer declaration or function pointer type
/// declaration out of a return type and a function name.
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
    returnType (*name)

/// 4. CK_CALLBACK_FUNCTION(returnType, name): A macro which makes a function
/// pointer type for an application callback out of a return type for the
/// callback and a name for the callback.
#define CK_CALLBACK_FUNCTION(returnType, name) \
    returnType (*name)

/// 5. NULL_PTR: This macro is the value of a NULL pointer.
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "oasis-headers/pkcs11.h"

#ifdef _MSC_VER
#pragma pack(pop, cryptoki)
#endif

#endif