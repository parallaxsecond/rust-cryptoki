#if defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)
#pragma pack(push, cryptoki, 1)
#endif

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#define NULL_PTR 0

// bugs?
#define CK_BOOL CK_BBOOL
#define CK_HANDLE CK_ULONG

#include "vendor/pkcs11.h"

#if defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)
#pragma pack(pop, cryptoki, 1)
#endif
