// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Function types

use crate::context::Function;

use super::{Error, Result, RvError};
use cryptoki_sys::*;
use log::error;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
/// Return value of a PKCS11 function
pub enum Rv {
    /// The function exited successfully
    Ok,
    /// There was an error
    Error(RvError),
}

/// One row per standard return value, `RvError` variant => `CKR_*` constant: `From<CK_RV> for Rv`,
/// its inverse and `RvError::name` are all generated from it, so they cannot disagree.
macro_rules! rv_errors {
    ($($variant:ident => $ckr:ident,)*) => {
        impl From<CK_RV> for Rv {
            fn from(ck_rv: CK_RV) -> Self {
                match ck_rv {
                    CKR_OK => Rv::Ok,
                    $($ckr => Rv::Error(RvError::$variant),)*
                    CKR_VENDOR_DEFINED..=CK_ULONG::MAX => Rv::Error(RvError::VendorDefined(ck_rv)),
                    other => {
                        error!(
                            "Can not find a corresponding error for {other}, converting to UnknownErrorCode."
                        );
                        Rv::Error(RvError::UnknownErrorCode(other))
                    }
                }
            }
        }

        impl From<RvError> for CK_RV {
            /// The return value an error stands for: the inverse of `From<CK_RV> for Rv`.
            fn from(rv_error: RvError) -> Self {
                match rv_error {
                    $(RvError::$variant => $ckr,)*
                    RvError::VendorDefined(ck_rv) | RvError::UnknownErrorCode(ck_rv) => ck_rv,
                }
            }
        }

        impl RvError {
            /// The name of the `CKR_*` constant this error stands for, as the specification spells
            /// it; `None` for a vendor-defined or unknown return value.
            pub fn name(&self) -> Option<&'static str> {
                match self {
                    $(RvError::$variant => Some(stringify!($ckr)),)*
                    RvError::VendorDefined(_) | RvError::UnknownErrorCode(_) => None,
                }
            }
        }
    };
}

rv_errors! {
    Cancel => CKR_CANCEL,
    HostMemory => CKR_HOST_MEMORY,
    SlotIdInvalid => CKR_SLOT_ID_INVALID,
    GeneralError => CKR_GENERAL_ERROR,
    FunctionFailed => CKR_FUNCTION_FAILED,
    ArgumentsBad => CKR_ARGUMENTS_BAD,
    NoEvent => CKR_NO_EVENT,
    NeedToCreateThreads => CKR_NEED_TO_CREATE_THREADS,
    CantLock => CKR_CANT_LOCK,
    AttributeReadOnly => CKR_ATTRIBUTE_READ_ONLY,
    AttributeSensitive => CKR_ATTRIBUTE_SENSITIVE,
    AttributeTypeInvalid => CKR_ATTRIBUTE_TYPE_INVALID,
    AttributeValueInvalid => CKR_ATTRIBUTE_VALUE_INVALID,
    ActionProhibited => CKR_ACTION_PROHIBITED,
    DataInvalid => CKR_DATA_INVALID,
    DataLenRange => CKR_DATA_LEN_RANGE,
    DeviceError => CKR_DEVICE_ERROR,
    DeviceMemory => CKR_DEVICE_MEMORY,
    DeviceRemoved => CKR_DEVICE_REMOVED,
    EncryptedDataInvalid => CKR_ENCRYPTED_DATA_INVALID,
    EncryptedDataLenRange => CKR_ENCRYPTED_DATA_LEN_RANGE,
    FunctionCanceled => CKR_FUNCTION_CANCELED,
    FunctionNotParallel => CKR_FUNCTION_NOT_PARALLEL,
    FunctionNotSupported => CKR_FUNCTION_NOT_SUPPORTED,
    CurveNotSupported => CKR_CURVE_NOT_SUPPORTED,
    KeyHandleInvalid => CKR_KEY_HANDLE_INVALID,
    KeySizeRange => CKR_KEY_SIZE_RANGE,
    KeyTypeInconsistent => CKR_KEY_TYPE_INCONSISTENT,
    KeyNotNeeded => CKR_KEY_NOT_NEEDED,
    KeyChanged => CKR_KEY_CHANGED,
    KeyNeeded => CKR_KEY_NEEDED,
    KeyIndigestible => CKR_KEY_INDIGESTIBLE,
    KeyFunctionNotPermitted => CKR_KEY_FUNCTION_NOT_PERMITTED,
    KeyNotWrappable => CKR_KEY_NOT_WRAPPABLE,
    KeyUnextractable => CKR_KEY_UNEXTRACTABLE,
    MechanismInvalid => CKR_MECHANISM_INVALID,
    MechanismParamInvalid => CKR_MECHANISM_PARAM_INVALID,
    ObjectHandleInvalid => CKR_OBJECT_HANDLE_INVALID,
    OperationActive => CKR_OPERATION_ACTIVE,
    OperationNotInitialized => CKR_OPERATION_NOT_INITIALIZED,
    PinIncorrect => CKR_PIN_INCORRECT,
    PinInvalid => CKR_PIN_INVALID,
    PinLenRange => CKR_PIN_LEN_RANGE,
    PinExpired => CKR_PIN_EXPIRED,
    PinLocked => CKR_PIN_LOCKED,
    SessionClosed => CKR_SESSION_CLOSED,
    SessionCount => CKR_SESSION_COUNT,
    SessionHandleInvalid => CKR_SESSION_HANDLE_INVALID,
    SessionParallelNotSupported => CKR_SESSION_PARALLEL_NOT_SUPPORTED,
    SessionReadOnly => CKR_SESSION_READ_ONLY,
    SessionExists => CKR_SESSION_EXISTS,
    SessionReadOnlyExists => CKR_SESSION_READ_ONLY_EXISTS,
    SessionReadWriteSoExists => CKR_SESSION_READ_WRITE_SO_EXISTS,
    SignatureInvalid => CKR_SIGNATURE_INVALID,
    SignatureLenRange => CKR_SIGNATURE_LEN_RANGE,
    TemplateIncomplete => CKR_TEMPLATE_INCOMPLETE,
    TemplateInconsistent => CKR_TEMPLATE_INCONSISTENT,
    TokenNotPresent => CKR_TOKEN_NOT_PRESENT,
    TokenNotRecognized => CKR_TOKEN_NOT_RECOGNIZED,
    TokenWriteProtected => CKR_TOKEN_WRITE_PROTECTED,
    UnwrappingKeyHandleInvalid => CKR_UNWRAPPING_KEY_HANDLE_INVALID,
    UnwrappingKeySizeRange => CKR_UNWRAPPING_KEY_SIZE_RANGE,
    UnwrappingKeyTypeInconsistent => CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
    UserAlreadyLoggedIn => CKR_USER_ALREADY_LOGGED_IN,
    UserNotLoggedIn => CKR_USER_NOT_LOGGED_IN,
    UserPinNotInitialized => CKR_USER_PIN_NOT_INITIALIZED,
    UserTypeInvalid => CKR_USER_TYPE_INVALID,
    UserAnotherAlreadyLoggedIn => CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
    UserTooManyTypes => CKR_USER_TOO_MANY_TYPES,
    WrappedKeyInvalid => CKR_WRAPPED_KEY_INVALID,
    WrappedKeyLenRange => CKR_WRAPPED_KEY_LEN_RANGE,
    WrappingKeyHandleInvalid => CKR_WRAPPING_KEY_HANDLE_INVALID,
    WrappingKeySizeRange => CKR_WRAPPING_KEY_SIZE_RANGE,
    WrappingKeyTypeInconsistent => CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
    RandomSeedNotSupported => CKR_RANDOM_SEED_NOT_SUPPORTED,
    RandomNoRng => CKR_RANDOM_NO_RNG,
    DomainParamsInvalid => CKR_DOMAIN_PARAMS_INVALID,
    BufferTooSmall => CKR_BUFFER_TOO_SMALL,
    SavedStateInvalid => CKR_SAVED_STATE_INVALID,
    InformationSensitive => CKR_INFORMATION_SENSITIVE,
    StateUnsaveable => CKR_STATE_UNSAVEABLE,
    CryptokiNotInitialized => CKR_CRYPTOKI_NOT_INITIALIZED,
    CryptokiAlreadyInitialized => CKR_CRYPTOKI_ALREADY_INITIALIZED,
    MutexBad => CKR_MUTEX_BAD,
    MutexNotLocked => CKR_MUTEX_NOT_LOCKED,
    NewPinMode => CKR_NEW_PIN_MODE,
    NextOtp => CKR_NEXT_OTP,
    ExceededMaxIterations => CKR_EXCEEDED_MAX_ITERATIONS,
    FipsSelfTestFailed => CKR_FIPS_SELF_TEST_FAILED,
    LibraryLoadFailed => CKR_LIBRARY_LOAD_FAILED,
    PinTooWeak => CKR_PIN_TOO_WEAK,
    PublicKeyInvalid => CKR_PUBLIC_KEY_INVALID,
    FunctionRejected => CKR_FUNCTION_REJECTED,
    AeadDecryptFailed => CKR_AEAD_DECRYPT_FAILED,
    TokenResourceExceeded => CKR_TOKEN_RESOURCE_EXCEEDED,
    OperationCancelFailed => CKR_OPERATION_CANCEL_FAILED,
    KeyExhausted => CKR_KEY_EXHAUSTED,
    Pending => CKR_PENDING,
    SessionAsyncNotSupported => CKR_SESSION_ASYNC_NOT_SUPPORTED,
    SeedRandomRequired => CKR_SEED_RANDOM_REQUIRED,
    OperationNotValidated => CKR_OPERATION_NOT_VALIDATED,
    TokenNotInitialized => CKR_TOKEN_NOT_INITIALIZED,
    ParameterSetNotSupported => CKR_PARAMETER_SET_NOT_SUPPORTED,
}

impl From<Rv> for CK_RV {
    fn from(rv: Rv) -> Self {
        match rv {
            Rv::Ok => CKR_OK,
            Rv::Error(rv_error) => rv_error.into(),
        }
    }
}

impl Rv {
    /// Convert the return value into a standard Result type
    pub fn into_result(self, function: Function) -> Result<()> {
        match self {
            Rv::Ok => Ok(()),
            Rv::Error(rv_error) => Err(Error::Pkcs11(rv_error, function)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::{Rv, RvError};
    use cryptoki_sys::*;

    #[test]
    fn vendor_defined_exact() {
        let code = CKR_VENDOR_DEFINED;
        let actual = Rv::from(code);
        let expected = Rv::Error(RvError::VendorDefined(code));
        assert_eq!(actual, expected);
    }

    #[test]
    fn vendor_defined_higher() {
        let code = CKR_VENDOR_DEFINED + 42;
        let actual = Rv::from(code);
        let expected = Rv::Error(RvError::VendorDefined(code));
        assert_eq!(actual, expected);
    }

    #[test]
    fn unknown_code() {
        let code = CKR_VENDOR_DEFINED - 42;
        let actual = Rv::from(code);
        let expected = Rv::Error(RvError::UnknownErrorCode(code));
        assert_eq!(actual, expected);
    }

    #[test]
    fn round_trip() {
        for code in (0..0x1000).chain([CKR_VENDOR_DEFINED, CKR_VENDOR_DEFINED + 42]) {
            let rv = Rv::from(code);
            assert_eq!(CK_RV::from(rv), code);
            if let Rv::Error(rv_error) = rv {
                let named = !matches!(
                    rv_error,
                    RvError::VendorDefined(_) | RvError::UnknownErrorCode(_)
                );
                assert_eq!(rv_error.name().is_some(), named, "{code:#x}");
            }
        }
        assert_eq!(RvError::GeneralError.name(), Some("CKR_GENERAL_ERROR"));
        assert_eq!(CK_RV::from(RvError::GeneralError), CKR_GENERAL_ERROR);
    }
}
