//! Rust PKCS11 new abstraction
//!
//! The items in the new module only expose idiomatic and safe Rust types and functions to
//! interface with the PKCS11 API. All the PKCS11 items might not be implemented but everything
//! that is implemented is safe.
//!
//! The modules under `new` follow the structure of the PKCS11 document version 2.40 available [here](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html).

pub mod functions;
pub mod objects;
pub mod types;

use crate::types::function::{Rv, RvError};
use crate::types::session::{Session, UserType};
use crate::types::slot_token::Slot;
use cryptoki_sys::*;
use log::error;
use secrecy::{ExposeSecret, Secret, SecretVec};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::ffi::CString;
use std::fmt;
use std::mem;
use std::path::Path;
use std::sync::{Mutex, RwLock};

#[macro_export]
macro_rules! get_pkcs11 {
    ($pkcs11:expr, $func_name:ident) => {
        ($pkcs11
            .function_list
            .$func_name
            .ok_or(crate::Error::NullFunctionPointer)?)
    };
}

/// Main PKCS11 context. Should usually be unique per application.
pub struct Pkcs11 {
    // Even if this field is never read, it is needed for the pointers in function_list to remain
    // valid.
    _pkcs11_lib: cryptoki_sys::Pkcs11,
    function_list: cryptoki_sys::_CK_FUNCTION_LIST,
    // Handle of sessions currently logged in per slot. This is used for logging in and out.
    logged_sessions: Mutex<HashMap<Slot, HashSet<CK_SESSION_HANDLE>>>,
    // Pin per slot, will be used for login. Ideally this should also be filtered by user type.
    pins: RwLock<HashMap<Slot, SecretVec<u8>>>,
}

impl Pkcs11 {
    /// Instantiate a new context from the path of a PKCS11 dynamic llibrary implementation.
    pub fn new<P>(filename: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        unsafe {
            let pkcs11_lib =
                cryptoki_sys::Pkcs11::new(filename.as_ref()).map_err(Error::LibraryLoading)?;
            let mut list = mem::MaybeUninit::uninit();

            Rv::from(pkcs11_lib.C_GetFunctionList(list.as_mut_ptr())).into_result()?;

            let list_ptr = *list.as_ptr();

            Ok(Pkcs11 {
                _pkcs11_lib: pkcs11_lib,
                function_list: *list_ptr,
                logged_sessions: Mutex::new(HashMap::new()),
                pins: RwLock::new(HashMap::new()),
            })
        }
    }

    /// Set the PIN used when logging in sessions.
    /// The pin set is the one that is going to be use with all user type specified when logging in.
    /// It needs to be changed before calling login with a different user type.
    pub fn set_pin(&self, slot: Slot, pin: &str) -> Result<()> {
        let _ = self
            .pins
            .write()
            .expect("Pins lock poisoned")
            .insert(slot, Secret::new(CString::new(pin)?.into_bytes()));
        Ok(())
    }

    /// Clear the pin store.
    /// Ignore if the pin was not set previously on the slot. Note that the pin will be cleared
    /// anyway on drop.
    pub fn clear_pin(&self, slot: Slot) {
        // The removed pin will be zeroized on drop as it is a SecretVec
        let _ = self.pins.write().expect("Pins lock poisoned").remove(&slot);
    }

    // Do not fail if the user is already logged in. It happens if another session on the same slot
    // has already called the log in operation. Record the login call and only log out when there
    // aren't anymore sessions requiring log in state.
    fn login(&self, session: &Session, user_type: UserType) -> Result<()> {
        let pins = self.pins.read().expect("Pins lock poisoned");
        let pin = pins
            .get(&session.slot())
            .ok_or(Error::PinNotSet)?
            .expose_secret();

        let mut logged_sessions = self
            .logged_sessions
            .lock()
            .expect("Logged sessions mutex poisoned!");

        match unsafe {
            Rv::from(get_pkcs11!(self, C_Login)(
                session.handle(),
                user_type.into(),
                pin.as_ptr() as *mut u8,
                pin.len().try_into()?,
            ))
        } {
            Rv::Ok | Rv::Error(RvError::UserAlreadyLoggedIn) => {
                if let Some(session_handles) = logged_sessions.get_mut(&session.slot()) {
                    // It might already been present in if this session already tried to log in.
                    let _ = session_handles.insert(session.handle());
                } else {
                    let mut new_set = HashSet::new();
                    let _ = new_set.insert(session.handle());
                    let _ = logged_sessions.insert(session.slot(), new_set);
                }
                Ok(())
            }
            Rv::Error(err) => Err(err.into()),
        }
    }

    fn logout(&self, session: &Session) -> Result<()> {
        let mut logged_sessions = self
            .logged_sessions
            .lock()
            .expect("Logged sessions mutex poisoned!");

        // A non-logged in session might call this method.

        if let Some(session_handles) = logged_sessions.get_mut(&session.slot()) {
            if session_handles.contains(&session.handle()) {
                if session_handles.len() == 1 {
                    // Only this session is logged in, we can logout.
                    unsafe {
                        Rv::from(get_pkcs11!(self, C_Logout)(session.handle())).into_result()?;
                    }
                }
                let _ = session_handles.remove(&session.handle());
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
/// Main error type
pub enum Error {
    /// Any error that happens during library loading of the PKCS#11 module is encompassed under
    /// this error. It is a direct forward of the underlying error from libloading.
    LibraryLoading(libloading::Error),

    /// All PKCS#11 functions that return non-zero translate to this error.
    Pkcs11(types::function::RvError),

    /// This error marks a feature that is not yet supported by the PKCS11 Rust abstraction layer.
    NotSupported,

    /// Error happening while converting types
    TryFromInt(std::num::TryFromIntError),

    /// Error when converting a slice to an array
    TryFromSlice(std::array::TryFromSliceError),

    /// Error with nul characters in Strings
    NulError(std::ffi::NulError),

    /// Calling a PKCS11 function that is a NULL function pointer.
    NullFunctionPointer,

    /// The value is not one of those expected.
    InvalidValue,

    /// The PIN was not set before logging in.
    PinNotSet,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::LibraryLoading(e) => write!(f, "libloading error ({})", e),
            Error::Pkcs11(e) => write!(f, "PKCS11 error: {}", e),
            Error::NotSupported => write!(f, "Feature not supported"),
            Error::TryFromInt(e) => write!(f, "Conversion between integers failed ({})", e),
            Error::TryFromSlice(e) => write!(f, "Error converting slice to array ({})", e),
            Error::NulError(e) => write!(f, "An interior nul byte was found ({})", e),
            Error::NullFunctionPointer => write!(f, "Calling a NULL function pointer"),
            Error::InvalidValue => write!(f, "The value is not one of the expected options"),
            Error::PinNotSet => write!(f, "Pin has not been set before trying to log in"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::LibraryLoading(e) => Some(e),
            Error::TryFromInt(e) => Some(e),
            Error::TryFromSlice(e) => Some(e),
            Error::NulError(e) => Some(e),
            Error::Pkcs11(_)
            | Error::NotSupported
            | Error::NullFunctionPointer
            | Error::PinNotSet
            | Error::InvalidValue => None,
        }
    }
}

impl From<libloading::Error> for Error {
    fn from(err: libloading::Error) -> Error {
        Error::LibraryLoading(err)
    }
}

impl From<std::num::TryFromIntError> for Error {
    fn from(err: std::num::TryFromIntError) -> Error {
        Error::TryFromInt(err)
    }
}

impl From<std::array::TryFromSliceError> for Error {
    fn from(err: std::array::TryFromSliceError) -> Error {
        Error::TryFromSlice(err)
    }
}

impl From<std::ffi::NulError> for Error {
    fn from(err: std::ffi::NulError) -> Error {
        Error::NulError(err)
    }
}

impl From<std::convert::Infallible> for Error {
    fn from(_err: std::convert::Infallible) -> Error {
        unreachable!()
    }
}

impl Drop for Pkcs11 {
    fn drop(&mut self) {
        if let Err(e) = self.finalize_private() {
            error!("Failed to finalize: {}", e);
        }
    }
}

/// Main Result type
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use crate::types::locking::CInitializeArgs;
    use crate::types::mechanism::Mechanism;
    use crate::types::object::{Attribute, AttributeInfo, AttributeType, KeyType, ObjectClass};
    use crate::types::session::UserType;
    use crate::types::Flags;
    use crate::Pkcs11;
    use crate::Slot;
    use std::env;
    use std::sync::Arc;
    use std::thread;
    use serial_test::serial;

    fn init_pins() -> (Pkcs11, Slot) {
        let pkcs11 = Pkcs11::new(
            env::var("PKCS11_SOFTHSM2_MODULE")
                .unwrap_or_else(|_| "/usr/local/lib/softhsm/libsofthsm2.so".to_string()),
        )
        .unwrap();

        // initialize the library
        pkcs11.initialize(CInitializeArgs::OsThreads).unwrap();

        // find a slot, get the first one
        let slot = pkcs11.get_slots_with_token().unwrap().remove(0);

        pkcs11.init_token(slot, "1234").unwrap();
        pkcs11.set_pin(slot, "1234").unwrap();

        // set flags
        let mut flags = Flags::new();
        flags.set_rw_session(true).set_serial_session(true);

        {
            // open a session
            let session = pkcs11.open_session_no_callback(slot, flags).unwrap();
            // log in the session
            session.login(UserType::So).unwrap();
            session.init_pin("1234").unwrap();
        }

        (pkcs11, slot)
    }

    #[test]
    #[serial]
    fn sign_verify() {
        let (pkcs11, slot) = init_pins();

        // set flags
        let mut flags = Flags::new();
        flags.set_rw_session(true).set_serial_session(true);

        // open a session
        let session = pkcs11.open_session_no_callback(slot, flags).unwrap();

        // log in the session
        session.login(UserType::User).unwrap();

        // get mechanism
        let mechanism = Mechanism::RsaPkcsKeyPairGen;

        let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01];
        let modulus_bits: u64 = 1024;

        // pub key template
        let pub_key_template = vec![
            Attribute::Token(true.into()),
            Attribute::Private(false.into()),
            Attribute::PublicExponent(public_exponent),
            Attribute::ModulusBits(modulus_bits.into()),
        ];

        // priv key template
        let priv_key_template = vec![Attribute::Token(true.into())];

        // generate a key pair
        let (public, private) = session
            .generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)
            .unwrap();

        // data to sign
        let data = [0xFF, 0x55, 0xDD];

        // sign something with it
        let signature = session.sign(&Mechanism::RsaPkcs, private, &data).unwrap();

        // verify the signature
        session
            .verify(&Mechanism::RsaPkcs, public, &data, &signature)
            .unwrap();

        // delete keys
        session.destroy_object(public).unwrap();
        session.destroy_object(private).unwrap();
    }

    #[test]
    #[serial]
    fn encrypt_decrypt() {
        let (pkcs11, slot) = init_pins();

        // set flags
        let mut flags = Flags::new();
        flags.set_rw_session(true).set_serial_session(true);

        // open a session
        let session = pkcs11.open_session_no_callback(slot, flags).unwrap();

        // log in the session
        session.login(UserType::User).unwrap();

        // get mechanism
        let mechanism = Mechanism::RsaPkcsKeyPairGen;

        let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01];
        let modulus_bits: u64 = 1024;

        // pub key template
        let pub_key_template = vec![
            Attribute::Token(true.into()),
            Attribute::Private(false.into()),
            Attribute::PublicExponent(public_exponent),
            Attribute::ModulusBits(modulus_bits.into()),
            Attribute::Encrypt(true.into()),
        ];

        // priv key template
        let priv_key_template = vec![
            Attribute::Token(true.into()),
            Attribute::Decrypt(true.into()),
        ];

        // generate a key pair
        let (public, private) = session
            .generate_key_pair(&mechanism, &pub_key_template, &priv_key_template)
            .unwrap();

        // data to encrypt
        let data = vec![0xFF, 0x55, 0xDD];

        // encrypt something with it
        let encrypted_data = session.encrypt(&Mechanism::RsaPkcs, public, &data).unwrap();

        // decrypt
        let decrypted_data = session
            .decrypt(&Mechanism::RsaPkcs, private, &encrypted_data)
            .unwrap();

        // The decrypted buffer is bigger than the original one.
        assert_eq!(data, decrypted_data);

        // delete keys
        session.destroy_object(public).unwrap();
        session.destroy_object(private).unwrap();
    }

    #[test]
    #[serial]
    fn import_export() {
        let (pkcs11, slot) = init_pins();

        // set flags
        let mut flags = Flags::new();
        flags.set_rw_session(true).set_serial_session(true);

        // open a session
        let session = pkcs11.open_session_no_callback(slot, flags).unwrap();

        // log in the session
        session.login(UserType::User).unwrap();

        let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01];
        let modulus = vec![0xFF; 1024];

        let template = vec![
            Attribute::Token(true.into()),
            Attribute::Private(false.into()),
            Attribute::PublicExponent(public_exponent),
            Attribute::Modulus(modulus.clone()),
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::KeyType(KeyType::RSA),
            Attribute::Verify(true.into()),
        ];

        {
            // Intentionally forget the object handle to find it later
            let _public_key = session.create_object(&template).unwrap();
        }

        let is_it_the_public_key = session.find_objects(&template).unwrap().remove(0);

        let attribute_info = session
            .get_attribute_info(is_it_the_public_key, &[AttributeType::Modulus])
            .unwrap()
            .remove(0);

        if let AttributeInfo::Available(size) = attribute_info {
            assert_eq!(size, 1024);
        } else {
            panic!("The Modulus attribute was expected to be present.")
        };

        let attr = session
            .get_attributes(is_it_the_public_key, &[AttributeType::Modulus])
            .unwrap()
            .remove(0);

        if let Attribute::Modulus(modulus_cmp) = attr {
            assert_eq!(modulus[..], modulus_cmp[..]);
        } else {
            panic!("Expected the Modulus attribute.");
        }

        // delete key
        session.destroy_object(is_it_the_public_key).unwrap();
    }

    #[test]
    #[serial]
    fn login_feast() {
        const SESSIONS: usize = 100;

        let (pkcs11, slot) = init_pins();

        // set flags
        let mut flags = Flags::new();
        flags.set_rw_session(true).set_serial_session(true);

        let pkcs11 = Arc::from(pkcs11);
        let mut threads = Vec::new();

        for _ in 0..SESSIONS {
            let pkcs11 = pkcs11.clone();
            threads.push(thread::spawn(move || {
                let session = pkcs11.open_session_no_callback(slot, flags).unwrap();
                session.login(UserType::User).unwrap();
                session.login(UserType::User).unwrap();
                session.login(UserType::User).unwrap();
                session.logout().unwrap();
                session.logout().unwrap();
                session.logout().unwrap();
            }));
        }

        for thread in threads {
            thread.join().unwrap();
        }
    }
}
