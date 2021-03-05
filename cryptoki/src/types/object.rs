//! Object types

use crate::types::mechanism::MechanismType;
use crate::types::{Bbool, Ulong};
use crate::{Error, Result};
use cryptoki_sys::*;
use log::error;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::ffi::c_void;
use std::ops::Deref;

#[derive(Debug, Copy, Clone)]
/// Type of an attribute
pub enum AttributeType {
    /// List of mechanisms allowed to be used with the key
    AllowedMechanisms,
    /// Base number value of a key
    Base,
    /// Type of an object
    Class,
    /// Determines if an object can be copied
    Copyable,
    /// Determines if a key supports decryption
    Decrypt,
    /// Determines if it is possible to derive other keys from the key
    Derive,
    /// Determines if a key supports encryption
    Encrypt,
    /// Determines if a key is extractable and can be wrapped
    Extractable,
    /// Key identifier for key
    Id,
    /// Type of a key
    KeyType,
    /// Description of the object
    Label,
    /// Determines if the object can be modified
    Modifiable,
    /// Modulus value of a key
    Modulus,
    /// Length in bits of the modulus of a key
    ModulusBits,
    /// Prime number value of a key
    Prime,
    /// Determines if the object is private
    Private,
    /// Public exponent value of a key
    PublicExponent,
    /// Determines if the key is sensitive
    Sensitive,
    /// Determines if a key supports signing
    Sign,
    /// Determines if a key supports signing where the data can be recovered from the signature
    SignRecover,
    /// Determines if the object is a token object
    Token,
    /// Determines if a key supports unwrapping
    Unwrap,
    /// Value of the object
    Value,
    /// Length in bytes of the value
    ValueLen,
    /// Determines if a key supports verifying
    Verify,
    /// Determines if a key supports verifying where the data can be recovered from the signature
    VerifyRecover,
    /// Determines if a key supports wrapping
    Wrap,
}

impl From<AttributeType> for CK_ATTRIBUTE_TYPE {
    fn from(attribute_type: AttributeType) -> Self {
        match attribute_type {
            AttributeType::AllowedMechanisms => CKA_ALLOWED_MECHANISMS,
            AttributeType::Base => CKA_BASE,
            AttributeType::Class => CKA_CLASS,
            AttributeType::Copyable => CKA_COPYABLE,
            AttributeType::Decrypt => CKA_DECRYPT,
            AttributeType::Derive => CKA_DERIVE,
            AttributeType::Encrypt => CKA_ENCRYPT,
            AttributeType::Extractable => CKA_EXTRACTABLE,
            AttributeType::Id => CKA_ID,
            AttributeType::KeyType => CKA_KEY_TYPE,
            AttributeType::Label => CKA_LABEL,
            AttributeType::Modifiable => CKA_MODIFIABLE,
            AttributeType::Modulus => CKA_MODULUS,
            AttributeType::ModulusBits => CKA_MODULUS_BITS,
            AttributeType::Prime => CKA_PRIME,
            AttributeType::Private => CKA_PRIVATE,
            AttributeType::PublicExponent => CKA_PUBLIC_EXPONENT,
            AttributeType::Sensitive => CKA_SENSITIVE,
            AttributeType::Sign => CKA_SIGN,
            AttributeType::SignRecover => CKA_SIGN_RECOVER,
            AttributeType::Token => CKA_TOKEN,
            AttributeType::Unwrap => CKA_UNWRAP,
            AttributeType::Value => CKA_VALUE,
            AttributeType::ValueLen => CKA_VALUE_LEN,
            AttributeType::Verify => CKA_VERIFY,
            AttributeType::VerifyRecover => CKA_VERIFY_RECOVER,
            AttributeType::Wrap => CKA_WRAP,
        }
    }
}

impl TryFrom<CK_ATTRIBUTE_TYPE> for AttributeType {
    type Error = Error;

    fn try_from(attribute_type: CK_ATTRIBUTE_TYPE) -> Result<Self> {
        match attribute_type {
            CKA_ALLOWED_MECHANISMS => Ok(AttributeType::AllowedMechanisms),
            CKA_BASE => Ok(AttributeType::Base),
            CKA_CLASS => Ok(AttributeType::Class),
            CKA_COPYABLE => Ok(AttributeType::Copyable),
            CKA_DECRYPT => Ok(AttributeType::Decrypt),
            CKA_DERIVE => Ok(AttributeType::Derive),
            CKA_ENCRYPT => Ok(AttributeType::Encrypt),
            CKA_EXTRACTABLE => Ok(AttributeType::Extractable),
            CKA_ID => Ok(AttributeType::Id),
            CKA_KEY_TYPE => Ok(AttributeType::KeyType),
            CKA_LABEL => Ok(AttributeType::Label),
            CKA_MODIFIABLE => Ok(AttributeType::Modifiable),
            CKA_MODULUS => Ok(AttributeType::Modulus),
            CKA_MODULUS_BITS => Ok(AttributeType::ModulusBits),
            CKA_PRIME => Ok(AttributeType::Prime),
            CKA_PRIVATE => Ok(AttributeType::Private),
            CKA_PUBLIC_EXPONENT => Ok(AttributeType::PublicExponent),
            CKA_SENSITIVE => Ok(AttributeType::Sensitive),
            CKA_SIGN => Ok(AttributeType::Sign),
            CKA_SIGN_RECOVER => Ok(AttributeType::SignRecover),
            CKA_TOKEN => Ok(AttributeType::Token),
            CKA_UNWRAP => Ok(AttributeType::Unwrap),
            CKA_VALUE => Ok(AttributeType::Value),
            CKA_VALUE_LEN => Ok(AttributeType::ValueLen),
            CKA_VERIFY => Ok(AttributeType::Verify),
            CKA_VERIFY_RECOVER => Ok(AttributeType::VerifyRecover),
            CKA_WRAP => Ok(AttributeType::Wrap),
            attr_type => {
                error!("Attribute type {} not supported.", attr_type);
                Err(Error::NotSupported)
            }
        }
    }
}

#[derive(Debug, Clone)]
/// Attribute value
pub enum Attribute {
    /// List of mechanisms allowed to be used with the key
    AllowedMechanisms(Vec<MechanismType>),
    /// Base number value of a key
    Base(Vec<u8>),
    /// Type of an object
    Class(ObjectClass),
    /// Determines if an object can be copied
    Copyable(Bbool),
    /// Determines if a key supports decryption
    Decrypt(Bbool),
    /// Determines if it is possible to derive other keys from the key
    Derive(Bbool),
    /// Determines if a key supports encryption
    Encrypt(Bbool),
    /// Determines if a key is extractable and can be wrapped
    Extractable(Bbool),
    /// Key identifier for key
    Id(Vec<u8>),
    /// Type of a key
    KeyType(KeyType),
    /// Description of the object
    Label(Vec<u8>),
    /// Determines if the object can be modified
    Modifiable(Bbool),
    /// Modulus value of a key
    Modulus(Vec<u8>),
    /// Length in bits of the modulus of a key
    ModulusBits(Ulong),
    /// Prime number value of a key
    Prime(Vec<u8>),
    /// Determines if the object is private
    Private(Bbool),
    /// Public exponent value of a key
    PublicExponent(Vec<u8>),
    /// Determines if the key is sensitive
    Sensitive(Bbool),
    /// Determines if a key supports signing
    Sign(Bbool),
    /// Determines if a key supports signing where the data can be recovered from the signature
    SignRecover(Bbool),
    /// Determines if the object is a token object
    Token(Bbool),
    /// Determines if a key supports unwrapping
    Unwrap(Bbool),
    /// Value of the object
    Value(Vec<u8>),
    /// Length in bytes of the value
    ValueLen(Ulong),
    /// Determines if a key supports verifying
    Verify(Bbool),
    /// Determines if a key supports verifying where the data can be recovered from the signature
    VerifyRecover(Bbool),
    /// Determines if a key supports wrapping
    Wrap(Bbool),
}

impl Attribute {
    /// Get the type of an attribute
    pub fn attribute_type(&self) -> AttributeType {
        match self {
            Attribute::AllowedMechanisms(_) => AttributeType::AllowedMechanisms,
            Attribute::Base(_) => AttributeType::Base,
            Attribute::Class(_) => AttributeType::Class,
            Attribute::Copyable(_) => AttributeType::Copyable,
            Attribute::Decrypt(_) => AttributeType::Decrypt,
            Attribute::Derive(_) => AttributeType::Derive,
            Attribute::Encrypt(_) => AttributeType::Encrypt,
            Attribute::Extractable(_) => AttributeType::Extractable,
            Attribute::Id(_) => AttributeType::Id,
            Attribute::KeyType(_) => AttributeType::KeyType,
            Attribute::Label(_) => AttributeType::Label,
            Attribute::Modifiable(_) => AttributeType::Modifiable,
            Attribute::Modulus(_) => AttributeType::Modulus,
            Attribute::ModulusBits(_) => AttributeType::ModulusBits,
            Attribute::Prime(_) => AttributeType::Prime,
            Attribute::Private(_) => AttributeType::Private,
            Attribute::PublicExponent(_) => AttributeType::PublicExponent,
            Attribute::Sensitive(_) => AttributeType::Sensitive,
            Attribute::Sign(_) => AttributeType::Sign,
            Attribute::SignRecover(_) => AttributeType::SignRecover,
            Attribute::Token(_) => AttributeType::Token,
            Attribute::Unwrap(_) => AttributeType::Unwrap,
            Attribute::Value(_) => AttributeType::Value,
            Attribute::ValueLen(_) => AttributeType::ValueLen,
            Attribute::Verify(_) => AttributeType::Verify,
            Attribute::VerifyRecover(_) => AttributeType::VerifyRecover,
            Attribute::Wrap(_) => AttributeType::Wrap,
        }
    }

    /// Returns the length in bytes of the objects contained by this CkAttribute.
    fn len(&self) -> usize {
        match self {
            Attribute::Copyable(_)
            | Attribute::Decrypt(_)
            | Attribute::Derive(_)
            | Attribute::Encrypt(_)
            | Attribute::Extractable(_)
            | Attribute::Modifiable(_)
            | Attribute::Private(_)
            | Attribute::Sensitive(_)
            | Attribute::Sign(_)
            | Attribute::SignRecover(_)
            | Attribute::Token(_)
            | Attribute::Unwrap(_)
            | Attribute::Verify(_)
            | Attribute::VerifyRecover(_)
            | Attribute::Wrap(_) => 1,
            Attribute::Base(_) => 1,
            Attribute::Class(_) => std::mem::size_of::<CK_OBJECT_CLASS>(),
            Attribute::KeyType(_) => std::mem::size_of::<CK_KEY_TYPE>(),
            Attribute::Label(label) => std::mem::size_of::<CK_UTF8CHAR>() * label.len(),
            Attribute::ModulusBits(_) => std::mem::size_of::<CK_ULONG>(),
            Attribute::Prime(bytes) => bytes.len(),
            Attribute::PublicExponent(bytes) => bytes.len(),
            Attribute::Modulus(bytes) => bytes.len(),
            Attribute::Value(bytes) => std::mem::size_of::<u8>() * bytes.len(),
            Attribute::ValueLen(_) => std::mem::size_of::<CK_ULONG>(),
            Attribute::Id(bytes) => bytes.len(),
            Attribute::AllowedMechanisms(mechanisms) => {
                std::mem::size_of::<CK_MECHANISM_TYPE>() * mechanisms.len()
            }
        }
    }

    /// Returns a CK_VOID_PTR pointing to the object contained by this CkAttribute.
    ///
    /// Casting from an immutable reference to a mutable pointer is kind of unsafe but the
    /// Attribute structure will only be used with PKCS11 functions that do not modify the template
    /// given.
    /// The C_GetAttributeValue function, which is the only one that modifies the template given,
    /// will not use Attribute parameters but return them
    /// directly to the caller.
    fn ptr(&self) -> *mut c_void {
        match self {
            // CK_BBOOL
            Attribute::Copyable(b)
            | Attribute::Decrypt(b)
            | Attribute::Derive(b)
            | Attribute::Encrypt(b)
            | Attribute::Extractable(b)
            | Attribute::Modifiable(b)
            | Attribute::Private(b)
            | Attribute::Sensitive(b)
            | Attribute::Sign(b)
            | Attribute::SignRecover(b)
            | Attribute::Token(b)
            | Attribute::Unwrap(b)
            | Attribute::Verify(b)
            | Attribute::VerifyRecover(b)
            | Attribute::Wrap(b) => b as *const _ as *mut c_void,
            // CK_ULONG
            Attribute::ModulusBits(val) | Attribute::ValueLen(val) => {
                val as *const _ as *mut c_void
            }
            // Vec<u8>
            Attribute::Base(bytes)
            | Attribute::Label(bytes)
            | Attribute::Prime(bytes)
            | Attribute::PublicExponent(bytes)
            | Attribute::Modulus(bytes)
            | Attribute::Value(bytes)
            | Attribute::Id(bytes) => bytes.as_ptr() as *mut c_void,
            // Unique types
            Attribute::Class(object_class) => object_class as *const _ as *mut c_void,
            Attribute::KeyType(key_type) => key_type as *const _ as *mut c_void,
            Attribute::AllowedMechanisms(mechanisms) => mechanisms.as_ptr() as *mut c_void,
        }
    }
}

impl From<&Attribute> for CK_ATTRIBUTE {
    fn from(attribute: &Attribute) -> Self {
        Self {
            type_: attribute.attribute_type().into(),
            pValue: attribute.ptr(),
            // The panic should only happen if there is a bug.
            ulValueLen: attribute
                .len()
                .try_into()
                .expect("Can not convert the attribute length value (usize) to a CK_ULONG."),
        }
    }
}

impl TryFrom<CK_ATTRIBUTE> for Attribute {
    type Error = Error;

    fn try_from(attribute: CK_ATTRIBUTE) -> Result<Self> {
        let attr_type = AttributeType::try_from(attribute.type_)?;
        // Cast from c_void to u8
        let val = unsafe {
            std::slice::from_raw_parts(
                attribute.pValue as *const u8,
                attribute.ulValueLen.try_into()?,
            )
        };
        match attr_type {
            // CK_BBOOL
            AttributeType::Copyable => Ok(Attribute::Copyable(val.try_into()?)),
            AttributeType::Decrypt => Ok(Attribute::Decrypt(val.try_into()?)),
            AttributeType::Derive => Ok(Attribute::Derive(val.try_into()?)),
            AttributeType::Encrypt => Ok(Attribute::Encrypt(val.try_into()?)),
            AttributeType::Extractable => Ok(Attribute::Extractable(val.try_into()?)),
            AttributeType::Modifiable => Ok(Attribute::Modifiable(val.try_into()?)),
            AttributeType::Private => Ok(Attribute::Private(val.try_into()?)),
            AttributeType::Sensitive => Ok(Attribute::Sensitive(val.try_into()?)),
            AttributeType::Sign => Ok(Attribute::Sign(val.try_into()?)),
            AttributeType::SignRecover => Ok(Attribute::SignRecover(val.try_into()?)),
            AttributeType::Token => Ok(Attribute::Token(val.try_into()?)),
            AttributeType::Unwrap => Ok(Attribute::Unwrap(val.try_into()?)),
            AttributeType::Verify => Ok(Attribute::Verify(val.try_into()?)),
            AttributeType::VerifyRecover => Ok(Attribute::VerifyRecover(val.try_into()?)),
            AttributeType::Wrap => Ok(Attribute::Wrap(val.try_into()?)),
            // CK_ULONG
            AttributeType::ModulusBits => Ok(Attribute::ModulusBits(
                CK_ULONG::from_ne_bytes(val.try_into()?).try_into()?,
            )),
            AttributeType::ValueLen => Ok(Attribute::ValueLen(
                CK_ULONG::from_ne_bytes(val.try_into()?).try_into()?,
            )),
            // Vec<u8>
            AttributeType::Base => Ok(Attribute::Base(val.to_vec())),
            AttributeType::Label => Ok(Attribute::Label(val.to_vec())),
            AttributeType::Prime => Ok(Attribute::Prime(val.to_vec())),
            AttributeType::PublicExponent => Ok(Attribute::PublicExponent(val.to_vec())),
            AttributeType::Modulus => Ok(Attribute::Modulus(val.to_vec())),
            AttributeType::Value => Ok(Attribute::Value(val.to_vec())),
            AttributeType::Id => Ok(Attribute::Id(val.to_vec())),
            // Unique types
            AttributeType::Class => Ok(Attribute::Class(
                CK_OBJECT_CLASS::from_ne_bytes(val.try_into()?).try_into()?,
            )),
            AttributeType::KeyType => Ok(Attribute::KeyType(
                CK_KEY_TYPE::from_ne_bytes(val.try_into()?).try_into()?,
            )),
            AttributeType::AllowedMechanisms => {
                let val = unsafe {
                    std::slice::from_raw_parts(
                        attribute.pValue as *const CK_MECHANISM_TYPE,
                        attribute.ulValueLen.try_into()?,
                    )
                };
                let types: Vec<MechanismType> = val
                    .to_vec()
                    .into_iter()
                    .map(|t| t.try_into())
                    .collect::<Result<Vec<MechanismType>>>()?;
                Ok(Attribute::AllowedMechanisms(types))
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
/// Token specific identifier for an object
pub struct ObjectHandle {
    handle: CK_OBJECT_HANDLE,
}

impl ObjectHandle {
    pub(crate) fn new(handle: CK_OBJECT_HANDLE) -> Self {
        ObjectHandle { handle }
    }

    pub(crate) fn handle(&self) -> CK_OBJECT_HANDLE {
        self.handle
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(transparent)]
/// Identifier of the class of an object
pub struct ObjectClass {
    val: CK_OBJECT_CLASS,
}

impl ObjectClass {
    /// Data objects
    pub const DATA: ObjectClass = ObjectClass {
        val: CKO_DATA,
    };
    /// Certificate objects
    pub const CERTIFICATE: ObjectClass = ObjectClass {
        val: CKO_CERTIFICATE,
    };
    /// Public key object
    pub const PUBLIC_KEY: ObjectClass = ObjectClass {
        val: CKO_PUBLIC_KEY,
    };
    /// Private key object
    pub const PRIVATE_KEY: ObjectClass = ObjectClass {
        val: CKO_PRIVATE_KEY,
    };
    /// Secret key object
    pub const SECRET_KEY: ObjectClass = ObjectClass {
        val: CKO_SECRET_KEY,
    };
}

impl Deref for ObjectClass {
    type Target = CK_OBJECT_CLASS;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

impl From<ObjectClass> for CK_OBJECT_CLASS {
    fn from(object_class: ObjectClass) -> Self {
        *object_class
    }
}

impl TryFrom<CK_OBJECT_CLASS> for ObjectClass {
    type Error = Error;

    fn try_from(object_class: CK_OBJECT_CLASS) -> Result<Self> {
        match object_class {
            CKO_PUBLIC_KEY => Ok(ObjectClass::PUBLIC_KEY),
            other => {
                error!("Object class {} is not supported.", other);
                Err(Error::NotSupported)
            }
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
/// Key type
pub struct KeyType {
    val: CK_KEY_TYPE,
}

impl KeyType {
    /// RSA key
    pub const RSA: KeyType = KeyType { val: CKK_RSA };
}

impl Deref for KeyType {
    type Target = CK_KEY_TYPE;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

impl From<KeyType> for CK_KEY_TYPE {
    fn from(key_type: KeyType) -> Self {
        *key_type
    }
}

impl TryFrom<CK_KEY_TYPE> for KeyType {
    type Error = Error;

    fn try_from(key_type: CK_KEY_TYPE) -> Result<Self> {
        match key_type {
            CKK_RSA => Ok(KeyType::RSA),
            other => {
                error!("Key type {} is not supported.", other);
                Err(Error::NotSupported)
            }
        }
    }
}

#[derive(Debug, Copy, Clone)]
/// Information about the attribute of an object
pub enum AttributeInfo {
    /// The attribute is not defined for the object
    Unavailable,
    /// The attribute is available to get from the object and has the specified size in bytes.
    Available(usize),
}
