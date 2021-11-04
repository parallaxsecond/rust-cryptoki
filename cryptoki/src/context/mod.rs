// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Pkcs11 context and initialization types

/// Directly get the PKCS #11 operation from the context structure and check for null pointers.
macro_rules! get_pkcs11 {
    ($pkcs11:expr, $func_name:ident) => {
        ($pkcs11
            .impl_
            .function_list
            .$func_name
            .ok_or(crate::error::Error::NullFunctionPointer)?)
    };
}

mod flags;
mod general_purpose;
mod info;
mod locking;
mod session_management;
mod slot_token_management;

pub use flags::*;
pub use info::*;
pub use locking::*;

use crate::error::{Error, Result, Rv};
use crate::mechanism::{MechanismInfo, MechanismType};
use crate::session::{Session, SessionFlags};
use crate::slot::{Slot, SlotInfo, TokenInfo};

use derivative::Derivative;
use log::error;
use std::mem;
use std::path::Path;
use std::sync::Arc;

#[derive(Derivative)]
#[derivative(Debug)]
// Implementation of Pkcs11 class that can be enclosed in a single Arc
pub(crate) struct Pkcs11Impl {
    // Even if this field is never read, it is needed for the pointers in function_list to remain
    // valid.
    #[derivative(Debug = "ignore")]
    _pkcs11_lib: Arc<cryptoki_sys::Pkcs11>,
    pub(crate) function_list: Arc<cryptoki_sys::_CK_FUNCTION_LIST>,
}

/// Main PKCS11 context. Should usually be unique per application.
#[derive(Clone, Debug)]
pub struct Pkcs11 {
    pub(crate) impl_: Arc<Pkcs11Impl>,
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
                impl_: Arc::new(Pkcs11Impl {
                    _pkcs11_lib: Arc::new(pkcs11_lib),
                    function_list: Arc::new(*list_ptr),
                }),
            })
        }
    }

    /// Initialize the PKCS11 library
    pub fn initialize(&self, init_args: CInitializeArgs) -> Result<()> {
        general_purpose::initialize(self, init_args)
    }

    /// Finalize the PKCS11 library. Indicates that the application no longer needs to use PKCS11.
    /// The library is also automatically finalized on drop.
    pub fn finalize(self) {}

    /// Returns the information about the library
    pub fn get_library_info(&self) -> Result<Info> {
        general_purpose::get_library_info(self)
    }

    /// Get all slots available with a token
    pub fn get_slots_with_token(&self) -> Result<Vec<Slot>> {
        slot_token_management::get_slots_with_token(self)
    }

    /// Get all slots available with a token
    pub fn get_slots_with_initialized_token(&self) -> Result<Vec<Slot>> {
        slot_token_management::get_slots_with_initialized_token(self)
    }

    /// Get all slots
    pub fn get_all_slots(&self) -> Result<Vec<Slot>> {
        slot_token_management::get_all_slots(self)
    }

    /// Initialize a token
    ///
    /// Currently will use an empty label for all tokens.
    pub fn init_token(&self, slot: Slot, pin: &str, label: &str) -> Result<()> {
        slot_token_management::init_token(self, slot, pin, label)
    }

    /// Returns the slot info
    pub fn get_slot_info(&self, slot: Slot) -> Result<SlotInfo> {
        slot_token_management::get_slot_info(self, slot)
    }

    /// Returns information about a specific token
    pub fn get_token_info(&self, slot: Slot) -> Result<TokenInfo> {
        slot_token_management::get_token_info(self, slot)
    }

    /// Get all mechanisms support by a slot
    pub fn get_mechanism_list(&self, slot: Slot) -> Result<Vec<MechanismType>> {
        slot_token_management::get_mechanism_list(self, slot)
    }

    /// Get detailed information about a mechanism for a slot
    pub fn get_mechanism_info(&self, slot: Slot, type_: MechanismType) -> Result<MechanismInfo> {
        slot_token_management::get_mechanism_info(self, slot, type_)
    }

    /// Open a new session with no callback set
    pub fn open_session_no_callback(&self, slot_id: Slot, flags: SessionFlags) -> Result<Session> {
        session_management::open_session_no_callback(self, slot_id, flags)
    }
}

impl Drop for Pkcs11 {
    fn drop(&mut self) {
        if let Err(e) = general_purpose::finalize_private(self) {
            error!("Failed to finalize: {}", e);
        }
    }
}
