// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Key management functions

use crate::get_pkcs11;
use crate::types::function::Rv;
use crate::types::mechanism::Mechanism;
use crate::types::object::{Attribute, ObjectHandle};
use crate::types::session::Session;
use crate::Result;
use cryptoki_sys::{CK_ATTRIBUTE, CK_MECHANISM, CK_MECHANISM_PTR};
use std::convert::TryInto;

impl<'a> Session<'a> {
    /// Generate a public/private key pair
    pub fn generate_key_pair(
        &self,
        mechanism: &Mechanism,
        pub_key_template: &[Attribute],
        priv_key_template: &[Attribute],
    ) -> Result<(ObjectHandle, ObjectHandle)> {
        let mut mechanism: CK_MECHANISM = mechanism.into();
        let mut pub_key_template: Vec<CK_ATTRIBUTE> =
            pub_key_template.iter().map(|attr| attr.into()).collect();
        let mut priv_key_template: Vec<CK_ATTRIBUTE> =
            priv_key_template.iter().map(|attr| attr.into()).collect();
        let mut pub_handle = 0;
        let mut priv_handle = 0;
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_GenerateKeyPair)(
                self.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                pub_key_template.as_mut_ptr(),
                pub_key_template.len().try_into()?,
                priv_key_template.as_mut_ptr(),
                priv_key_template.len().try_into()?,
                &mut pub_handle,
                &mut priv_handle,
            ))
            .into_result()?;
        }

        Ok((
            ObjectHandle::new(pub_handle),
            ObjectHandle::new(priv_handle),
        ))
    }
}
