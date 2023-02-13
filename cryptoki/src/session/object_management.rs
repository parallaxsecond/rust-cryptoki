// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Object management functions

use crate::error::{Result, Rv, RvError};
use crate::object::{Attribute, AttributeInfo, AttributeType, ObjectHandle};
use crate::session::Session;
use cryptoki_sys::*;
use std::collections::HashMap;
use std::convert::TryInto;

// Search 10 elements at a time
const MAX_OBJECT_COUNT: usize = 10;

impl Session {
    /// Search for session objects matching a template
    pub fn find_objects(&self, template: &[Attribute]) -> Result<Vec<ObjectHandle>> {
        let mut template: Vec<CK_ATTRIBUTE> = template.iter().map(|attr| attr.into()).collect();

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_FindObjectsInit)(
                self.handle(),
                template.as_mut_ptr(),
                template.len().try_into()?,
            ))
            .into_result()?;
        }

        let mut object_handles = [0; MAX_OBJECT_COUNT];
        let mut object_count = 0;
        let mut objects = Vec::new();

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_FindObjects)(
                self.handle(),
                object_handles.as_mut_ptr() as CK_OBJECT_HANDLE_PTR,
                MAX_OBJECT_COUNT.try_into()?,
                &mut object_count,
            ))
            .into_result()?;
        }

        while object_count > 0 {
            objects.extend_from_slice(&object_handles[..object_count.try_into()?]);

            unsafe {
                Rv::from(get_pkcs11!(self.client(), C_FindObjects)(
                    self.handle(),
                    object_handles.as_mut_ptr() as CK_OBJECT_HANDLE_PTR,
                    MAX_OBJECT_COUNT.try_into()?,
                    &mut object_count,
                ))
                .into_result()?;
            }
        }

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_FindObjectsFinal)(
                self.handle(),
            ))
            .into_result()?;
        }

        let objects = objects.into_iter().map(ObjectHandle::new).collect();

        Ok(objects)
    }

    /// Create a new object
    pub fn create_object(&self, template: &[Attribute]) -> Result<ObjectHandle> {
        let mut template: Vec<CK_ATTRIBUTE> = template.iter().map(|attr| attr.into()).collect();
        let mut object_handle = 0;

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_CreateObject)(
                self.handle(),
                template.as_mut_ptr(),
                template.len().try_into()?,
                &mut object_handle as CK_OBJECT_HANDLE_PTR,
            ))
            .into_result()?;
        }

        Ok(ObjectHandle::new(object_handle))
    }

    /// Destroy an object
    pub fn destroy_object(&self, object: ObjectHandle) -> Result<()> {
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_DestroyObject)(
                self.handle(),
                object.handle(),
            ))
            .into_result()
        }
    }

    /// Get the attribute info of an object: if the attribute is present and its size.
    ///
    /// # Arguments
    ///
    /// * `object` - The [ObjectHandle] used to reference the object
    /// * `attributes` - The list of attributes to get the information of
    ///
    /// # Returns
    ///
    /// This function will return a Vector of [AttributeInfo] enums that will either contain
    /// the size of the requested attribute, [AttributeInfo::TypeInvalid] if the attribute is not a
    /// valid type for the object, or [AttributeInfo::Sensitive] if the requested attribute is
    /// sensitive and will not be returned to the user.
    ///
    /// The list of returned attributes is 1-to-1 matched with the provided vector of attribute
    /// types.  If you wish, you may create a hash table simply by:
    ///
    /// ```no_run
    /// use cryptoki::context::Pkcs11;
    /// use cryptoki::context::CInitializeArgs;
    /// use cryptoki::object::AttributeType;
    /// use cryptoki::session::UserType;
    /// use std::collections::HashMap;
    /// use std::env;
    ///
    /// let mut pkcs11 = Pkcs11::new(
    ///         env::var("PKCS11_SOFTHSM2_MODULE")
    ///             .unwrap_or_else(|_| "/usr/local/lib/softhsm/libsofthsm2.so".to_string()),
    ///     )
    ///     .unwrap();
    ///
    /// pkcs11.initialize(CInitializeArgs::OsThreads).unwrap();
    /// let slot = pkcs11.get_slots_with_token().unwrap().remove(0);
    ///
    /// let session = pkcs11.open_ro_session(slot).unwrap();
    /// session.login(UserType::User, Some("fedcba"));
    ///
    /// let empty_attrib= vec![];
    /// if let Some(object) = session.find_objects(&empty_attrib).unwrap().get(0) {
    ///     let attribute_types = vec![
    ///         AttributeType::Token,
    ///         AttributeType::Private,
    ///         AttributeType::Modulus,
    ///         AttributeType::KeyType,
    ///         AttributeType::Verify,];
    ///
    ///     let attribute_info = session.get_attribute_info(*object, &attribute_types).unwrap();
    ///
    ///     let hash = attribute_types
    ///         .iter()
    ///         .zip(attribute_info.iter())
    ///         .collect::<HashMap<_, _>>();
    /// }
    /// ```
    ///
    /// Alternatively, you can call [Session::get_attribute_info_map], found below.
    pub fn get_attribute_info(
        &self,
        object: ObjectHandle,
        attributes: &[AttributeType],
    ) -> Result<Vec<AttributeInfo>> {
        let mut results = Vec::new();

        for attrib in attributes.iter() {
            let mut template: Vec<CK_ATTRIBUTE> = vec![CK_ATTRIBUTE {
                type_: (*attrib).into(),
                pValue: std::ptr::null_mut(),
                ulValueLen: 0,
            }];

            match unsafe {
                Rv::from(get_pkcs11!(self.client(), C_GetAttributeValue)(
                    self.handle(),
                    object.handle(),
                    template.as_mut_ptr(),
                    template.len().try_into()?,
                ))
            } {
                Rv::Ok => {
                    results.push(AttributeInfo::Available(template[0].ulValueLen.try_into()?))
                }
                Rv::Error(RvError::AttributeSensitive) => results.push(AttributeInfo::Sensitive),
                Rv::Error(RvError::AttributeTypeInvalid) => {
                    results.push(AttributeInfo::TypeInvalid)
                }
                rv => rv.into_result()?,
            }
        }
        Ok(results)
    }

    /// Get the attribute info of an object: if the attribute is present and its size.
    ///
    /// # Arguments
    ///
    /// * `object` - The [ObjectHandle] used to reference the object
    /// * `attributes` - The list of attributes to get the information of
    ///
    /// # Returns
    ///
    /// This function will return a HashMap of [AttributeType] and [AttributeInfo] enums that will
    /// either contain the size of the requested attribute, [AttributeInfo::TypeInvalid] if the
    /// attribute is not a valid type for the object, or [AttributeInfo::Sensitive] if the requested
    /// attribute is sensitive and will not be returned to the user.
    pub fn get_attribute_info_map(
        &self,
        object: ObjectHandle,
        attributes: Vec<AttributeType>,
    ) -> Result<HashMap<AttributeType, AttributeInfo>> {
        let attrib_info = self.get_attribute_info(object, attributes.as_slice())?;

        Ok(attributes
            .iter()
            .cloned()
            .zip(attrib_info.iter().cloned())
            .collect::<HashMap<_, _>>())
    }

    /// Get the attributes values of an object.
    /// Ignore the unavailable one. One has to call the get_attribute_info method to check which
    /// ones are unavailable.
    pub fn get_attributes(
        &self,
        object: ObjectHandle,
        attributes: &[AttributeType],
    ) -> Result<Vec<Attribute>> {
        let attrs_info = self.get_attribute_info(object, attributes)?;

        // Allocating a chunk of memory where to put the attributes value.
        let attrs_memory: Vec<(AttributeType, Vec<u8>)> = attrs_info
            .iter()
            .zip(attributes.iter())
            .filter_map(|(attr_info, attr_type)| {
                if let AttributeInfo::Available(size) = attr_info {
                    Some((*attr_type, vec![0; *size]))
                } else {
                    None
                }
            })
            .collect();

        let mut template: Vec<CK_ATTRIBUTE> = attrs_memory
            .iter()
            .map(|(attr_type, memory)| {
                Ok(CK_ATTRIBUTE {
                    type_: (*attr_type).into(),
                    pValue: memory.as_ptr() as *mut std::ffi::c_void,
                    ulValueLen: memory.len().try_into()?,
                })
            })
            .collect::<Result<Vec<CK_ATTRIBUTE>>>()?;

        // This should only return OK as all attributes asked should be
        // available. Concurrency problem?
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_GetAttributeValue)(
                self.handle(),
                object.handle(),
                template.as_mut_ptr(),
                template.len().try_into()?,
            ))
            .into_result()?;
        }

        // Convert from CK_ATTRIBUTE to Attribute
        template.into_iter().map(|attr| attr.try_into()).collect()
    }

    /// Sets the attributes of an object
    pub fn update_attributes(&self, object: ObjectHandle, template: &[Attribute]) -> Result<()> {
        let mut template: Vec<CK_ATTRIBUTE> = template.iter().map(|attr| attr.into()).collect();

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_SetAttributeValue)(
                self.handle(),
                object.handle(),
                template.as_mut_ptr(),
                template.len().try_into()?,
            ))
            .into_result()?;
        }

        Ok(())
    }
}
