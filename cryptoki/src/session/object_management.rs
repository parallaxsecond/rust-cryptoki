// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Object management functions

use crate::error::{Result, Rv, RvError};
use crate::object::{Attribute, AttributeInfo, AttributeType, ObjectHandle};
use crate::session::Session;
use cryptoki_sys::*;
use log::error;
use std::collections::HashMap;
use std::convert::TryInto;

/// Represents an ongoing object search
///
/// See the documentation for [Session::find_objects_init].
#[derive(Debug)]
pub struct FindObjects<'a> {
    session: &'a mut Session,
}

impl<'a> FindObjects<'a> {
    /// Continue an ongoing object search
    ///
    /// # Arguments
    ///
    /// * `max_objects` - The maximum number of objects to return
    ///
    /// # Returns
    ///
    /// This function returns up to `max_objects` objects.  If there are no remaining
    /// objects, or `max_objects` is 0, then it returns an empty vector.
    pub fn find_next(&mut self, max_objects: usize) -> Result<Vec<ObjectHandle>> {
        if max_objects == 0 {
            return Ok(vec![]);
        }

        let mut object_handles = Vec::with_capacity(max_objects);
        let mut object_count = 0;

        unsafe {
            Rv::from(get_pkcs11!(self.session.client(), C_FindObjects)(
                self.session.handle(),
                object_handles.as_mut_ptr(),
                max_objects.try_into()?,
                &mut object_count,
            ))
            .into_result()?;
            object_handles.set_len(object_count.try_into()?)
        }

        Ok(object_handles.into_iter().map(ObjectHandle::new).collect())
    }

    /// Get the session associated to the search
    pub fn session(&self) -> &Session {
        self.session
    }
}

impl<'a> Drop for FindObjects<'a> {
    fn drop(&mut self) {
        if let Err(e) = find_objects_final_private(self.session) {
            error!("Failed to terminate object search: {}", e);
        }
    }
}

fn find_objects_final_private(session: &Session) -> Result<()> {
    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_FindObjectsFinal)(
            session.handle(),
        ))
        .into_result()
    }
}

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn find_objects_init<'a>(
    session: &'a mut Session,
    template: &[Attribute],
) -> Result<FindObjects<'a>> {
    let mut template: Vec<CK_ATTRIBUTE> = template.iter().map(|attr| attr.into()).collect();
    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_FindObjectsInit)(
            session.handle(),
            template.as_mut_ptr(),
            template.len().try_into()?,
        ))
        .into_result()?;
    }
    Ok(FindObjects { session })
}

// Search 10 elements at a time
const MAX_OBJECT_COUNT: usize = 10;

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn find_objects(
    session: &mut Session,
    template: &[Attribute],
) -> Result<Vec<ObjectHandle>> {
    let mut search = session.find_objects_init(template)?;
    let mut objects = Vec::new();

    while let ref new_objects @ [_, ..] = search.find_next(MAX_OBJECT_COUNT)?[..] {
        objects.extend_from_slice(new_objects)
    }

    Ok(objects)
}

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn create_object(session: &Session, template: &[Attribute]) -> Result<ObjectHandle> {
    let mut template: Vec<CK_ATTRIBUTE> = template.iter().map(|attr| attr.into()).collect();
    let mut object_handle = 0;

    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_CreateObject)(
            session.handle(),
            template.as_mut_ptr(),
            template.len().try_into()?,
            &mut object_handle as CK_OBJECT_HANDLE_PTR,
        ))
        .into_result()?;
    }

    Ok(ObjectHandle::new(object_handle))
}

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn destroy_object(session: &Session, object: ObjectHandle) -> Result<()> {
    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_DestroyObject)(
            session.handle(),
            object.handle(),
        ))
        .into_result()
    }
}

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn get_attribute_info(
    session: &Session,
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
            Rv::from(get_pkcs11!(session.client(), C_GetAttributeValue)(
                session.handle(),
                object.handle(),
                template.as_mut_ptr(),
                template.len().try_into()?,
            ))
        } {
            Rv::Ok => results.push(AttributeInfo::Available(template[0].ulValueLen.try_into()?)),
            Rv::Error(RvError::AttributeSensitive) => results.push(AttributeInfo::Sensitive),
            Rv::Error(RvError::AttributeTypeInvalid) => results.push(AttributeInfo::TypeInvalid),
            rv => rv.into_result()?,
        }
    }
    Ok(results)
}

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn get_attribute_info_map(
    session: &Session,
    object: ObjectHandle,
    attributes: Vec<AttributeType>,
) -> Result<HashMap<AttributeType, AttributeInfo>> {
    let attrib_info = session.get_attribute_info(object, attributes.as_slice())?;

    Ok(attributes
        .iter()
        .cloned()
        .zip(attrib_info.iter().cloned())
        .collect::<HashMap<_, _>>())
}

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn get_attributes(
    session: &Session,
    object: ObjectHandle,
    attributes: &[AttributeType],
) -> Result<Vec<Attribute>> {
    let attrs_info = session.get_attribute_info(object, attributes)?;

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
        Rv::from(get_pkcs11!(session.client(), C_GetAttributeValue)(
            session.handle(),
            object.handle(),
            template.as_mut_ptr(),
            template.len().try_into()?,
        ))
        .into_result()?;
    }

    // Convert from CK_ATTRIBUTE to Attribute
    template.into_iter().map(|attr| attr.try_into()).collect()
}
