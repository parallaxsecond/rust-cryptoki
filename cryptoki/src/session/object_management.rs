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

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn find_objects(
    session: &Session<'_>,
    template: &[Attribute],
) -> Result<Vec<ObjectHandle>> {
    let mut template: Vec<CK_ATTRIBUTE> = template.iter().map(|attr| attr.into()).collect();

    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_FindObjectsInit)(
            session.handle(),
            template.as_mut_ptr(),
            template.len().try_into()?,
        ))
        .into_result()?;
    }

    let mut object_handles = [0; MAX_OBJECT_COUNT];
    let mut object_count = 0;
    let mut objects = Vec::new();

    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_FindObjects)(
            session.handle(),
            object_handles.as_mut_ptr() as CK_OBJECT_HANDLE_PTR,
            MAX_OBJECT_COUNT.try_into()?,
            &mut object_count,
        ))
        .into_result()?;
    }

    while object_count > 0 {
        objects.extend_from_slice(&object_handles[..object_count.try_into()?]);

        unsafe {
            Rv::from(get_pkcs11!(session.client(), C_FindObjects)(
                session.handle(),
                object_handles.as_mut_ptr() as CK_OBJECT_HANDLE_PTR,
                MAX_OBJECT_COUNT.try_into()?,
                &mut object_count,
            ))
            .into_result()?;
        }
    }

    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_FindObjectsFinal)(
            session.handle(),
        ))
        .into_result()?;
    }

    let objects = objects.into_iter().map(ObjectHandle::new).collect();

    Ok(objects)
}

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn create_object(session: &Session<'_>, template: &[Attribute]) -> Result<ObjectHandle> {
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
pub(super) fn destroy_object(session: &Session<'_>, object: ObjectHandle) -> Result<()> {
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
    session: &Session<'_>,
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
    session: &Session<'_>,
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
    session: &Session<'_>,
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
