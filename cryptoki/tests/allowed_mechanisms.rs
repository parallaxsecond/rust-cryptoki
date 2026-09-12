// Copyright 2026 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::mem::size_of;

use cryptoki::{error::Error, mechanism::MechanismType, object::Attribute};
use cryptoki_sys::{CKA_ALLOWED_MECHANISMS, CK_ATTRIBUTE, CK_MECHANISM_TYPE};

#[test]
fn allowed_mechanisms_raw_length_is_measured_in_bytes() {
    let mechanisms = vec![MechanismType::AES_CBC, MechanismType::AES_GCM];
    let attribute = Attribute::AllowedMechanisms(mechanisms.clone());

    let raw = CK_ATTRIBUTE::from(&attribute);

    assert_eq!(raw.type_, CKA_ALLOWED_MECHANISMS);
    assert_eq!(
        raw.ulValueLen as usize,
        mechanisms.len() * size_of::<CK_MECHANISM_TYPE>()
    );
}

#[test]
fn nonempty_allowed_mechanisms_round_trip_preserves_element_count() {
    let expected = vec![MechanismType::AES_CBC, MechanismType::AES_GCM];
    let attribute = Attribute::AllowedMechanisms(expected.clone());
    let raw = CK_ATTRIBUTE::from(&attribute);

    let decoded = Attribute::try_from(raw).unwrap();

    assert_eq!(decoded, Attribute::AllowedMechanisms(expected));
}

#[test]
fn unaligned_allowed_mechanisms_value_is_decoded_as_bytes() {
    let expected = vec![MechanismType::AES_CBC, MechanismType::AES_GCM];
    let mechanism_size = size_of::<CK_MECHANISM_TYPE>();
    let declared_byte_len = expected.len() * mechanism_size;
    let mut backing = vec![0_u8; declared_byte_len + 1];

    for (index, mechanism) in expected.iter().copied().enumerate() {
        let mechanism = CK_MECHANISM_TYPE::from(mechanism).to_ne_bytes();
        let start = 1 + index * mechanism_size;
        backing[start..start + mechanism_size].copy_from_slice(&mechanism);
    }

    let raw = CK_ATTRIBUTE {
        type_: CKA_ALLOWED_MECHANISMS,
        pValue: backing[1..].as_mut_ptr().cast(),
        ulValueLen: declared_byte_len.try_into().unwrap(),
    };

    let decoded = Attribute::try_from(raw).unwrap();

    assert_eq!(decoded, Attribute::AllowedMechanisms(expected));
}

#[test]
fn malformed_allowed_mechanisms_byte_length_is_rejected() {
    let mut backing = vec![0_u8; size_of::<CK_MECHANISM_TYPE>() + 1];
    let raw = CK_ATTRIBUTE {
        type_: CKA_ALLOWED_MECHANISMS,
        pValue: backing.as_mut_ptr().cast(),
        ulValueLen: backing.len().try_into().unwrap(),
    };

    assert!(matches!(Attribute::try_from(raw), Err(Error::InvalidValue)));
}

#[test]
fn null_nonempty_allowed_mechanisms_value_is_rejected() {
    let raw = CK_ATTRIBUTE {
        type_: CKA_ALLOWED_MECHANISMS,
        pValue: std::ptr::null_mut(),
        ulValueLen: size_of::<CK_MECHANISM_TYPE>().try_into().unwrap(),
    };

    assert!(matches!(Attribute::try_from(raw), Err(Error::InvalidValue)));
}

#[cfg(miri)]
#[test]
fn direct_nonempty_allowed_mechanisms_round_trip_stays_in_bounds() {
    let expected = vec![MechanismType::AES_CBC, MechanismType::AES_GCM];
    let attribute = Attribute::AllowedMechanisms(expected.clone());
    let raw = CK_ATTRIBUTE::from(&attribute);

    let decoded = Attribute::try_from(raw).unwrap();

    assert_eq!(decoded, Attribute::AllowedMechanisms(expected));
}
