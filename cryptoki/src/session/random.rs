// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Functions used to generate random numbers

use crate::error::{Result, Rv};
use crate::session::Session;
use std::convert::TryInto;

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn generate_random_slice(session: &Session, random_data: &mut [u8]) -> Result<()> {
    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_GenerateRandom)(
            session.handle(),
            random_data.as_ptr() as *mut u8,
            random_data.len().try_into()?,
        ))
        .into_result()?;
    }
    Ok(())
}

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn generate_random_vec(session: &Session, random_len: u32) -> Result<Vec<u8>> {
    let mut result: Vec<u8> = vec![0; random_len as usize];
    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_GenerateRandom)(
            session.handle(),
            result.as_mut_ptr() as *mut u8,
            random_len.try_into()?,
        ))
        .into_result()?;
    }
    Ok(result)
}

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn seed_random(session: &Session, seed: &[u8]) -> Result<()> {
    unsafe {
        Rv::from(get_pkcs11!(session.client(), C_SeedRandom)(
            session.handle(),
            seed.as_ptr() as *mut u8,
            seed.len().try_into()?,
        ))
        .into_result()?;
    }
    Ok(())
}
