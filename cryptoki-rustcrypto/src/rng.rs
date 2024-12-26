// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use signature::rand_core::{CryptoRng, Error as RndError, RngCore};
use thiserror::Error;

use crate::SessionLike;

#[derive(Debug, Error)]
pub enum Error {}

/// [`Rng`] is a PKCS#11-backed CSPRNG.
///
/// ## Panics
///
/// The [`RngCore::fill_bytes`] implementation may panic if the provider was
/// unable to return enough bytes.
pub struct Rng<S: SessionLike>(S);

// TODO(baloo): check for CKF_RNG bit flag (CK_TOKEN_INFO struct -> flags)
impl<S: SessionLike> Rng<S> {
    pub fn new(session: S) -> Result<Self, Error> {
        Ok(Self(session))
    }
}

macro_rules! impl_next_uint {
    ($self:ident, $u:ty) => {{
        let mut buf = <$u>::MIN.to_be_bytes();
        $self.fill_bytes(&mut buf[..]);

        <$u>::from_be_bytes(buf)
    }};
}

impl<S: SessionLike> RngCore for Rng<S> {
    fn next_u32(&mut self) -> u32 {
        impl_next_uint!(self, u32)
    }

    fn next_u64(&mut self) -> u64 {
        impl_next_uint!(self, u64)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest)
            .expect("Cryptoki provider failed to generate random");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RndError> {
        self.0.generate_random_slice(dest).map_err(RndError::new)
    }
}

impl<S: SessionLike> CryptoRng for Rng<S> {}
