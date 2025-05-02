//! ML-DSA mechanism types

use crate::mechanism::{Mechanism, MechanismType};

use cryptoki_sys::*;
use std::{convert::TryInto, marker::PhantomData, ptr::null_mut};

/// The hedge type for ML-DSA signature
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum HedgeType {
    /// Token may create either a hedged signature or a deterministic signature
    ///
    /// This variant maps to `CKH_HEDGE_PREFERRED`: Default
    #[default]
    Preferred,
    /// Token must produce a hedged signature or fail
    ///
    /// This variant maps to `CKH_HEDGE_REQUIRED`
    Required,
    /// Token must produce a deterministic signature or fail
    ///
    /// This variant maps to `CKH_DETERMINISTIC_REQUIRED`
    DeterministicRequired,
}

impl From<HedgeType> for CK_ULONG {
    fn from(hedge: HedgeType) -> CK_ULONG {
        match hedge {
            HedgeType::Preferred => CKH_HEDGE_PREFERRED,
            HedgeType::Required => CKH_HEDGE_REQUIRED,
            HedgeType::DeterministicRequired => CKH_DETERMINISTIC_REQUIRED,
        }
    }
}

/// The ML-DSA additional context for signatures
///
/// This structure wraps `CK_SIGN_ADDITIONAL_CONTEXT` structure.
#[derive(Debug, Clone, Copy)]
pub struct SignAdditionalContext<'a> {
    inner: Option<CK_SIGN_ADDITIONAL_CONTEXT>,
    /// Marker type to ensure we don't outlive the data
    _marker: PhantomData<&'a [u8]>,
}

impl SignAdditionalContext<'_> {
    /// Construct ML-DSA signature parameters.
    ///
    /// # Arguments
    ///
    /// * `hedge` - The [`HedgeType`].
    /// * `context` - The context.
    ///
    /// # Returns
    ///
    /// A new [`SignAdditionalContext`] struct.
    pub fn new(hedge: HedgeType, context: Option<&[u8]>) -> Self {
        if hedge == HedgeType::Preferred && context.is_none() {
            return Self {
                inner: None,
                _marker: PhantomData,
            };
        }

        let (p_context, ul_context_len) = match context {
            Some(c) => (
                c.as_ptr() as *mut _,
                c.len().try_into().expect("usize can not fit in CK_ULONG"),
            ),
            None => (null_mut() as *mut _, 0),
        };
        Self {
            inner: Some(CK_SIGN_ADDITIONAL_CONTEXT {
                hedgeVariant: hedge.into(),
                pContext: p_context,
                ulContextLen: ul_context_len,
            }),
            _marker: PhantomData,
        }
    }

    /// Retrieve the inner `CK_SIGN_ADDITIONAL_CONTEXT` struct, if present.
    ///
    /// This method provides a reference to the `CK_SIGN_ADDITIONAL_CONTEXT`
    /// struct encapsulated within the `SignAdditionalContext`, if the signature
    /// scheme requires additional parameters.
    ///
    /// # Returns
    ///
    /// `Some(&CK_SIGN_ADDITIONAL_CONTEXT)` if the signature scheme has associated
    /// parameters, otherwise `None`.
    pub fn inner(&self) -> Option<&CK_SIGN_ADDITIONAL_CONTEXT> {
        self.inner.as_ref()
    }
}

/// The ML-DSA additional context for signatures with hashing information
///
/// This structure wraps `CK_HASH_SIGN_ADDITIONAL_CONTEXT` structure.
#[derive(Debug, Clone, Copy)]
pub struct HashSignAdditionalContext<'a> {
    inner: CK_HASH_SIGN_ADDITIONAL_CONTEXT,
    /// Marker type to ensure we don't outlive the data
    _marker: PhantomData<&'a [u8]>,
}

impl HashSignAdditionalContext<'_> {
    /// Construct HashML-DSA Signature parameters.
    ///
    /// # Arguments
    ///
    /// * `hedge` - The HedgeType.
    /// * `context` - The context
    /// * `hash` - The hash type
    ///
    /// # Returns
    ///
    /// A new SignAdditionalContext struct.
    pub fn new(hedge: HedgeType, context: Option<&[u8]>, hash: MechanismType) -> Self {
        let (p_context, ul_context_len) = match context {
            Some(c) => (
                c.as_ptr() as *mut _,
                c.len().try_into().expect("usize can not fit in CK_ULONG"),
            ),
            None => (null_mut(), 0),
        };
        Self {
            inner: CK_HASH_SIGN_ADDITIONAL_CONTEXT {
                hedgeVariant: hedge.into(),
                pContext: p_context,
                ulContextLen: ul_context_len,
                hash: hash.into(),
            },
            _marker: PhantomData,
        }
    }

    /// Retrieve the inner `CK_HASH_SIGN_ADDITIONAL_CONTEXT` struct.
    ///
    /// This method provides a reference to the `CK_HASH_SIGN_ADDITIONAL_CONTEXT`
    /// struct encapsulated within the `HashSignAdditionalContext`.
    ///
    /// # Returns
    ///
    /// `&CK_HASH_SIGN_ADDITIONAL_CONTEXT`.
    pub fn inner(&self) -> &CK_HASH_SIGN_ADDITIONAL_CONTEXT {
        &self.inner
    }
}

impl<'a> From<HashSignAdditionalContext<'a>> for Mechanism<'a> {
    fn from(params: HashSignAdditionalContext<'a>) -> Self {
        Mechanism::HashMlDsa(params)
    }
}
