// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! Generic abstraction of CK_FLAGS for specialization in other modules
//!
//! Generate a bit flag set bound to a type definition, T. T has no
//! function beyond providing a compile-time bounds check and is only
//! present as phantom data.
//!
//! These definitions also divide the roles of a flag accumulator
//! (`BitFlags`) from a single, constant bit that contributes to it
//! ('FlagBit`) or that bit's inverse (`FlagMask`)
//!
//! The following fundamental operations are defined.
//!
//! * Flags traits:  From CK_FLAGS, Deref and DerefMut as CK_FLAGS
//! * !Bit -> Mask (ones compliment)
//! * Flags |= Bit
//! * Flags &= Mask
//! * Flags ^= Bit
//! * Bit | Bit
//! * Mask & Mask
//! * Flags.contains(Bit)
//!
//! Imporantly, Bit types cannot* be assigned to, but can be composed
//! for assignment to the associated accumulator type. Likewise, two
//! accumulators can't be composed with each other. Only the accumulator
//! type can be converted to/from CK_FLAGS for use in FFI operations.
//!
//! *Technically false. The binary operations resolve to a bit type, not
//! an accumulator. If assigned to an itermediate variable, a multi-bit
//! type can be constructed. There is also no enforcement of the assumption
//! that FlagBit only has a single set bit. The lack of assign-op operators
//! is intended to discourage this, though, and the type isn't pub to be
//! abused anyway.
//!
//! The following are intended use patterns.
//!
//! * Set: Flags |= Bit
//! * Set multiple: Flags |= Bit | Bit | ...
//! * Unset: Flags &= !Bit
//! * Unset multiple: Flags &= !(Bit | Bit | ...)
//! * Toggle: Flags ^= Bit
//! * Toggle mutliple: Flags ^= Bit | Bit | ...
//! * Test: Flags.contains(Bit) -> bool
//! * Test (ALL): Flags.contains(Bit | Bit | ...) -> bool
use cryptoki_sys::CK_FLAGS;
use std::marker::PhantomData;
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXorAssign, Deref, DerefMut, Not};

/// A type representing a 1-bit flag constant or some composition thereof
#[repr(transparent)]
pub(crate) struct FlagBit<T> {
    value: CK_FLAGS,
    _type: PhantomData<T>,
}

/// A type representing the one's compliment of a FlagBit<T>
#[repr(transparent)]
pub(crate) struct FlagMask<T> {
    value: CK_FLAGS,
    _type: PhantomData<T>,
}

/// An accumulator type representing the flag state of a T instance
#[derive(Default)]
#[repr(transparent)]
pub(crate) struct CkFlags<T> {
    value: CK_FLAGS,
    _type: PhantomData<T>,
}

// Must hand write Clone and Copy traits because the derived
// versions assume T to be Copy and constrain the impl accordingly.
// In general, we'll have non-Copy Ts and want to avoid this.
impl<T> Copy for FlagBit<T> {}
impl<T> Clone for FlagBit<T> {
    fn clone(&self) -> Self {
        Self {
            value: self.value,
            _type: PhantomData,
        }
    }
}
impl<T> Copy for FlagMask<T> {}
impl<T> Clone for FlagMask<T> {
    fn clone(&self) -> Self {
        Self {
            value: self.value,
            _type: PhantomData,
        }
    }
}
impl<T> Copy for CkFlags<T> {}
impl<T> Clone for CkFlags<T> {
    fn clone(&self) -> Self {
        Self {
            value: self.value,
            _type: PhantomData,
        }
    }
}

/// Const constructor for defined CKF_* constants
impl<T> FlagBit<T> {
    pub(crate) const fn new(value: CK_FLAGS) -> Self {
        Self {
            value,
            _type: PhantomData,
        }
    }
}

/// Bit | Bit -> Bit
impl<T> BitOr for FlagBit<T> {
    type Output = FlagBit<T>;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self {
            value: self.value | rhs.value,
            ..self
        }
    }
}

/// !Bit -> Mask
impl<T> Not for FlagBit<T> {
    type Output = FlagMask<T>;
    fn not(self) -> Self::Output {
        FlagMask {
            value: !self.value,
            _type: PhantomData,
        }
    }
}

/// Mask & Mask -> Mask
impl<T> BitAnd for FlagMask<T> {
    type Output = FlagMask<T>;
    fn bitand(self, rhs: Self) -> Self::Output {
        Self {
            value: self.value & rhs.value,
            ..self
        }
    }
}

/// Flags = CK_FLAGS.into()
impl<T> From<CK_FLAGS> for CkFlags<T> {
    fn from(value: CK_FLAGS) -> Self {
        Self {
            value,
            _type: PhantomData,
        }
    }
}

/// CK_FLAGS = *Flags
impl<T> Deref for CkFlags<T> {
    type Target = CK_FLAGS;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

/// *Flags = CK_FLAGS
impl<T> DerefMut for CkFlags<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

/// Flags |= Bit
impl<T> BitOrAssign<FlagBit<T>> for CkFlags<T> {
    fn bitor_assign(&mut self, rhs: FlagBit<T>) {
        **self |= rhs.value
    }
}

/// Flags &= Mask
impl<T> BitAndAssign<FlagMask<T>> for CkFlags<T> {
    fn bitand_assign(&mut self, rhs: FlagMask<T>) {
        **self &= rhs.value
    }
}

/// Flags ^= Bit
impl<T> BitXorAssign<FlagBit<T>> for CkFlags<T> {
    fn bitxor_assign(&mut self, rhs: FlagBit<T>) {
        **self ^= rhs.value
    }
}

impl<T> CkFlags<T> {
    pub(crate) fn contains(&self, bits: FlagBit<T>) -> bool {
        (self.value & bits.value) == bits.value
    }
}

#[cfg(test)]
mod test {
    use super::*;
    const ONE: FlagBit<()> = FlagBit::new(1);
    const TWO: FlagBit<()> = FlagBit::new(2);
    const FOUR: FlagBit<()> = FlagBit::new(4);
    fn is_copy<T: Copy>(_: T) -> bool {
        true
    }

    #[test]
    fn c_type_is_copy() {
        // Probably overkill, but if this is ever false
        // the hand implementation of Copy may hide it.
        let n: CK_FLAGS = 0;
        assert!(is_copy(n));
    }

    #[test]
    fn default_to_zero() {
        let flags: CkFlags<()> = CkFlags::default();
        assert_eq!(flags.value, 0);
    }

    #[test]
    fn set_one() {
        let mut flags = CkFlags::default();
        flags |= ONE;
        assert_eq!(flags.value, 1);
        flags |= ONE;
        assert_eq!(flags.value, 1);
    }

    #[test]
    fn set_multi() {
        let mut flags = CkFlags::default();
        flags |= ONE | TWO | FOUR;
        assert_eq!(flags.value, 7);
        flags |= ONE | TWO | FOUR;
        assert_eq!(flags.value, 7);
    }

    #[test]
    fn unset_one() {
        let mut flags = CkFlags::from(7);
        flags &= !TWO;
        assert_eq!(flags.value, 5);
        flags &= !TWO;
        assert_eq!(flags.value, 5);
    }

    #[test]
    fn unset_multi() {
        let mut flags = CkFlags::from(7);
        flags &= !(ONE | FOUR);
        assert_eq!(flags.value, 2);
        flags &= !(ONE | FOUR);
        assert_eq!(flags.value, 2);
    }

    #[test]
    fn toggle_one() {
        let mut flags = CkFlags::from(7);
        flags ^= TWO;
        assert_eq!(flags.value, 5);
        flags ^= TWO;
        assert_eq!(flags.value, 7);
    }

    #[test]
    fn toggle_multi() {
        let mut flags = CkFlags::from(7);
        flags ^= ONE | FOUR;
        assert_eq!(flags.value, 2);
        flags ^= ONE | FOUR;
        assert_eq!(flags.value, 7);
    }

    #[test]
    fn check_contains() {
        let flags = CkFlags::default();
        assert!(!flags.contains(ONE));
        assert!(!flags.contains(TWO));
        assert!(!flags.contains(ONE | TWO));
        assert!(!flags.contains(FOUR));
        assert!(!flags.contains(ONE | FOUR));
        assert!(!flags.contains(TWO | FOUR));
        assert!(!flags.contains(ONE | TWO | FOUR));
        assert_eq!(flags.value, 0);

        let flags = CkFlags::from(2);
        assert!(!flags.contains(ONE));
        assert!(flags.contains(TWO));
        assert!(!flags.contains(ONE | TWO));
        assert!(!flags.contains(FOUR));
        assert!(!flags.contains(ONE | FOUR));
        assert!(!flags.contains(TWO | FOUR));
        assert!(!flags.contains(ONE | TWO | FOUR));
        assert_eq!(flags.value, 2);

        let flags = CkFlags::from(5);
        assert!(flags.contains(ONE)); // counterintuitive
        assert!(!flags.contains(TWO));
        assert!(!flags.contains(ONE | TWO));
        assert!(flags.contains(FOUR)); // counterintuitive
        assert!(flags.contains(ONE | FOUR));
        assert!(!flags.contains(TWO | FOUR));
        assert!(!flags.contains(ONE | TWO | FOUR));
        assert_eq!(flags.value, 5);

        let flags = CkFlags::from(7);
        assert!(flags.contains(ONE));
        assert!(flags.contains(TWO));
        assert!(flags.contains(ONE | TWO));
        assert!(flags.contains(FOUR));
        assert!(flags.contains(ONE | FOUR));
        assert!(flags.contains(TWO | FOUR));
        assert!(flags.contains(ONE | TWO | FOUR));
        assert_eq!(flags.value, 7);
    }
}
