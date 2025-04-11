// Copyright 2025 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Mechanisms of NIST key-based key derive functions (SP 800-108, informally KBKDF)
//! See: <https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061446>

use core::{convert::TryInto, marker::PhantomData, pin::Pin, ptr};

use crate::object::{Attribute, ObjectHandle};

use super::MechanismType;

/// Endianness of byte representation of data.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Endianness {
    /// Little endian.
    Little,
    /// Big endian.
    Big,
}

/// Defines encoding format for a counter value.
///
/// This structure wraps a `CK_SP800_108_COUNTER_FORMAT` structure.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct KbkdfCounterFormat(cryptoki_sys::CK_SP800_108_COUNTER_FORMAT);

impl KbkdfCounterFormat {
    /// Construct encoding format for KDF's internal counter variable.
    ///
    /// # Arguments
    ///
    /// * `endianness` - The endianness of the counter's bit representation.
    ///
    /// * `width_in_bits` - The number of bits used to represent the counter value.
    pub fn new(endianness: Endianness, width_in_bits: usize) -> Self {
        Self(cryptoki_sys::CK_SP800_108_COUNTER_FORMAT {
            bLittleEndian: (endianness == Endianness::Little).into(),
            ulWidthInBits: width_in_bits
                .try_into()
                .expect("bit width of KBKDF internal counter does not fit in CK_ULONG"),
        })
    }
}

/// Method for calculating length of DKM (derived key material).
///
/// Corresponds to CK_SP800_108_DKM_LENGTH_METHOD.
#[derive(Debug, Clone, Copy)]
pub enum DkmLengthMethod {
    /// Sum of length of all keys derived by given invocation of KDF.
    SumOfKeys,
    /// Sum of length of all segments of output produced by PRF in given invocation of KDF.
    SumOfSegments,
}

/// Defines encoding format for DKM (derived key material).
///
/// This structure wraps a `CK_SP800_108_DKM_LENGTH_FORMAT` structure.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct KbkdfDkmLengthFormat(cryptoki_sys::CK_SP800_108_DKM_LENGTH_FORMAT);

impl KbkdfDkmLengthFormat {
    /// Construct encoding format for length value of DKM (derived key material) from KDF.
    ///
    /// # Arguments
    ///
    /// * `dkm_length_method` - The method used to calculate the DKM length value.
    ///
    /// * `endianness` - The endianness of the DKM length value's bit representation.
    ///
    /// * `width_in_bits` - The number of bits used to represent the DKM length value.
    pub fn new(
        dkm_length_method: DkmLengthMethod,
        endianness: Endianness,
        width_in_bits: usize,
    ) -> Self {
        Self(cryptoki_sys::CK_SP800_108_DKM_LENGTH_FORMAT {
            dkmLengthMethod: match dkm_length_method {
                DkmLengthMethod::SumOfKeys => cryptoki_sys::CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS,
                DkmLengthMethod::SumOfSegments => {
                    cryptoki_sys::CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS
                }
            },
            bLittleEndian: (endianness == Endianness::Little).into(),
            ulWidthInBits: width_in_bits.try_into().expect(
                "bit width of KBKDF derived key material length value does not fit in CK_ULONG",
            ),
        })
    }
}

/// The type of a segment of input data for the PRF, for a KBKDF operating in feedback- or double pipeline-mode.
#[derive(Debug, Clone, Copy)]
pub enum PrfDataParamType<'a> {
    /// Identifies location of predefined iteration variable in constructed PRF input data.
    IterationVariable(Option<&'a KbkdfCounterFormat>),
    /// Identifies location of counter in constructed PRF input data.
    Counter(&'a KbkdfCounterFormat),
    /// Identifies location of DKM (derived key material) length value in constructed PRF input data.
    DkmLength(&'a KbkdfDkmLengthFormat),
    /// Identifies location and value of byte array of data in constructed PRF input data.
    ByteArray(&'a [u8]),
}

/// A segment of input data for the PRF, to be used to construct a sequence of input.
///
/// This structure wraps a `CK_PRF_DATA_PARAM` structure.
///
/// * [`PrfDataParamType::IterationVariable`] is required for the KDF in all modes.
///   * In counter-mode, [`PrfDataParamType::IterationVariable`] must contain [`KbkdfCounterFormat`].
///     In feedback- and double pipeline-mode, it must contain [`None`].
/// * [`PrfDataParamType::Counter`] must not be present in counter-mode.
/// * [`PrfDataParamType::DkmLength`] can be present at most once, in any mode.
/// * [`PrfDataParamType::ByteArray`] can be present any amount of times, in any mode.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct PrfDataParam<'a> {
    inner: cryptoki_sys::CK_PRF_DATA_PARAM,
    /// Marker type to ensure we don't outlive the data
    _marker: PhantomData<&'a [u8]>,
}

impl<'a> PrfDataParam<'a> {
    /// Construct data parameter for input of the PRF internal to the KBKDF.
    ///
    /// # Arguments
    ///
    /// * `type_` - The specific type and parameters for the data parameter.
    pub fn new(type_: PrfDataParamType<'a>) -> Self {
        Self {
            inner: match type_ {
                PrfDataParamType::IterationVariable(None) => cryptoki_sys::CK_PRF_DATA_PARAM {
                    type_: cryptoki_sys::CK_SP800_108_ITERATION_VARIABLE,
                    pValue: ptr::null_mut(),
                    ulValueLen: 0,
                },
                PrfDataParamType::IterationVariable(Some(counter_format)) => {
                    cryptoki_sys::CK_PRF_DATA_PARAM {
                        type_: cryptoki_sys::CK_SP800_108_ITERATION_VARIABLE,
                        pValue: counter_format as *const _ as *mut _,
                        ulValueLen: size_of::<cryptoki_sys::CK_SP800_108_COUNTER_FORMAT>()
                            as cryptoki_sys::CK_ULONG,
                    }
                }
                PrfDataParamType::Counter(counter_format) => cryptoki_sys::CK_PRF_DATA_PARAM {
                    type_: cryptoki_sys::CK_SP800_108_COUNTER,
                    pValue: counter_format as *const _ as *mut _,
                    ulValueLen: size_of::<cryptoki_sys::CK_SP800_108_COUNTER_FORMAT>()
                        as cryptoki_sys::CK_ULONG,
                },
                PrfDataParamType::DkmLength(dkm_length_format) => cryptoki_sys::CK_PRF_DATA_PARAM {
                    type_: cryptoki_sys::CK_SP800_108_DKM_LENGTH,
                    pValue: dkm_length_format as *const _ as *mut _,
                    ulValueLen: size_of::<cryptoki_sys::CK_SP800_108_DKM_LENGTH_FORMAT>()
                        as cryptoki_sys::CK_ULONG,
                },
                PrfDataParamType::ByteArray(data) => cryptoki_sys::CK_PRF_DATA_PARAM {
                    type_: cryptoki_sys::CK_SP800_108_BYTE_ARRAY,
                    pValue: data.as_ptr() as *mut _,
                    ulValueLen: data
                        .len()
                        .try_into()
                        .expect("length of data parameter does not fit in CK_ULONG"),
                },
            },
            _marker: PhantomData,
        }
    }
}

/// Container for information on an additional key to be derived.
#[derive(Debug)]
pub struct DerivedKey {
    template: Pin<Box<[cryptoki_sys::CK_ATTRIBUTE]>>,
    handle: cryptoki_sys::CK_OBJECT_HANDLE,
}

impl DerivedKey {
    /// Construct template for additional key to be derived by KDF.
    ///
    /// # Arguments
    ///
    /// * `template` - The template for the key to be derived.
    pub fn new(template: &[Attribute]) -> Self {
        let template: Box<[cryptoki_sys::CK_ATTRIBUTE]> = template.iter().map(Into::into).collect();
        let template = Pin::new(template);

        Self {
            template,
            handle: cryptoki_sys::CK_INVALID_HANDLE,
        }
    }

    /// Return handle for derived key, if it has been created yet
    pub fn handle(&self) -> Option<ObjectHandle> {
        if self.handle == cryptoki_sys::CK_INVALID_HANDLE {
            None
        } else {
            Some(ObjectHandle::new(self.handle))
        }
    }
}

impl From<&mut DerivedKey> for cryptoki_sys::CK_DERIVED_KEY {
    fn from(value: &mut DerivedKey) -> Self {
        cryptoki_sys::CK_DERIVED_KEY {
            pTemplate: value.template.as_ptr() as cryptoki_sys::CK_ATTRIBUTE_PTR,
            ulAttributeCount: value
                .template
                .len()
                .try_into()
                .expect("number of attributes in template does not fit in CK_ULONG"),
            phKey: &mut value.handle as cryptoki_sys::CK_OBJECT_HANDLE_PTR,
        }
    }
}

/// NIST SP 800-108 (aka KBKDF) counter and double pipeline-mode parameters.
///
/// This structure wraps a `CK_SP800_108_KDF_PARAMS` structure.
#[derive(Debug)]
pub struct KbkdfParams<'a> {
    /// Holds own data so that we have a contiguous memory region to give to backend
    _additional_derived_keys: Option<Pin<Box<[cryptoki_sys::CK_DERIVED_KEY]>>>,

    inner: cryptoki_sys::CK_SP800_108_KDF_PARAMS,
    /// Marker type to ensure we don't outlive the data
    _marker: PhantomData<&'a [u8]>,
}

impl<'a> KbkdfParams<'a> {
    /// Construct parameters for NIST SP 800-108 KDF (aka KBKDF) pseuderandom function-based key
    /// derivation function, in counter or double pipeline-mode.
    ///
    /// # Arguments
    ///
    /// * `prf_mechanism` - The pseudorandom function that underlies the KBKDF operation.
    ///
    /// * `prf_data_params` - The sequence of data segments used as input data for the PRF. Requires at least [`PrfCounterDataParam::IterationVariable`].
    ///
    /// * `additional_derived_keys` - Any additional keys to be generated by the KDF from the base key.
    pub fn new(
        prf_mechanism: MechanismType,
        prf_data_params: &'a [PrfDataParam<'a>],
        additional_derived_keys: Option<&'a mut [DerivedKey]>,
    ) -> Self {
        let mut additional_derived_keys = additional_derived_keys
            .map(|keys| {
                keys.iter_mut()
                    .map(Into::into)
                    .collect::<Box<[cryptoki_sys::CK_DERIVED_KEY]>>()
            })
            .map(Pin::new);

        let inner = cryptoki_sys::CK_SP800_108_KDF_PARAMS {
            prfType: prf_mechanism.into(),
            ulNumberOfDataParams: prf_data_params
                .len()
                .try_into()
                .expect("number of data parameters does not fit in CK_ULONG"),
            pDataParams: prf_data_params.as_ptr() as cryptoki_sys::CK_PRF_DATA_PARAM_PTR,
            ulAdditionalDerivedKeys: additional_derived_keys.as_ref().map_or(0, |keys| {
                keys.len()
                    .try_into()
                    .expect("number of additional derived keys does not fit in CK_ULONG")
            }),
            pAdditionalDerivedKeys: additional_derived_keys
                .as_mut()
                .map_or(ptr::null_mut(), |keys| {
                    keys.as_mut_ptr() as cryptoki_sys::CK_DERIVED_KEY_PTR
                }),
        };

        Self {
            _additional_derived_keys: additional_derived_keys,

            inner,
            _marker: PhantomData,
        }
    }

    pub(crate) fn inner(&self) -> &cryptoki_sys::CK_SP800_108_KDF_PARAMS {
        &self.inner
    }
}

/// NIST SP 800-108 (aka KBKDF) feedback-mode parameters.
///
/// This structure wraps a `CK_SP800_108_FEEDBACK_KDF_PARAMS` structure.
#[derive(Debug)]
pub struct KbkdfFeedbackParams<'a> {
    /// Holds own data so that we have a contiguous memory region to give to backend
    _additional_derived_keys: Option<Pin<Box<[cryptoki_sys::CK_DERIVED_KEY]>>>,

    inner: cryptoki_sys::CK_SP800_108_FEEDBACK_KDF_PARAMS,
    /// Marker type to ensure we don't outlive the data
    _marker: PhantomData<&'a [u8]>,
}

impl<'a> KbkdfFeedbackParams<'a> {
    /// Construct parameters for NIST SP 800-108 KDF (aka KBKDF) pseuderandom function-based key
    /// derivation function, in feedback-mode.
    ///
    /// # Arguments
    ///
    /// * `prf_mechanism` - The pseudorandom function that underlies the KBKDF operation.
    ///
    /// * `prf_data_params` - The sequence of data segments used as input data for the PRF. Requires at least [`PrfDataParam::IterationVariable`].
    ///
    /// * `iv` - The IV to be used for the feedback-mode KDF.
    ///
    /// * `additional_derived_keys` - Any additional keys to be generated by the KDF from the base key.
    pub fn new(
        prf_mechanism: MechanismType,
        prf_data_params: &'a [PrfDataParam<'a>],
        iv: Option<&'a [u8]>,
        additional_derived_keys: Option<&'a mut [DerivedKey]>,
    ) -> Self {
        let mut additional_derived_keys = additional_derived_keys
            .map(|keys| {
                keys.iter_mut()
                    .map(Into::into)
                    .collect::<Box<[cryptoki_sys::CK_DERIVED_KEY]>>()
            })
            .map(Pin::new);

        let inner = cryptoki_sys::CK_SP800_108_FEEDBACK_KDF_PARAMS {
            prfType: prf_mechanism.into(),
            ulNumberOfDataParams: prf_data_params
                .len()
                .try_into()
                .expect("number of data parameters does not fit in CK_ULONG"),
            pDataParams: prf_data_params.as_ptr() as cryptoki_sys::CK_PRF_DATA_PARAM_PTR,
            ulIVLen: iv.map_or(0, |iv| {
                iv.len()
                    .try_into()
                    .expect("IV length does not fit in CK_ULONG")
            }),
            pIV: iv.map_or(ptr::null_mut(), |iv| iv.as_ptr() as *mut _),
            ulAdditionalDerivedKeys: additional_derived_keys.as_ref().map_or(0, |keys| {
                keys.len()
                    .try_into()
                    .expect("number of additional derived keys does not fit in CK_ULONG")
            }),
            pAdditionalDerivedKeys: additional_derived_keys
                .as_mut()
                .map_or(ptr::null_mut(), |keys| {
                    keys.as_mut_ptr() as cryptoki_sys::CK_DERIVED_KEY_PTR
                }),
        };

        Self {
            _additional_derived_keys: additional_derived_keys,

            inner,
            _marker: PhantomData,
        }
    }

    pub(crate) fn inner(&self) -> &cryptoki_sys::CK_SP800_108_FEEDBACK_KDF_PARAMS {
        &self.inner
    }
}
