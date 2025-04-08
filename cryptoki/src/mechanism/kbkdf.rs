// Copyright 2025 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Mechanisms of NIST key-based key derive functions (SP 800-108, informally KBKDF)
//! See: <https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061446>

use core::{convert::TryInto, marker::PhantomData, ptr, slice};

use cryptoki_sys::{
    CK_ATTRIBUTE, CK_ATTRIBUTE_PTR, CK_DERIVED_KEY, CK_DERIVED_KEY_PTR, CK_OBJECT_HANDLE,
    CK_PRF_DATA_PARAM, CK_PRF_DATA_PARAM_PTR, CK_SP800_108_BYTE_ARRAY, CK_SP800_108_COUNTER,
    CK_SP800_108_COUNTER_FORMAT, CK_SP800_108_DKM_LENGTH, CK_SP800_108_DKM_LENGTH_FORMAT,
    CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS, CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS,
    CK_SP800_108_ITERATION_VARIABLE, CK_ULONG,
};

use crate::object::Attribute;

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
/// Corresponds to CK_SP800_108_COUNTER_FORMAT.
#[derive(Debug, Clone, Copy)]
pub struct KbkdfCounterFormat {
    endianness: Endianness,
    width_in_bits: usize,
}

impl From<KbkdfCounterFormat> for CK_SP800_108_COUNTER_FORMAT {
    fn from(value: KbkdfCounterFormat) -> Self {
        Self {
            bLittleEndian: (value.endianness == Endianness::Little).into(),
            ulWidthInBits: value
                .width_in_bits
                .try_into()
                .expect("bit width of KBKDF internal counter does not fit in CK_ULONG"),
        }
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
/// Corresponds to CK_SP800_108_DKM_LENGTH_FORMAT.
#[derive(Debug, Clone, Copy)]
pub struct KbkdfDkmLengthFormat {
    dkm_length_method: DkmLengthMethod,
    endianness: Endianness,
    width_in_bits: usize,
}

impl From<KbkdfDkmLengthFormat> for CK_SP800_108_DKM_LENGTH_FORMAT {
    fn from(value: KbkdfDkmLengthFormat) -> Self {
        Self {
            dkmLengthMethod: match value.dkm_length_method {
                DkmLengthMethod::SumOfKeys => CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS,
                DkmLengthMethod::SumOfSegments => CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS,
            },
            bLittleEndian: (value.endianness == Endianness::Little).into(),
            ulWidthInBits: value
                .width_in_bits
                .try_into()
                .expect("bit width of KBKDF derived key material does not fit in CK_ULONG"),
        }
    }
}

/// A segment of input data for the PRF, to be used to construct a sequence of input.
///
/// Corresponds to CK_PRF_DATA_PARAM in the specific cases of the KDF operating in feedback- or double pipeline-mode.
#[derive(Debug, Clone, Copy)]
pub enum PrfDataParam<'a> {
    /// Identifies location of predefined iteration variable in constructed PRF input data.
    IterationVariable,
    /// Identifies location of counter in constructed PRF input data.
    Counter(KbkdfCounterFormat),
    /// Identifies location of DKM (derived key material) length in constructed PRF input data.
    DkmLength(KbkdfDkmLengthFormat),
    /// Identifies location and value of byte array of data in constructed PRF input data.
    ByteArray(&'a [u8]),
}

/// A segment of input data for the PRF, to be used to construct a sequence of input.
///
/// Corresponds to CK_PRF_DATA_PARAM in the specific case of the KDF operating in counter-mode.
#[derive(Debug, Clone, Copy)]
pub enum PrfCounterDataParam<'a> {
    /// Identifies location of iteration variable (a counter in this case) in constructed PRF input data.
    IterationVariable(KbkdfCounterFormat),
    /// Identifies location of DKM (derived key material) length in constructed PRF input data.
    DkmLength(KbkdfDkmLengthFormat),
    /// Identifies location and value of byte array of data in constructed PRF input data.
    ByteArray(&'a [u8]),
}

/// Parameters for additional key to be derived from base key.
#[derive(Debug, Clone, Copy)]
pub struct DerivedKey<'a> {
    template: &'a [Attribute],
    object_handle: CK_OBJECT_HANDLE,
}

impl<'a> DerivedKey<'a> {
    /// Construct template for additional key to be derived by KDF.
    ///
    /// # Arguments
    ///
    /// * `template` - The template for the key to be derived.
    pub fn new(template: &'a [Attribute]) -> Self {
        Self {
            template,
            object_handle: 0,
        }
    }
}

/// NIST SP 800-108 (aka KBKDF) counter-mode parameters.
///
/// This structure wraps a `CK_SP800_108_KDF_PARAMS` structure.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct KbkdfCounterParams<'a> {
    inner: cryptoki_sys::CK_SP800_108_KDF_PARAMS,
    /// Marker type to ensure we don't outlive the data
    _marker: PhantomData<&'a [u8]>,
}

impl<'a> KbkdfCounterParams<'a> {
    /// Construct parameters for NIST SP 800-108 KDF (aka KBKDF) pseuderandom function-based key
    /// derivation function, in counter-mode.
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
        prf_data_params: Vec<PrfDataParam<'a>>,
        mut additional_derived_keys: Vec<DerivedKey<'a>>,
    ) -> Self {
        let prf_data_params: Vec<CK_PRF_DATA_PARAM> =
            prf_data_params.iter().map(Into::into).collect();
        let additional_derived_keys: Vec<CK_DERIVED_KEY> =
            additional_derived_keys.iter_mut().map(Into::into).collect();

        Self {
            inner: cryptoki_sys::CK_SP800_108_KDF_PARAMS {
                prfType: prf_mechanism.into(),
                ulNumberOfDataParams: prf_data_params
                    .len()
                    .try_into()
                    .expect("number of data parameters does not fit in CK_ULONG"),
                pDataParams: prf_data_params.as_ptr() as CK_PRF_DATA_PARAM_PTR,
                ulAdditionalDerivedKeys: additional_derived_keys
                    .len()
                    .try_into()
                    .expect("number of additional derived keys does not fit in CK_ULONG"),
                pAdditionalDerivedKeys: additional_derived_keys.as_ptr() as CK_DERIVED_KEY_PTR,
            },
            _marker: PhantomData,
        }
    }

    /// The additional keys derived by the KDF, as per the params
    pub fn additional_derived_keys(&self) -> Vec<CK_OBJECT_HANDLE> {
        let derived_keys = unsafe {
            slice::from_raw_parts(
                self.inner.pAdditionalDerivedKeys,
                self.inner.ulAdditionalDerivedKeys as _,
            )
        };

        unsafe {
            derived_keys
                .iter()
                .map(|derived_key| *derived_key.phKey)
                .collect()
        }
    }
}

/// NIST SP 800-108 (aka KBKDF) feedback-mode parameters.
///
/// This structure wraps a `CK_SP800_108_FEEDBACK_KDF_PARAMS` structure.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct KbkdfFeedbackParams<'a> {
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
    /// * `prf_data_params` - The sequence of data segments used as input data for the PRF. Requires at least [`PrfCounterDataParam::IterationVariable`].
    ///
    /// * `iv` - The IV to be used for the feedback-mode KDF.
    ///
    /// * `additional_derived_keys` - Any additional keys to be generated by the KDF from the base key.
    pub fn new(
        prf_mechanism: MechanismType,
        prf_data_params: Vec<PrfDataParam<'a>>,
        iv: Option<&'a [u8]>,
        mut additional_derived_keys: Vec<DerivedKey<'a>>,
    ) -> Self {
        let prf_data_params: Vec<CK_PRF_DATA_PARAM> =
            prf_data_params.iter().map(Into::into).collect();
        let additional_derived_keys: Vec<CK_DERIVED_KEY> =
            additional_derived_keys.iter_mut().map(Into::into).collect();

        Self {
            inner: cryptoki_sys::CK_SP800_108_FEEDBACK_KDF_PARAMS {
                prfType: prf_mechanism.into(),
                ulNumberOfDataParams: prf_data_params
                    .len()
                    .try_into()
                    .expect("number of data parameters does not fit in CK_ULONG"),
                pDataParams: prf_data_params.as_ptr() as CK_PRF_DATA_PARAM_PTR,
                ulIVLen: iv.map_or(0, |iv| {
                    iv.len()
                        .try_into()
                        .expect("IV length does not fit in CK_ULONG")
                }),
                pIV: iv.map_or(ptr::null_mut(), |iv| iv.as_ptr() as *mut _),
                ulAdditionalDerivedKeys: additional_derived_keys
                    .len()
                    .try_into()
                    .expect("number of additional derived keys does not fit in CK_ULONG"),
                pAdditionalDerivedKeys: additional_derived_keys.as_ptr() as CK_DERIVED_KEY_PTR,
            },
            _marker: PhantomData,
        }
    }

    /// The additional keys derived by the KDF, as per the params
    pub fn additional_derived_keys(&self) -> Vec<CK_OBJECT_HANDLE> {
        let derived_keys = unsafe {
            slice::from_raw_parts(
                self.inner.pAdditionalDerivedKeys,
                self.inner.ulAdditionalDerivedKeys as _,
            )
        };

        unsafe {
            derived_keys
                .iter()
                .map(|derived_key| *derived_key.phKey)
                .collect()
        }
    }
}

/// NIST SP 800-108 (aka KBKDF) double pipeline-mode parameters.
///
/// This structure wraps a `CK_SP800_108_KDF_PARAMS` structure.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct KbkdfDoublePipelineParams<'a> {
    inner: cryptoki_sys::CK_SP800_108_KDF_PARAMS,
    /// Marker type to ensure we don't outlive the data
    _marker: PhantomData<&'a [u8]>,
}

impl<'a> KbkdfDoublePipelineParams<'a> {
    /// Construct parameters for NIST SP 800-108 KDF (aka KBKDF) pseuderandom function-based key
    /// derivation function, in double pipeline-mode.
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
        prf_data_params: Vec<PrfDataParam<'a>>,
        mut additional_derived_keys: Vec<DerivedKey<'a>>,
    ) -> Self {
        let prf_data_params: Vec<CK_PRF_DATA_PARAM> =
            prf_data_params.iter().map(Into::into).collect();
        let additional_derived_keys: Vec<CK_DERIVED_KEY> =
            additional_derived_keys.iter_mut().map(Into::into).collect();

        Self {
            inner: cryptoki_sys::CK_SP800_108_KDF_PARAMS {
                prfType: prf_mechanism.into(),
                ulNumberOfDataParams: prf_data_params
                    .len()
                    .try_into()
                    .expect("number of data parameters does not fit in CK_ULONG"),
                pDataParams: prf_data_params.as_ptr() as CK_PRF_DATA_PARAM_PTR,
                ulAdditionalDerivedKeys: additional_derived_keys
                    .len()
                    .try_into()
                    .expect("number of additional derived keys does not fit in CK_ULONG"),
                pAdditionalDerivedKeys: additional_derived_keys.as_ptr() as CK_DERIVED_KEY_PTR,
            },
            _marker: PhantomData,
        }
    }

    /// The additional keys derived by the KDF, as per the params
    pub fn additional_derived_keys(&self) -> Vec<CK_OBJECT_HANDLE> {
        let derived_keys = unsafe {
            slice::from_raw_parts(
                self.inner.pAdditionalDerivedKeys,
                self.inner.ulAdditionalDerivedKeys as _,
            )
        };

        unsafe {
            derived_keys
                .iter()
                .map(|derived_key| *derived_key.phKey)
                .collect()
        }
    }
}

impl<'a> From<&PrfDataParam<'a>> for CK_PRF_DATA_PARAM {
    fn from(value: &PrfDataParam<'a>) -> Self {
        Self {
            type_: match value {
                PrfDataParam::IterationVariable => CK_SP800_108_ITERATION_VARIABLE,
                PrfDataParam::Counter(_) => CK_SP800_108_COUNTER,
                PrfDataParam::DkmLength(_) => CK_SP800_108_DKM_LENGTH,
                PrfDataParam::ByteArray(_) => CK_SP800_108_BYTE_ARRAY,
            },
            pValue: match value {
                PrfDataParam::IterationVariable => ptr::null_mut(),
                PrfDataParam::Counter(inner) => inner as *const _ as *mut _,
                PrfDataParam::DkmLength(inner) => inner as *const _ as *mut _,
                PrfDataParam::ByteArray(data) => data.as_ptr() as *mut _,
            },
            ulValueLen: match value {
                PrfDataParam::IterationVariable => 0,
                PrfDataParam::Counter(_) => size_of::<CK_SP800_108_COUNTER_FORMAT>() as CK_ULONG,
                PrfDataParam::DkmLength(_) => {
                    size_of::<CK_SP800_108_DKM_LENGTH_FORMAT>() as CK_ULONG
                }
                PrfDataParam::ByteArray(data) => data
                    .len()
                    .try_into()
                    .expect("length of data parameter does not fit in CK_ULONG"),
            },
        }
    }
}

impl<'a> From<&PrfCounterDataParam<'a>> for CK_PRF_DATA_PARAM {
    fn from(value: &PrfCounterDataParam<'a>) -> Self {
        Self {
            type_: match value {
                PrfCounterDataParam::IterationVariable(_) => CK_SP800_108_ITERATION_VARIABLE,
                PrfCounterDataParam::DkmLength(_) => CK_SP800_108_DKM_LENGTH,
                PrfCounterDataParam::ByteArray(_) => CK_SP800_108_BYTE_ARRAY,
            },
            pValue: match value {
                PrfCounterDataParam::IterationVariable(inner) => inner as *const _ as *mut _,
                PrfCounterDataParam::DkmLength(inner) => inner as *const _ as *mut _,
                PrfCounterDataParam::ByteArray(data) => data.as_ptr() as *mut _,
            },
            ulValueLen: match value {
                PrfCounterDataParam::IterationVariable(_) => {
                    size_of::<CK_SP800_108_COUNTER_FORMAT>() as CK_ULONG
                }
                PrfCounterDataParam::DkmLength(_) => {
                    size_of::<CK_SP800_108_DKM_LENGTH_FORMAT>() as CK_ULONG
                }
                PrfCounterDataParam::ByteArray(data) => data
                    .len()
                    .try_into()
                    .expect("length of data parameter does not fit in CK_ULONG"),
            },
        }
    }
}

impl<'a> From<&mut DerivedKey<'a>> for CK_DERIVED_KEY {
    fn from(value: &mut DerivedKey<'a>) -> Self {
        let template: Vec<CK_ATTRIBUTE> = value.template.iter().map(Into::into).collect();

        Self {
            pTemplate: template.as_ptr() as CK_ATTRIBUTE_PTR,
            ulAttributeCount: template
                .len()
                .try_into()
                .expect("number of attributes in template does not fit in CK_ULONG"),
            phKey: &mut value.object_handle,
        }
    }
}
