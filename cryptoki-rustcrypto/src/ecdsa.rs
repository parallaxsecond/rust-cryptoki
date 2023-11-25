// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use cryptoki::{
    mechanism::Mechanism,
    object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle},
};
use der::{
    asn1::{ObjectIdentifier, OctetStringRef},
    oid::AssociatedOid,
    AnyRef, Decode, Encode,
};
use ecdsa::{
    elliptic_curve::{
        generic_array::ArrayLength,
        sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
        AffinePoint, CurveArithmetic, FieldBytesSize, PublicKey,
    },
    hazmat::DigestPrimitive,
    PrimeCurve, Signature, VerifyingKey,
};
use signature::digest::Digest;
use spki::{
    AlgorithmIdentifier, AlgorithmIdentifierRef, AssociatedAlgorithmIdentifier,
    SignatureAlgorithmIdentifier,
};
use std::{convert::TryFrom, ops::Add};
use thiserror::Error;

use crate::SessionLike;

pub fn read_key<S: SessionLike, C: SignAlgorithm>(
    session: &S,
    template: impl Into<Vec<Attribute>>,
) -> Result<PublicKey<C>, Error>
where
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    let mut template = template.into();
    template.push(Attribute::Class(ObjectClass::PUBLIC_KEY));
    template.push(Attribute::KeyType(KeyType::EC));
    template.push(Attribute::EcParams(C::OID.to_der().unwrap()));

    let keys = session.find_objects(&template)?;
    if let Some(public_key) = keys.first() {
        let attribute_pub = session.get_attributes(*public_key, &[AttributeType::EcPoint])?;

        let mut ec_point = None;
        for attribute in attribute_pub {
            match attribute {
                Attribute::EcPoint(p) if ec_point.is_none() => {
                    ec_point = Some(p);
                    break;
                }
                _ => {}
            }
        }

        let ec_point = ec_point.ok_or(Error::MissingAttribute(AttributeType::EcPoint))?;

        // documented as "DER-encoding of ANSI X9.62 ECPoint value Q"
        // https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203418
        // https://www.rfc-editor.org/rfc/rfc5480#section-2.2
        let ec_point = OctetStringRef::from_der(&ec_point).unwrap();

        Ok(PublicKey::<C>::from_sec1_bytes(ec_point.as_bytes())?)
    } else {
        Err(Error::MissingKey)
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Cryptoki error: {0}")]
    Cryptoki(#[from] cryptoki::error::Error),

    #[error("Private key missing attribute: {0}")]
    MissingAttribute(AttributeType),

    #[error("Elliptic curve error: {0}")]
    Ecdsa(#[from] ecdsa::elliptic_curve::Error),

    #[error("Key not found")]
    MissingKey,
}

pub trait SignAlgorithm: PrimeCurve + CurveArithmetic + AssociatedOid + DigestPrimitive {
    fn sign_mechanism() -> Mechanism<'static>;
}

macro_rules! impl_sign_algorithm {
    ($ec:ty) => {
        impl SignAlgorithm for $ec {
            fn sign_mechanism() -> Mechanism<'static> {
                Mechanism::Ecdsa
            }
        }
    };
}

impl_sign_algorithm!(p224::NistP224);
impl_sign_algorithm!(p256::NistP256);
impl_sign_algorithm!(p384::NistP384);
impl_sign_algorithm!(k256::Secp256k1);

pub struct Signer<C: SignAlgorithm, S: SessionLike> {
    session: S,
    private_key: ObjectHandle,
    verifying_key: VerifyingKey<C>,
}

impl<C: SignAlgorithm, S: SessionLike> Signer<C, S>
where
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    pub fn new(session: S, label: &[u8]) -> Result<Self, Error> {
        // First we'll lookup a private key with that label.
        let template = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Label(label.to_vec()),
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(KeyType::EC),
            Attribute::EcParams(C::OID.to_der().unwrap()),
            Attribute::Sign(true),
        ];

        let private_key = session.find_objects(&template)?.remove(0);
        let attribute_priv = session.get_attributes(private_key, &[AttributeType::Id])?;

        // Second we'll lookup a public key with the same label/ec params/ec point
        let mut template = vec![Attribute::Private(false), Attribute::Label(label.to_vec())];
        let mut id = None;
        for attribute in attribute_priv {
            match attribute {
                Attribute::Id(i) if id.is_none() => {
                    template.push(Attribute::Id(i.clone()));
                    id = Some(i);
                }
                _ => {}
            }
        }

        id.ok_or(Error::MissingAttribute(AttributeType::Id))?;

        let public = read_key(&session, template)?;
        let verifying_key = public.into();

        Ok(Self {
            session,
            private_key,
            verifying_key,
        })
    }

    pub fn into_session(self) -> S {
        self.session
    }
}

impl<C: SignAlgorithm, S: SessionLike> AssociatedAlgorithmIdentifier for Signer<C, S>
where
    C: AssociatedOid,
{
    type Params = ObjectIdentifier;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifier<ObjectIdentifier> =
        PublicKey::<C>::ALGORITHM_IDENTIFIER;
}

impl<C: SignAlgorithm, S: SessionLike> signature::Keypair for Signer<C, S> {
    type VerifyingKey = VerifyingKey<C>;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.verifying_key
    }
}

impl<C: SignAlgorithm, S: SessionLike> signature::Signer<Signature<C>> for Signer<C, S>
where
    <<C as ecdsa::elliptic_curve::Curve>::FieldBytesSize as Add>::Output: ArrayLength<u8>,
{
    fn try_sign(&self, msg: &[u8]) -> Result<Signature<C>, signature::Error> {
        println!("try sign");

        let msg = C::Digest::digest(msg);

        let bytes = self
            .session
            .sign(&C::sign_mechanism(), self.private_key, &msg)
            .map_err(Error::Cryptoki)
            .map_err(Box::new)
            .map_err(signature::Error::from_source)?;

        let signature = Signature::try_from(bytes.as_slice())?;

        Ok(signature)
    }
}

impl<C: SignAlgorithm, S: SessionLike> SignatureAlgorithmIdentifier for Signer<C, S>
where
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
    Signature<C>: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Params = AnyRef<'static>;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifierRef<'static> =
        Signature::<C>::ALGORITHM_IDENTIFIER;
}
