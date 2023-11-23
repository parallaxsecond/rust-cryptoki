// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use cryptoki::{
    object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle},
    session::Session,
};
use der::{asn1::ObjectIdentifier, oid::AssociatedOid, Any, AnyRef};
use rsa::{
    pkcs1::{self, RsaPssParams},
    pkcs8::{self},
    pss::{Signature, VerifyingKey},
    BigUint, RsaPublicKey,
};
use signature::digest::Digest;
use spki::{
    AlgorithmIdentifierOwned, AlgorithmIdentifierRef, AssociatedAlgorithmIdentifier,
    DynSignatureAlgorithmIdentifier,
};
use std::convert::TryFrom;

use super::{DigestSigning, Error};

pub struct Signer<D: DigestSigning> {
    session: Session,
    _public_key: ObjectHandle,
    private_key: ObjectHandle,
    verifying_key: VerifyingKey<D>,
    salt_len: usize,
}

impl<D: DigestSigning> Signer<D> {
    pub fn new(session: Session, label: &[u8]) -> Result<Self, Error> {
        // First we'll lookup a private key with that label.
        let template = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Label(label.to_vec()),
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(KeyType::RSA),
            Attribute::Sign(true),
        ];

        let private_key = session.find_objects(&template)?.remove(0);
        let attribute_pk = session.get_attributes(
            private_key,
            &[AttributeType::Modulus, AttributeType::PublicExponent],
        )?;

        // Second we'll lookup a public key with the same label/modulus/public exponent
        let mut template = vec![
            Attribute::Private(false),
            Attribute::Label(label.to_vec()),
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::KeyType(KeyType::RSA),
        ];
        let mut modulus = None;
        let mut public_exponent = None;
        for attribute in attribute_pk {
            match attribute {
                Attribute::Modulus(m) if modulus.is_none() => {
                    modulus = Some(m.clone());
                    template.push(Attribute::Modulus(m));
                }
                Attribute::PublicExponent(e) if public_exponent.is_none() => {
                    public_exponent = Some(e.clone());
                    template.push(Attribute::PublicExponent(e));
                }
                _ => {}
            }
        }

        let modulus = modulus
            .ok_or(Error::MissingAttribute(AttributeType::Modulus))
            .map(|v| BigUint::from_bytes_be(v.as_slice()))?;
        let public_exponent = public_exponent
            .ok_or(Error::MissingAttribute(AttributeType::PublicExponent))
            .map(|v| BigUint::from_bytes_be(v.as_slice()))?;

        let public_key = session.find_objects(&template)?.remove(0);

        let verifying_key = VerifyingKey::new(RsaPublicKey::new(modulus, public_exponent)?);
        let salt_len = <D as Digest>::output_size();

        Ok(Self {
            session,
            private_key,
            _public_key: public_key,
            verifying_key,
            salt_len,
        })
    }

    pub fn into_session(self) -> Session {
        self.session
    }
}

impl<D: DigestSigning> AssociatedAlgorithmIdentifier for Signer<D> {
    type Params = AnyRef<'static>;
    const ALGORITHM_IDENTIFIER: AlgorithmIdentifierRef<'static> = pkcs1::ALGORITHM_ID;
}

impl<D: DigestSigning> signature::Keypair for Signer<D> {
    type VerifyingKey = VerifyingKey<D>;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.verifying_key.clone()
    }
}

impl<D: DigestSigning> signature::Signer<Signature> for Signer<D> {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        let bytes = self
            .session
            .sign(&D::pss_mechanism(), self.private_key, msg)
            .map_err(Error::Cryptoki)
            .map_err(Box::new)
            .map_err(signature::Error::from_source)?;

        let signature = Signature::try_from(bytes.as_slice())?;

        Ok(signature)
    }
}

impl<D: DigestSigning> DynSignatureAlgorithmIdentifier for Signer<D> {
    fn signature_algorithm_identifier(&self) -> pkcs8::spki::Result<AlgorithmIdentifierOwned> {
        get_pss_signature_algo_id::<D>(self.salt_len as u8)
    }
}

fn get_pss_signature_algo_id<D>(salt_len: u8) -> pkcs8::spki::Result<AlgorithmIdentifierOwned>
where
    D: Digest + AssociatedOid,
{
    const ID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");

    let pss_params = RsaPssParams::new::<D>(salt_len);

    Ok(AlgorithmIdentifierOwned {
        oid: ID_RSASSA_PSS,
        parameters: Some(Any::encode_from(&pss_params)?),
    })
}
