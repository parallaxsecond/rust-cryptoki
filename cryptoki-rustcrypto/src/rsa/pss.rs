// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use der::{asn1::ObjectIdentifier, oid::AssociatedOid, Any, AnyRef};
use rsa::{
    pkcs1::{self, RsaPssParams},
    pkcs8::{self},
    pss::{Signature, VerifyingKey},
};
use signature::digest::Digest;
use spki::{
    AlgorithmIdentifierOwned, AlgorithmIdentifierRef, AssociatedAlgorithmIdentifier,
    DynSignatureAlgorithmIdentifier,
};
use std::convert::TryFrom;

use super::{read_key, DigestSigning, Error};
use crate::SessionLike;

pub struct Signer<D: DigestSigning, S: SessionLike> {
    session: S,
    private_key: ObjectHandle,
    verifying_key: VerifyingKey<D>,
    salt_len: usize,
}

impl<D: DigestSigning, S: SessionLike> Signer<D, S> {
    pub fn new(session: S, label: &[u8]) -> Result<Self, Error> {
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
        let attribute_priv = session.get_attributes(
            private_key,
            &[AttributeType::Modulus, AttributeType::PublicExponent],
        )?;

        // Second we'll lookup a public key with the same label/modulus/public exponent
        let mut template = vec![Attribute::Private(false), Attribute::Label(label.to_vec())];
        let mut modulus = None;
        let mut public_exponent = None;
        for attribute in attribute_priv {
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

        let public_key = read_key(&session, template)?;

        let verifying_key = VerifyingKey::new(public_key);
        let salt_len = <D as Digest>::output_size();

        Ok(Self {
            session,
            private_key,
            verifying_key,
            salt_len,
        })
    }

    pub fn into_session(self) -> S {
        self.session
    }
}

impl<D: DigestSigning, S: SessionLike> AssociatedAlgorithmIdentifier for Signer<D, S> {
    type Params = AnyRef<'static>;
    const ALGORITHM_IDENTIFIER: AlgorithmIdentifierRef<'static> = pkcs1::ALGORITHM_ID;
}

impl<D: DigestSigning, S: SessionLike> signature::Keypair for Signer<D, S> {
    type VerifyingKey = VerifyingKey<D>;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.verifying_key.clone()
    }
}

impl<D: DigestSigning, S: SessionLike> signature::Signer<Signature> for Signer<D, S> {
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

impl<D: DigestSigning, S: SessionLike> DynSignatureAlgorithmIdentifier for Signer<D, S> {
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
