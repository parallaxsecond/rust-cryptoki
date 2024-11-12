# Cryptoki Rust Wrapper

<p align="center">
  <a href="https://crates.io/crates/cryptoki"><img alt="Crates.io" src="https://img.shields.io/crates/v/cryptoki"></a>
  <a href="https://docs.rs/cryptoki"><img src="https://docs.rs/cryptoki/badge.svg" alt="Code documentation"/></a>
</p>

This is the high-level, Rust idiomatic wrapper crate for PKCS #11.

The items in this crate only expose idiomatic and safe Rust types and
functions to interface with the PKCS11 API. All the PKCS11 items might
not be implemented but everything that is implemented is safe.

## Example

The following example initializes an empty token and generates a new RSA key.

```rust
# fn main() -> testresult::TestResult {
use cryptoki::object::Attribute;
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use cryptoki::mechanism::Mechanism;

// initialize a new Pkcs11 object using the module from the env variable
let pkcs11 = Pkcs11::new(std::env::var("PKCS11_SOFTHSM2_MODULE")?)?;

pkcs11.initialize(CInitializeArgs::OsThreads)?;

let slot = pkcs11.get_slots_with_token()?[0];

// initialize a test token
let so_pin = AuthPin::new("abcdef".into());
pkcs11.init_token(slot, &so_pin, "Test Token")?;

let user_pin = AuthPin::new("fedcba".into());

// initialize user PIN
{
  let session = pkcs11.open_rw_session(slot)?;
  session.login(UserType::So, Some(&so_pin))?;
  session.init_pin(&user_pin)?;
}

// login as a user, the token has to be already initialized
let session = pkcs11.open_rw_session(slot)?;
session.login(UserType::User, Some(&user_pin))?;

// template of the public key
let pub_key_template = vec![
    Attribute::Token(true),
    Attribute::Private(false),
    Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
    Attribute::ModulusBits(1024.into()),
];

let priv_key_template = vec![Attribute::Token(true)];

// generate an RSA key according to passed templates
let (public, private) = session.generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &pub_key_template, &priv_key_template)?;
# Ok(()) }
```

## Conformance Notes

Throughout this crate, many functions and other items include additional
"**Conformance**" notes. These notes may provide guarantees about behavior or
additional, contextual information. In all cases, such items pertain
to information from the PKCS#11 standard and are contingent on the provider
being accessed through this crate conforming to that standard. That is, this
crate is permitted to *assume* these guarantees, and is does not necessarily
check for or enforce them itself.

## License

This project is licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this crate by you, as defined in the
Apache-2.0 license, shall be licensed as above, without any
additional terms or conditions.

*Copyright 2021 Contributors to the Parsec project.*
