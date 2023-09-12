mod common;
use crate::common::USER_PIN;
use common::init_pins;
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource};
use cryptoki::object::Attribute;
use cryptoki::session::UserType;
use std::error::Error;
use cryptoki::types::AuthPin;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption() -> Result<(), Box<dyn Error>> {
        let (pkcs11, slot) = init_pins();

        // open a session
        let session = pkcs11.open_rw_session(slot)?;

        // log in the session
        session.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))?;
        let pub_key_template = [Attribute::ModulusBits(2048.into())];
        let (pubkey, _privkey) = session.generate_key_pair(&Mechanism::RsaPkcsKeyPairGen,
                                                           &pub_key_template, &[])?;
        let oaep = PkcsOaepParams::new(MechanismType::SHA1, PkcsMgfType::MGF1_SHA1, PkcsOaepSource::empty());
        let encrypt_mechanism: Mechanism = Mechanism::RsaPkcsOaep(oaep);
        let encrypted_data = session.encrypt(&encrypt_mechanism, pubkey, b"Hello")?;

        let decrypted_data = session.decrypt(&encrypt_mechanism, _privkey, &encrypted_data)?;
        let decrypted = String::from_utf8(decrypted_data)?;
        assert_eq!("Hello", decrypted);


        Ok(())
    }
}
use std::env; //To set Environment Variable if softhsm isn't initialised in the system

fn main() {
    let key = "SOFTHSM2_CONF";
    let value = "C:\\SoftHSM2\\etc\\softhsm2.conf";

    // Set the environment variable for the current process
    env::set_var(key, value);

    // Verify that the environment variable is set
    match env::var(key) {
        Ok(val) => println!("{} = {}", key, val),
        Err(_) => println!("{} is not set", key),
    }
}


