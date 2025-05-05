// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::session::UserType;
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use std::env;

// The default user pin
pub static USER_PIN: &str = "fedcba";
// The default SO pin
pub static SO_PIN: &str = "abcdef";

fn get_token_label() -> Option<String> {
    env::var("TEST_TOKEN_LABEL").ok()
}

fn skip_token_init() -> bool {
    match env::var("TEST_SKIP_TOKEN_INIT") {
        Ok(s) => s == "1",
        Err(_) => false,
    }
}

fn get_pkcs11_path() -> String {
    env::var("TEST_PKCS11_MODULE")
        .unwrap_or_else(|_| "/usr/local/lib/softhsm/libsofthsm2.so".to_string())
}

pub fn is_softhsm() -> bool {
    get_pkcs11_path().contains("softhsm")
}

pub fn get_pkcs11() -> Pkcs11 {
    Pkcs11::new(get_pkcs11_path()).unwrap()
}

fn get_slot(pkcs11: &Pkcs11) -> Slot {
    // find a slot, get the first one or one with name specified in the environment variable
    let mut slots = pkcs11.get_slots_with_token().unwrap();
    match get_token_label() {
        None => slots.remove(0),
        Some(label) => {
            for s in slots {
                let ti = pkcs11.get_token_info(s).unwrap();
                if ti.label() == label {
                    return s;
                }
            }
            panic!("No token with Token Label `{label}` found");
        }
    }
}

pub fn init_pins() -> (Pkcs11, Slot) {
    let pkcs11 = get_pkcs11();

    // initialize the library
    pkcs11.initialize(CInitializeArgs::OsThreads).unwrap();

    let slot = get_slot(&pkcs11);

    if !skip_token_init() {
        let so_pin = AuthPin::new(SO_PIN.into());
        let _ = pkcs11.init_token(slot, &so_pin, "Test Token");
        {
            // open a session
            let session = pkcs11.open_rw_session(slot).unwrap();
            // log in the session
            session.login(UserType::So, Some(&so_pin)).unwrap();
            session.init_pin(&AuthPin::new(USER_PIN.into())).unwrap();
        }
    }

    (pkcs11, slot)
}
