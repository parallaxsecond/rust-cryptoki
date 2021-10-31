// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use cryptoki::context::{Pkcs11,CInitializeArgs};
use cryptoki::session::UserType;
use cryptoki::slot::Slot;
use cryptoki::session::SessionFlags;
use std::env;

// The default user pin
pub static USER_PIN: &str = "fedcba";
// The default SO pin
pub static SO_PIN: &str = "abcdef";

pub fn init_pins() -> (Pkcs11, Slot) {
    let pkcs11 = Pkcs11::new(
        env::var("PKCS11_SOFTHSM2_MODULE")
            .unwrap_or_else(|_| "/usr/local/lib/softhsm/libsofthsm2.so".to_string()),
    )
    .unwrap();

    // initialize the library
    pkcs11.initialize(CInitializeArgs::OsThreads).unwrap();

    // find a slot, get the first one
    let slot = pkcs11.get_slots_with_token().unwrap().remove(0);

    pkcs11.init_token(slot, SO_PIN, "Test Token").unwrap();

    // set flags
    let mut flags = SessionFlags::new();
    let _ = flags.set_rw_session(true).set_serial_session(true);

    {
        // open a session
        let session = pkcs11.open_session_no_callback(slot, flags).unwrap();
        // log in the session
        session.login(UserType::So, Some(SO_PIN)).unwrap();
        session.init_pin(USER_PIN).unwrap();
    }

    (pkcs11, slot)
}
