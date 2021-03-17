// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use cryptoki::types::locking::CInitializeArgs;
use cryptoki::types::session::UserType;
use cryptoki::types::slot_token::Slot;
use cryptoki::types::Flags;
use cryptoki::Pkcs11;
use std::env;

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

    pkcs11.init_token(slot, "1234").unwrap();
    pkcs11.set_pin(slot, "1234").unwrap();

    // set flags
    let mut flags = Flags::new();
    let _ = flags.set_rw_session(true).set_serial_session(true);

    {
        // open a session
        let session = pkcs11.open_session_no_callback(slot, flags).unwrap();
        // log in the session
        session.login(UserType::So).unwrap();
        session.init_pin("1234").unwrap();
    }

    (pkcs11, slot)
}
