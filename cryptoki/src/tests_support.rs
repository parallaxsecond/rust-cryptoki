// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{context::CInitializeArgs, context::Pkcs11, session::UserType, slot::Slot};
use nix::{
    sys::{
        stat,
        wait::{waitpid, WaitStatus::Exited},
    },
    unistd::{fork, mkdir, ForkResult},
};
use std::{env, fs, panic::UnwindSafe};
use tempfile::TempDir;

// The default user pin
pub static USER_PIN: &str = "fedcba";
// The default SO pin
pub static SO_PIN: &str = "abcdef";

trait TestFn: UnwindSafe {
    fn call(self, ctx: Pkcs11, slot: Slot);
}

impl TestFn for fn(Pkcs11, Slot) {
    fn call(self, ctx: Pkcs11, slot: Slot) {
        self(ctx, slot)
    }
}

impl TestFn for fn(Pkcs11, Slot) -> TestResult {
    fn call(self, ctx: Pkcs11, slot: Slot) {
        if let Err(e) = self(ctx, slot) {
            panic!("error: {:?}", e);
        }
    }
}

use testresult::TestResult;

#[allow(missing_docs)]
#[doc(hidden)]
pub fn test_with_hsm_result(test: fn(Pkcs11, Slot) -> TestResult) {
    test_in_subprocess(test);
}

#[allow(missing_docs)]
#[doc(hidden)]
pub fn test_with_hsm(test: fn(Pkcs11, Slot)) {
    test_in_subprocess(test);
}

#[allow(unused)]
fn test_in_subprocess<F: TestFn>(test: F) {
    // For isolation, every test is ran in their subprocess.
    // This is because we rely on softhsm2 and its configuration is passed via
    // the environment variable SOFTHSM2_CONF which is a global variable.
    // We can't have two threads set the variable to a different value.
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            match waitpid(child, None).unwrap() {
                Exited(_, 0) => {
                    // may success be upon you
                }
                Exited(_, 1) => {
                    panic!("child process failed");
                }
                _ => {
                    unimplemented!();
                }
            }
        }
        Ok(ForkResult::Child) => {
            match std::panic::catch_unwind(|| {
                child_main(test);
            }) {
                Ok(()) => {
                    std::process::exit(0);
                }
                Err(_) => {
                    std::process::exit(1);
                }
            };
        }
        Err(_) => panic!("Fork failed"),
    }
}

fn child_main<F: TestFn>(test: F) {
    let tmp_dir = TempDir::new().expect("create a tempdir");

    let conf_path = tmp_dir.path().join("softhsm2.conf");
    let data_path = tmp_dir.path().join("data");

    mkdir(&data_path, stat::Mode::S_IRWXU).expect("Create data dir");

    fs::write(
        conf_path.clone(),
        format!(
            r#"
                    directories.tokendir = {}
                    objectstore.backend = file
                    log.level = INFO
                "#,
            data_path.display()
        ),
    )
    .expect("Write the configuration file");

    std::env::set_var(
        "SOFTHSM2_CONF",
        conf_path.to_str().expect("non utf8 characters in path"),
    );

    let mut pkcs11 = Pkcs11::new(
        env::var("PKCS11_SOFTHSM2_MODULE")
            .unwrap_or_else(|_| "/usr/local/lib/softhsm/libsofthsm2.so".to_string()),
    )
    .expect("unable to open softhsm.so");

    // initialize the library
    pkcs11
        .initialize(CInitializeArgs::OsThreads)
        .expect("softhsm initialization failed");

    // find a slot, get the first one
    let slot = pkcs11
        .get_slots_with_token()
        .expect("Unable to list slots")
        .remove(0);

    pkcs11
        .init_token(slot, SO_PIN, "Test Token")
        .expect("token initialization failed");

    {
        // open a session
        let session = pkcs11
            .open_rw_session(slot)
            .expect("unable to open read/write sessions");
        // log in the session
        session
            .login(UserType::So, Some(SO_PIN))
            .expect("unable to login");
        session.init_pin(USER_PIN).expect("unable to set user pin");
    }

    // Run the test
    test.call(pkcs11, slot);
}
