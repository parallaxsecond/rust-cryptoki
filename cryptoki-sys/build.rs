// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
fn main() {
    #[cfg(feature = "generate-bindings")]
    {
        generate_bindings();
    }

    #[cfg(not(feature = "generate-bindings"))]
    {
        use std::str::FromStr;
        use target_lexicon::{Architecture, OperatingSystem, Triple};

        let target = Triple::from_str(&std::env::var("TARGET").unwrap())
            .expect("Failed to parse target triple");
        match (target.architecture, target.operating_system) {
            (Architecture::Arm(_), OperatingSystem::Linux) => {}
            (Architecture::Aarch64(_), OperatingSystem::Linux) => {}
            (Architecture::X86_64, OperatingSystem::Linux) => {}
            (Architecture::X86_32(_), OperatingSystem::Linux) => {}
            (Architecture::Powerpc64, OperatingSystem::Linux) => {}
            (Architecture::Powerpc64le, OperatingSystem::Linux) => {}
            (Architecture::X86_64, OperatingSystem::Darwin) => {}
            (Architecture::X86_64, OperatingSystem::Windows) => {}
            (arch, os) => {
                panic!("Compilation target (architecture, OS) tuple ({}, {}) is not part of the supported tuples. Please compile with the \"generate-bindings\" feature or add support for your platform :)", arch, os);
            }
        }
    }
}

// Only on a specific feature
#[cfg(feature = "generate-bindings")]
fn generate_bindings() {
    let bindings = bindgen::Builder::default()
        .header("pkcs11.h")
        .dynamic_library_name("Pkcs11")
        // The PKCS11 library works in a slightly different way to most shared libraries. We have
        // to call `C_GetFunctionList`, which returns a list of pointers to the _actual_ library
        // functions. This is the only function we need to create a binding for.
        .whitelist_function("C_GetFunctionList")
        // This is needed because no types will be generated if `whitelist_function` is used.
        // Unsure if this is a bug.
        .whitelist_type("*")
        // See this issue: https://github.com/parallaxsecond/rust-cryptoki/issues/12
        .blacklist_type("max_align_t")
        // Derive the `Debug` trait for the generated structs where possible.
        .derive_debug(true)
        // Derive the `Default` trait for the generated structs where possible.
        .derive_default(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/pkcs11_bindings.rs file.
    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("pkcs11_bindings.rs"))
        .expect("Couldn't write bindings!");
}
