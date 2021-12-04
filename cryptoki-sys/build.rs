// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
fn main() {
    #[cfg(feature = "generate-bindings")]
    {
        generate_bindings::generate_bindings();
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

#[cfg(feature = "generate-bindings")]
mod generate_bindings {
    use bindgen::callbacks::{IntKind, MacroParsingBehavior, ParseCallbacks};
    use bindgen::Builder;

    #[derive(Debug)]
    struct CustomCallbacks;
    impl ParseCallbacks for CustomCallbacks {
        // Specify preprocessor macros (of any type) that shouldn't appear in
        // the bindings
        fn will_parse_macro(&self, name: &str) -> MacroParsingBehavior {
            match name {
                // This type is defined for the sake of conforming to the
                // expected header content, but is never actually used.
                "NULL_PTR"

                // These are include guards that are set to 1 instaed of just
                // being checked ad defined.

                | "_PKCS11_H_"
                | "_PKCS11T_H_"

                // Conditionally defined versions of booleans outside
                // the "CK_" namespace
                | "FALSE"
                | "TRUE"

                // Convenience values for C clients that aren't
                // actually part of the spandard.
                | "CRYPTOKI_VERSION_MAJOR"
                | "CRYPTOKI_VERSION_MINOR"
                | "CRYPTOKI_VERSION_AMENDMENT"

                // Miscellaneous deprecated types
                | "CKK_ECDSA"
                | "CKA_ECDSA_PARAMS"
                | "CKA_SECONDARY_AUTH"
                | "CKA_AUTH_PIN_FLAGS"
                | "CKM_ECDSA_KEY_PAIR_GEN"

                // This type is a synonym for
                // CKA_SUBPRIME_BITS which is the
                // spelling that appears in the standard.
                | "CKA_SUB_PRIME_BITS"

                // Deprecated names, all of which have
                // identical "CAST128" spellings
                | "CKK_CAST5"
                | "CKM_CAST5_CBC"
                | "CKM_CAST5_MAC"
                | "CKM_CAST5_MAC_GENERAL"
                | "CKM_CAST5_CBC_PAD"
                | "CKM_PBE_MD5_CAST5_CBC"
                | "CKM_PBE_SHA1_CAST5_CBC"

                // Duplicate names like those above
                // but not explicitly marked as deprecated
                | "CKM_CAST5_KEY_GEN"
                | "CKM_CAST5_ECB" => MacroParsingBehavior::Ignore,
                _ => MacroParsingBehavior::Default,
            }
        }
        // Specify the C type of any integral preprocessor definitions
        fn int_macro(&self, name: &str, _value: i64) -> Option<IntKind> {
            match name {
                "CK_TRUE" | "CK_FALSE" => Some(IntKind::U8),
                _ => Some(IntKind::ULong),
            }
        }
    }

    // Only on a specific feature
    pub(super) fn generate_bindings() {
        let bindings = Builder::default()
            .header("rust-pkcs11.h")
            .dynamic_library_name("Pkcs11")
            // The PKCS11 library works in a slightly different way to most shared libraries. We have
            // to call `C_GetFunctionList`, which returns a list of pointers to the _actual_ library
            // functions. This is the only function we need to create a binding for.
            .allowlist_function("C_GetFunctionList")
            // Include types (e.g., structs) and constants (#define'd)
            .allowlist_type("*")
            .allowlist_var("*")
            // Two deprecated structs and their respective pointer types
            .blocklist_type("CK_AES_CCM_PARAMS")
            .blocklist_type("CK_AES_GCM_PARAMS")
            .blocklist_type("CK_AES_CCM_PARAMS_PTR")
            .blocklist_type("CK_AES_GCM_PARAMS_PTR")
            // Derive the `Debug` trait for the generated structs where possible.
            .derive_debug(true)
            // Derive the `Default` trait for the generated structs where possible.
            .derive_default(true)
            .parse_callbacks(Box::new(CustomCallbacks))
            .generate()
            .expect("Unable to generate bindings");

        // Write the bindings to the $OUT_DIR/pkcs11_bindings.rs file.
        let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
        bindings
            .write_to_file(out_path.join("pkcs11_bindings.rs"))
            .expect("Couldn't write bindings!");
    }
}
