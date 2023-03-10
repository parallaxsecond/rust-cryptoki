// Copyright 2021,2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
fn main() {
    #[cfg(feature = "generate-bindings")]
    {
        generate::generate_bindings();
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
            (Architecture::Aarch64(_), OperatingSystem::Darwin) => {}
            (Architecture::X86_64, OperatingSystem::Windows) => {}
            (Architecture::X86_64, OperatingSystem::Freebsd) => {}
            (arch, os) => {
                panic!("Compilation target (architecture, OS) tuple ({}, {}) is not part of the supported tuples. Please compile with the \"generate-bindings\" feature or add support for your platform :)", arch, os);
            }
        }
    }
}

// Only on a specific feature
#[cfg(feature = "generate-bindings")]
mod generate {
    use bindgen::callbacks;
    #[derive(Debug)]
    pub struct CargoCallbacks;

    impl callbacks::ParseCallbacks for CargoCallbacks {
        fn int_macro(&self, name: &str, _: i64) -> Option<callbacks::IntKind> {
            let prefixes = [
                ("CK_", "CK_ULONG"),
                ("CKA_", "CK_ATTRIBUTE_TYPE"),
                ("CKC_", "CK_CERTIFICATE_TYPE"),
                ("CKD_", "CK_EC_KDF_TYPE"),
                ("CKF_", "CK_FLAGS"),
                ("CKG_MGF1_", "CK_RSA_PKCS_MGF_TYPE"),
                ("CKH_", "CK_HW_FEATURE_TYPE"),
                ("CKK_", "CK_KEY_TYPE"),
                ("CKM_", "CK_MECHANISM_TYPE"),
                ("CKN_", "CK_NOTIFICATION"),
                ("CKO_", "CK_OBJECT_CLASS"),
                ("CKP_", "CK_PROFILE_ID"),
                ("CKR_", "CK_RV"),
                ("CKS_", "CK_STATE"),
                ("CKU_", "CK_USER_TYPE"),
                ("CKZ_", "CK_RSA_PKCS_OAEP_SOURCE_TYPE"),
                ("CRYPTOKI_VERSION_", "CK_BYTE"),
            ];

            if ["CK_TRUE", "CK_FALSE"].contains(&name) {
                Some(callbacks::IntKind::Custom {
                    name: "CK_BBOOL",
                    is_signed: false,
                })
            } else {
                let mut result = None;
                for (prefix, variable) in &prefixes {
                    if name.starts_with(prefix) {
                        result = Some(callbacks::IntKind::Custom {
                            name: variable,
                            is_signed: false,
                        })
                    }
                }
                result
            }
        }
    }

    pub fn generate_bindings() {
        let bindings = bindgen::Builder::default()
            .header("pkcs11.h")
            .dynamic_library_name("Pkcs11")
            // The PKCS11 library works in a slightly different way to most shared libraries. We have
            // to call `C_GetFunctionList`, which returns a list of pointers to the _actual_ library
            // functions. This is the only function we need to create a binding for.
            .allowlist_function("C_GetFunctionList")
            // This is needed because no types will be generated if `allowlist_function` is used.
            // Unsure if this is a bug.
            .allowlist_type("*")
            .allowlist_file("pkcs11.h")
            // See this issue: https://github.com/parallaxsecond/rust-cryptoki/issues/12
            .blocklist_type("max_align_t")
            // Derive the `Debug` trait for the generated structs where possible.
            .derive_debug(true)
            // Derive the `Default` trait for the generated structs where possible.
            .derive_default(true)
            .parse_callbacks(Box::new(CargoCallbacks))
            .generate()
            .expect("Unable to generate bindings");

        // Write the bindings to the $OUT_DIR/pkcs11_bindings.rs file.
        let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
        bindings
            .write_to_file(out_path.join("pkcs11_bindings.rs"))
            .expect("Couldn't write bindings!");
    }
}
