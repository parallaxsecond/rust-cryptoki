# Changelog

## [cryptoki-0.4.1](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-0.4.1) (2022-09-29)

**Implemented enhancements:**

- Implement Eq for SessionState [\#103](https://github.com/parallaxsecond/rust-cryptoki/pull/103) ([a1ien](https://github.com/a1ien))

## [cryptoki-0.4.0](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-0.4.0) (2022-09-07)

### Breaking changes since 0.3.0

- A change to the way `Pkcs11::initialize` needs to be called, and a new error variant in [#84](https://github.com/parallaxsecond/rust-cryptoki/pull/84)
- A change to the way sessions are created, in [#101](https://github.com/parallaxsecond/rust-cryptoki/pull/101)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-sys-0.1.4...cryptoki-0.4.0)

**Implemented enhancements:**

- Solve open issues [\#84](https://github.com/parallaxsecond/rust-cryptoki/pull/84) ([ionut-arm](https://github.com/ionut-arm))
- Add SHAn-RSA-PKCS-PSS mechanisms [\#81](https://github.com/parallaxsecond/rust-cryptoki/pull/81) ([ionut-arm](https://github.com/ionut-arm))

**Closed issues:**

- How to test for supported functions? [\#78](https://github.com/parallaxsecond/rust-cryptoki/issues/78)
- Add `is_initialized()` to `Pkcs11` [\#77](https://github.com/parallaxsecond/rust-cryptoki/issues/77)
- Segmentation fault on parsing `Date` [\#74](https://github.com/parallaxsecond/rust-cryptoki/issues/74)

**Merged pull requests:**
- Fix CI error for x86\_64-pc-windows-msvc [\#95](https://github.com/parallaxsecond/rust-cryptoki/pull/95) ([hug-dev](https://github.com/hug-dev))
- session\_management: Add ability to login with raw bytes [\#90](https://github.com/parallaxsecond/rust-cryptoki/pull/90) ([Subject38](https://github.com/Subject38))
- Remove serial\_test\_derive from deps [\#86](https://github.com/parallaxsecond/rust-cryptoki/pull/86) ([palfrey](https://github.com/palfrey))
- Fix typos and add automatic check to CI [\#83](https://github.com/parallaxsecond/rust-cryptoki/pull/83) ([wiktor-k](https://github.com/wiktor-k))
- Info flags refactor [\#68](https://github.com/parallaxsecond/rust-cryptoki/pull/68) ([vkkoskie](https://github.com/vkkoskie))
- Make separate constructors for RO/RW sessions [\#101](https://github.com/parallaxsecond/rust-cryptoki/pull/101) ([ionut-arm](https://github.com/ionut-arm))
- Fix issues reported by clippy [\#98](https://github.com/parallaxsecond/rust-cryptoki/pull/98) ([gowthamsk-arm](https://github.com/gowthamsk-arm))

## [cryptoki-sys-0.1.4](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-sys-0.1.4) (2022-08-11)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-0.2.1...cryptoki-sys-0.1.4)

**Merged pull requests:**

- Prepare release of changes to bindings [\#96](https://github.com/parallaxsecond/rust-cryptoki/pull/96) ([ionut-arm](https://github.com/ionut-arm))
- Add bindings for FreeBSD on x86-64. [\#94](https://github.com/parallaxsecond/rust-cryptoki/pull/94) ([ximon18](https://github.com/ximon18))
- Add script for regenerating bindings [\#91](https://github.com/parallaxsecond/rust-cryptoki/pull/91) ([ionut-arm](https://github.com/ionut-arm))
- Add bindings for aarch64-darwin [\#89](https://github.com/parallaxsecond/rust-cryptoki/pull/89) ([Subject38](https://github.com/Subject38))

## [cryptoki-0.2.1](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-0.2.1) (2022-02-14)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-0.3.0...cryptoki-0.2.1)

**Closed issues:**

- Signing with RSA-PSS does not hash the message with the given function [\#80](https://github.com/parallaxsecond/rust-cryptoki/issues/80)
- Force cache flush? [\#75](https://github.com/parallaxsecond/rust-cryptoki/issues/75)

## [cryptoki-0.3.0](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-0.3.0) (2022-01-14)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-sys-0.1.3...cryptoki-0.3.0)

## [cryptoki-sys-0.1.3](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-sys-0.1.3) (2022-01-14)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-0.2.0...cryptoki-sys-0.1.3)

**Implemented enhancements:**

- PIN Handling [\#50](https://github.com/parallaxsecond/rust-cryptoki/issues/50)
- Updates for getting attribute info - \#42 [\#48](https://github.com/parallaxsecond/rust-cryptoki/pull/48) ([mjb3279](https://github.com/mjb3279))
- Add secret key generation and key wrapping functions [\#38](https://github.com/parallaxsecond/rust-cryptoki/pull/38) ([wiktor-k](https://github.com/wiktor-k))

**Fixed bugs:**

- Provide attribute type in return from `get_attribute_info` [\#42](https://github.com/parallaxsecond/rust-cryptoki/issues/42)
- Resizing/Truncating returned lists [\#34](https://github.com/parallaxsecond/rust-cryptoki/issues/34)
- Remove unused field [\#53](https://github.com/parallaxsecond/rust-cryptoki/pull/53) ([hug-dev](https://github.com/hug-dev))

**Closed issues:**

- `get_attributes()` with AttributeType::Class fails for private key with YubiHSM2 Nano [\#76](https://github.com/parallaxsecond/rust-cryptoki/issues/76)
- `pkcs11.open_session_no_callback` against Luna Network HSM crashed with SIGSEGV [\#72](https://github.com/parallaxsecond/rust-cryptoki/issues/72)
- Solution for `Session` lifetimes [\#57](https://github.com/parallaxsecond/rust-cryptoki/issues/57)
- Module tree structure makes docs difficult to navigate [\#55](https://github.com/parallaxsecond/rust-cryptoki/issues/55)

**Merged pull requests:**

- Version bump [\#79](https://github.com/parallaxsecond/rust-cryptoki/pull/79) ([ionut-arm](https://github.com/ionut-arm))
- Suppress null pointer deref warnings [\#62](https://github.com/parallaxsecond/rust-cryptoki/pull/62) ([vkkoskie](https://github.com/vkkoskie))
- Use rust's own bool type in abstraction crate [\#61](https://github.com/parallaxsecond/rust-cryptoki/pull/61) ([vkkoskie](https://github.com/vkkoskie))
- Switch to inclusive bindgen naming [\#60](https://github.com/parallaxsecond/rust-cryptoki/pull/60) ([vkkoskie](https://github.com/vkkoskie))
- Implemented new way of holding the context within the session [\#59](https://github.com/parallaxsecond/rust-cryptoki/pull/59) ([mjb3279](https://github.com/mjb3279))
- Module tree hygiene [\#56](https://github.com/parallaxsecond/rust-cryptoki/pull/56) ([vkkoskie](https://github.com/vkkoskie))
- Fixes to address \#50 [\#52](https://github.com/parallaxsecond/rust-cryptoki/pull/52) ([mjb3279](https://github.com/mjb3279))
- Merge `devel` into `main` [\#51](https://github.com/parallaxsecond/rust-cryptoki/pull/51) ([hug-dev](https://github.com/hug-dev))
- Added support for `C_SetPIN` [\#49](https://github.com/parallaxsecond/rust-cryptoki/pull/49) ([mjb3279](https://github.com/mjb3279))
- Simplify test code by using Results instead of unwraps [\#39](https://github.com/parallaxsecond/rust-cryptoki/pull/39) ([wiktor-k](https://github.com/wiktor-k))
- Update CHaNGELOG [\#37](https://github.com/parallaxsecond/rust-cryptoki/pull/37) ([hug-dev](https://github.com/hug-dev))

## [cryptoki-0.2.0](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-0.2.0) (2021-08-03)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-sys-0.1.2...cryptoki-0.2.0)

## [cryptoki-sys-0.1.2](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-sys-0.1.2) (2021-08-03)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-0.1.1...cryptoki-sys-0.1.2)

**Implemented enhancements:**

- Supported targets might not need an exact target triple check [\#15](https://github.com/parallaxsecond/rust-cryptoki/issues/15)
- Add get\_token\_info [\#27](https://github.com/parallaxsecond/rust-cryptoki/pull/27) ([wiktor-k](https://github.com/wiktor-k))
- Add functions and types needed for ECDH-based decryption [\#24](https://github.com/parallaxsecond/rust-cryptoki/pull/24) ([wiktor-k](https://github.com/wiktor-k))
- Add ECC key generation [\#23](https://github.com/parallaxsecond/rust-cryptoki/pull/23) ([ionut-arm](https://github.com/ionut-arm))
- Add support for Elliptic Curves signing [\#22](https://github.com/parallaxsecond/rust-cryptoki/pull/22) ([wiktor-k](https://github.com/wiktor-k))
- Add a new way to check for supported targets [\#18](https://github.com/parallaxsecond/rust-cryptoki/pull/18) ([hug-dev](https://github.com/hug-dev))

**Fixed bugs:**

- Issue with code comment [\#25](https://github.com/parallaxsecond/rust-cryptoki/issues/25)
- Test fails on 32 bit platforms [\#19](https://github.com/parallaxsecond/rust-cryptoki/issues/19)
- Implement `CKM_EC_KEY_PAIR_GEN` to `MechanismType` conversion [\#32](https://github.com/parallaxsecond/rust-cryptoki/pull/32) ([daxpedda](https://github.com/daxpedda))

**Merged pull requests:**

- Prepare the new release [\#36](https://github.com/parallaxsecond/rust-cryptoki/pull/36) ([hug-dev](https://github.com/hug-dev))
- Added new methods to fix issue 375 - get slots with initialized token… [\#35](https://github.com/parallaxsecond/rust-cryptoki/pull/35) ([Sven-bg](https://github.com/Sven-bg))
- EC Edward and Montgomery support [\#33](https://github.com/parallaxsecond/rust-cryptoki/pull/33) ([daxpedda](https://github.com/daxpedda))
- Slot mechanisms [\#31](https://github.com/parallaxsecond/rust-cryptoki/pull/31) ([daxpedda](https://github.com/daxpedda))
- Removed confusing comment [\#30](https://github.com/parallaxsecond/rust-cryptoki/pull/30) ([Kakemone](https://github.com/Kakemone))
- Add x86\_64 macOS/Darwin bindings. [\#29](https://github.com/parallaxsecond/rust-cryptoki/pull/29) ([jeamland](https://github.com/jeamland))
- Add SHAn-RSA-PKCS mechanisms. [\#28](https://github.com/parallaxsecond/rust-cryptoki/pull/28) ([jeamland](https://github.com/jeamland))
- Add Object ID attribute [\#26](https://github.com/parallaxsecond/rust-cryptoki/pull/26) ([wiktor-k](https://github.com/wiktor-k))
- Update psa-crypto [\#21](https://github.com/parallaxsecond/rust-cryptoki/pull/21) ([hug-dev](https://github.com/hug-dev))
- Add dependency on the newest \(git only at the moment\) psa-crypto. [\#20](https://github.com/parallaxsecond/rust-cryptoki/pull/20) ([RobertDrazkowskiGL](https://github.com/RobertDrazkowskiGL))
- Update CHANGELOG [\#17](https://github.com/parallaxsecond/rust-cryptoki/pull/17) ([hug-dev](https://github.com/hug-dev))

## [cryptoki-0.1.1](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-0.1.1) (2021-03-31)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-sys-0.1.1...cryptoki-0.1.1)

## [cryptoki-sys-0.1.1](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-sys-0.1.1) (2021-03-31)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-0.1.0...cryptoki-sys-0.1.1)

**Implemented enhancements:**

- Add the generate-bindings feature to top-level [\#14](https://github.com/parallaxsecond/rust-cryptoki/pull/14) ([hug-dev](https://github.com/hug-dev))

**Fixed bugs:**

- bindgen\_test\_layout\_max\_align\_t test fails on i686 on cryptoki-sys crate [\#12](https://github.com/parallaxsecond/rust-cryptoki/issues/12)
- Fix a bindgen test failing [\#13](https://github.com/parallaxsecond/rust-cryptoki/pull/13) ([hug-dev](https://github.com/hug-dev))
- Remove armv7 bindings [\#11](https://github.com/parallaxsecond/rust-cryptoki/pull/11) ([ionut-arm](https://github.com/ionut-arm))

**Merged pull requests:**

- Prepare 0.1.1 release [\#16](https://github.com/parallaxsecond/rust-cryptoki/pull/16) ([hug-dev](https://github.com/hug-dev))
- Add CHANGELOG file [\#10](https://github.com/parallaxsecond/rust-cryptoki/pull/10) ([hug-dev](https://github.com/hug-dev))

## [cryptoki-0.1.0](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-0.1.0) (2021-03-18)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-sys-0.1.0...cryptoki-0.1.0)

## [cryptoki-sys-0.1.0](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-sys-0.1.0) (2021-03-18)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/43263d210a173fd4c0b97021d8f6a4046c1d88fd...cryptoki-sys-0.1.0)

**Implemented enhancements:**

- Add more object classes; fix tests [\#3](https://github.com/parallaxsecond/rust-cryptoki/pull/3) ([nickray](https://github.com/nickray))

**Closed issues:**

- Add Parsec copyright [\#5](https://github.com/parallaxsecond/rust-cryptoki/issues/5)
- Add some deny [\#4](https://github.com/parallaxsecond/rust-cryptoki/issues/4)
- Add the same labels as in Parsec [\#2](https://github.com/parallaxsecond/rust-cryptoki/issues/2)
- Add a testing infrastructure [\#1](https://github.com/parallaxsecond/rust-cryptoki/issues/1)

**Merged pull requests:**

- Prepare for the 0.1.0 release [\#9](https://github.com/parallaxsecond/rust-cryptoki/pull/9) ([hug-dev](https://github.com/hug-dev))
- Add armv7-hf to supported targets [\#8](https://github.com/parallaxsecond/rust-cryptoki/pull/8) ([hug-dev](https://github.com/hug-dev))
- Add Parsec copyright on all files [\#7](https://github.com/parallaxsecond/rust-cryptoki/pull/7) ([hug-dev](https://github.com/hug-dev))
- Improve general code quality [\#6](https://github.com/parallaxsecond/rust-cryptoki/pull/6) ([hug-dev](https://github.com/hug-dev))



\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
