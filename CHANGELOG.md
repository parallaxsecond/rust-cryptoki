# Changelog

## [cryptoki-0.10.0](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-0.10.0) (2025-06-03)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-sys-0.4.0...cryptoki-0.10.0)

## [cryptoki-sys-0.4.0](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-sys-0.4.0) (2025-06-03)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-0.9.0...cryptoki-sys-0.4.0)

**Implemented enhancements:**

- Consider changing get\_attribute\_info\_map from taking a Vec to taking a slice [\#267](https://github.com/parallaxsecond/rust-cryptoki/issues/267)

**Closed issues:**

- CKA\_UNIQUE\_ID not exposed [\#268](https://github.com/parallaxsecond/rust-cryptoki/issues/268)
- PkcsOaepParams mis-aligned [\#266](https://github.com/parallaxsecond/rust-cryptoki/issues/266)
- Thread Safety [\#260](https://github.com/parallaxsecond/rust-cryptoki/issues/260)
- Suggestion: Have verification functions return `Result<bool>` instead of `Result<()>` [\#254](https://github.com/parallaxsecond/rust-cryptoki/issues/254)
- Support for multi-part operations [\#250](https://github.com/parallaxsecond/rust-cryptoki/issues/250)
- GcmParams ulIvBits being set to 0 causes issues with Thales HSMs [\#247](https://github.com/parallaxsecond/rust-cryptoki/issues/247)
- Use GcmParams with AWS CloudHSM will cause undefined behavior [\#225](https://github.com/parallaxsecond/rust-cryptoki/issues/225)
- Add support for C\_GetInterfaceList [\#209](https://github.com/parallaxsecond/rust-cryptoki/issues/209)
- bug: `is_fn_supported()` always returns `true` [\#155](https://github.com/parallaxsecond/rust-cryptoki/issues/155)

**Merged pull requests:**

- Update CI definitions [\#275](https://github.com/parallaxsecond/rust-cryptoki/pull/275) ([wiktor-k](https://github.com/wiktor-k))
- Add workspace resolver to fix a build warning [\#274](https://github.com/parallaxsecond/rust-cryptoki/pull/274) ([wiktor-k](https://github.com/wiktor-k))
- \#267 Modify get\_attribute\_info\_map to take slice instead of vec [\#273](https://github.com/parallaxsecond/rust-cryptoki/pull/273) ([ivozeba](https://github.com/ivozeba))
- \#266: Added conditional attribute to pack the PkcsOaepParams struct o… [\#272](https://github.com/parallaxsecond/rust-cryptoki/pull/272) ([ivozeba](https://github.com/ivozeba))
-  Add UniqueId Attribute [\#271](https://github.com/parallaxsecond/rust-cryptoki/pull/271) ([Jakuje](https://github.com/Jakuje))
- Bump rust edition to 2021 [\#265](https://github.com/parallaxsecond/rust-cryptoki/pull/265) ([Jakuje](https://github.com/Jakuje))
- tests: Be less strict in accepted interface versions [\#262](https://github.com/parallaxsecond/rust-cryptoki/pull/262) ([Jakuje](https://github.com/Jakuje))
- Bump libloading version to 0.8.6 [\#261](https://github.com/parallaxsecond/rust-cryptoki/pull/261) ([Jakuje](https://github.com/Jakuje))
- Feat: Add SHA key generation mechanisms [\#259](https://github.com/parallaxsecond/rust-cryptoki/pull/259) ([jacobprudhomme](https://github.com/jacobprudhomme))
- Remove skipping of kryoptic tests as they should work now [\#258](https://github.com/parallaxsecond/rust-cryptoki/pull/258) ([Jakuje](https://github.com/Jakuje))
- Feat: Add NIST SP800-108 KDF mechanisms [\#257](https://github.com/parallaxsecond/rust-cryptoki/pull/257) ([jacobprudhomme](https://github.com/jacobprudhomme))
- Add support for message-based encryption and decryption \(PKCS\#11 3.0\) [\#255](https://github.com/parallaxsecond/rust-cryptoki/pull/255) ([Jakuje](https://github.com/Jakuje))
- Fixed failing tests for multi-part operations [\#253](https://github.com/parallaxsecond/rust-cryptoki/pull/253) ([jacobprudhomme](https://github.com/jacobprudhomme))
- Add bindings for multi-part operations [\#252](https://github.com/parallaxsecond/rust-cryptoki/pull/252) ([jacobprudhomme](https://github.com/jacobprudhomme))
- feat: add bindings for riscv64gc-unknown-linux-gnu target [\#251](https://github.com/parallaxsecond/rust-cryptoki/pull/251) ([hug-dev](https://github.com/hug-dev))
- Set ulIvBits and more graceful error handling [\#249](https://github.com/parallaxsecond/rust-cryptoki/pull/249) ([jaeparker22](https://github.com/jaeparker22))
- Add support for PKCS\#11 3.0 [\#248](https://github.com/parallaxsecond/rust-cryptoki/pull/248) ([Jakuje](https://github.com/Jakuje))
- WIP: supports mutable IV in GcmParams, close \#225 [\#226](https://github.com/parallaxsecond/rust-cryptoki/pull/226) ([zkonge](https://github.com/zkonge))

## [cryptoki-0.9.0](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-0.9.0) (2025-02-17)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-sys-0.3.0...cryptoki-0.9.0)

## [cryptoki-sys-0.3.0](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-sys-0.3.0) (2025-02-17)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-0.8.0...cryptoki-sys-0.3.0)

**Implemented enhancements:**

- PkcsOaepParams [\#195](https://github.com/parallaxsecond/rust-cryptoki/issues/195)
- Digest [\#88](https://github.com/parallaxsecond/rust-cryptoki/issues/88)

**Fixed bugs:**

- Treat CK\*\_VENDOR\_DEFINED correctly [\#54](https://github.com/parallaxsecond/rust-cryptoki/issues/54)

**Closed issues:**

- Status access violation [\#240](https://github.com/parallaxsecond/rust-cryptoki/issues/240)
- `clone()` and `is_initialized()` [\#151](https://github.com/parallaxsecond/rust-cryptoki/issues/151)
- CKA\_PUBLIC\_KEY\_INFO getting TypeInvalid [\#142](https://github.com/parallaxsecond/rust-cryptoki/issues/142)
- Function name as part of errors [\#135](https://github.com/parallaxsecond/rust-cryptoki/issues/135)
- Missing constants for x86\_64-unknown-linux-gnu [\#134](https://github.com/parallaxsecond/rust-cryptoki/issues/134)
- Session Pool Management [\#126](https://github.com/parallaxsecond/rust-cryptoki/issues/126)
- Vendored mechanisms [\#105](https://github.com/parallaxsecond/rust-cryptoki/issues/105)
- Remove psa\_crypto dependency [\#100](https://github.com/parallaxsecond/rust-cryptoki/issues/100)
- Improvement to unreleased open\_session change? [\#97](https://github.com/parallaxsecond/rust-cryptoki/issues/97)
- Add support for SHA-based KDFs for ECDH [\#92](https://github.com/parallaxsecond/rust-cryptoki/issues/92)
- EDDSA contrib [\#87](https://github.com/parallaxsecond/rust-cryptoki/issues/87)
- Document test dependencies/setup in contributor docs [\#71](https://github.com/parallaxsecond/rust-cryptoki/issues/71)

**Merged pull requests:**

- feat: add support for vendor defined key types [\#246](https://github.com/parallaxsecond/rust-cryptoki/pull/246) ([mcaneris](https://github.com/mcaneris))
- Add pack pragma for struct padding back [\#245](https://github.com/parallaxsecond/rust-cryptoki/pull/245) ([jrozner](https://github.com/jrozner))
- feat: revise EdDSA mechanism to support optional params [\#244](https://github.com/parallaxsecond/rust-cryptoki/pull/244) ([mcaneris](https://github.com/mcaneris))
- chore: add dev information to the README [\#242](https://github.com/parallaxsecond/rust-cryptoki/pull/242) ([hug-dev](https://github.com/hug-dev))
- Define CKD\_SHA256\_KDF transformation [\#239](https://github.com/parallaxsecond/rust-cryptoki/pull/239) ([hug-dev](https://github.com/hug-dev))
- chore: remove dependency on psa-crypto [\#238](https://github.com/parallaxsecond/rust-cryptoki/pull/238) ([hug-dev](https://github.com/hug-dev))
- Add support for vendor defined attributes [\#237](https://github.com/parallaxsecond/rust-cryptoki/pull/237) ([jrozner](https://github.com/jrozner))
- fix: fix some clippy lints [\#236](https://github.com/parallaxsecond/rust-cryptoki/pull/236) ([hug-dev](https://github.com/hug-dev))
- chore: update CHANGELOG [\#234](https://github.com/parallaxsecond/rust-cryptoki/pull/234) ([hug-dev](https://github.com/hug-dev))

## [cryptoki-0.8.0](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-0.8.0) (2024-11-14)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-sys-0.2.0...cryptoki-0.8.0)

## [cryptoki-sys-0.2.0](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-sys-0.2.0) (2024-11-14)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-0.7.0...cryptoki-sys-0.2.0)

**Closed issues:**

- build issues with rust \< 1.80 [\#221](https://github.com/parallaxsecond/rust-cryptoki/issues/221)
- project won't compile under Rust 1.80 - CI broken [\#216](https://github.com/parallaxsecond/rust-cryptoki/issues/216)
- New release? [\#194](https://github.com/parallaxsecond/rust-cryptoki/issues/194)
- Underlying library access / vendor extensions [\#115](https://github.com/parallaxsecond/rust-cryptoki/issues/115)
- Expose more fine-grained control over `find_objects` [\#106](https://github.com/parallaxsecond/rust-cryptoki/issues/106)
- Current `pkcs11.h` is not up-to-date [\#65](https://github.com/parallaxsecond/rust-cryptoki/issues/65)

**Merged pull requests:**

- chore: upgrade version number before publishing [\#233](https://github.com/parallaxsecond/rust-cryptoki/pull/233) ([hug-dev](https://github.com/hug-dev))
- feat: support vendor defined mechanisms [\#232](https://github.com/parallaxsecond/rust-cryptoki/pull/232) ([Direktor799](https://github.com/Direktor799))
- Move crate documentation to README and add code example [\#231](https://github.com/parallaxsecond/rust-cryptoki/pull/231) ([wiktor-k](https://github.com/wiktor-k))
- Add capability to load symbols from current executable [\#230](https://github.com/parallaxsecond/rust-cryptoki/pull/230) ([EliseChouleur](https://github.com/EliseChouleur))
- feat: add SHAn-HMAC [\#229](https://github.com/parallaxsecond/rust-cryptoki/pull/229) ([Direktor799](https://github.com/Direktor799))
- Feat/pkcs11 3.0 [\#228](https://github.com/parallaxsecond/rust-cryptoki/pull/228) ([Direktor799](https://github.com/Direktor799))
- feat: add HKDF mechanisms [\#227](https://github.com/parallaxsecond/rust-cryptoki/pull/227) ([Direktor799](https://github.com/Direktor799))
- flip order of CI commands, to check fmt and clippy first [\#224](https://github.com/parallaxsecond/rust-cryptoki/pull/224) ([keldonin](https://github.com/keldonin))
- implements session object handle iterator, with caching [\#223](https://github.com/parallaxsecond/rust-cryptoki/pull/223) ([keldonin](https://github.com/keldonin))
- fix compilation issues with Rust 1.79 [\#222](https://github.com/parallaxsecond/rust-cryptoki/pull/222) ([keldonin](https://github.com/keldonin))
- Support vendor extensions for CK\_USER\_TYPE [\#220](https://github.com/parallaxsecond/rust-cryptoki/pull/220) ([larper2axis](https://github.com/larper2axis))
- Add an example to `find_objects` [\#219](https://github.com/parallaxsecond/rust-cryptoki/pull/219) ([wiktor-k](https://github.com/wiktor-k))
- Adjust code to compile under rust 1.80 [\#217](https://github.com/parallaxsecond/rust-cryptoki/pull/217) ([keldonin](https://github.com/keldonin))
- Implement Session.copy\_object\(\) [\#215](https://github.com/parallaxsecond/rust-cryptoki/pull/215) ([keldonin](https://github.com/keldonin))
- Session.find\_objects\(\): implement fewer calls to C\_FindObjects\(\) [\#214](https://github.com/parallaxsecond/rust-cryptoki/pull/214) ([keldonin](https://github.com/keldonin))

## [cryptoki-0.7.0](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-0.7.0) (2024-06-18)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-sys-0.1.8...cryptoki-0.7.0)

## [cryptoki-sys-0.1.8](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-sys-0.1.8) (2024-06-18)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-0.6.2...cryptoki-sys-0.1.8)

**Closed issues:**

- Build of cryptoki v0.6.1 failing on Fedora 39+ [\#198](https://github.com/parallaxsecond/rust-cryptoki/issues/198)

**Merged pull requests:**

- Bump crates [\#211](https://github.com/parallaxsecond/rust-cryptoki/pull/211) ([gowthamsk-arm](https://github.com/gowthamsk-arm))
- Port 0.6 changes [\#210](https://github.com/parallaxsecond/rust-cryptoki/pull/210) ([gowthamsk-arm](https://github.com/gowthamsk-arm))
- Expose PkcsOaepParams' message digest algorithm [\#207](https://github.com/parallaxsecond/rust-cryptoki/pull/207) ([tgonzalezorlandoarm](https://github.com/tgonzalezorlandoarm))
- 20240308 mechanisms [\#203](https://github.com/parallaxsecond/rust-cryptoki/pull/203) ([Firstyear](https://github.com/Firstyear))
- Add support for `CARGO_TARGET_DIR` in `regenerate_bindings.sh` [\#200](https://github.com/parallaxsecond/rust-cryptoki/pull/200) ([wiktor-k](https://github.com/wiktor-k))
- Bump bindgen to 0.69.4 [\#199](https://github.com/parallaxsecond/rust-cryptoki/pull/199) ([hug-dev](https://github.com/hug-dev))
- Use infallible conversion into instead of try\_into [\#197](https://github.com/parallaxsecond/rust-cryptoki/pull/197) ([gowthamsk-arm](https://github.com/gowthamsk-arm))
- Fix test for 32bit arch [\#193](https://github.com/parallaxsecond/rust-cryptoki/pull/193) ([ionut-arm](https://github.com/ionut-arm))
- nightly: Add the loongaarch64-unkown-linux-gnu target [\#190](https://github.com/parallaxsecond/rust-cryptoki/pull/190) ([tgonzalezorlandoarm](https://github.com/tgonzalezorlandoarm))
- ci.yml: Add a job for runnning tests on MSRV [\#188](https://github.com/parallaxsecond/rust-cryptoki/pull/188) ([tgonzalezorlandoarm](https://github.com/tgonzalezorlandoarm))
- Add references to RFC 4493 in comments about AesCMac. [\#184](https://github.com/parallaxsecond/rust-cryptoki/pull/184) ([xaqq](https://github.com/xaqq))
- Add SHA256-HMAC mechanism [\#183](https://github.com/parallaxsecond/rust-cryptoki/pull/183) ([jippeholwerda](https://github.com/jippeholwerda))
- Expose AES-CMAC algorithm [\#181](https://github.com/parallaxsecond/rust-cryptoki/pull/181) ([xaqq](https://github.com/xaqq))
- Adding 2 new mechanisms: generic key generation and key derivation via encryption [\#178](https://github.com/parallaxsecond/rust-cryptoki/pull/178) ([Nk185](https://github.com/Nk185))
- Add bindings for loongarch64-linux-gnu [\#166](https://github.com/parallaxsecond/rust-cryptoki/pull/166) ([heiher](https://github.com/heiher))
- Add function name to errors and logs [\#147](https://github.com/parallaxsecond/rust-cryptoki/pull/147) ([ionut-arm](https://github.com/ionut-arm))

## [cryptoki-0.6.2](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-0.6.2) (2024-03-08)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-0.6.1...cryptoki-0.6.2)

**Closed issues:**

- session.login fails on MacOS Sonoma [\#191](https://github.com/parallaxsecond/rust-cryptoki/issues/191)
- test slot::token\_info::test::debug\_info fails on 32-bit architectures. [\#186](https://github.com/parallaxsecond/rust-cryptoki/issues/186)

## [cryptoki-0.6.1](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-0.6.1) (2023-10-17)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-0.6.0...cryptoki-0.6.1)

**Merged pull requests:**

- Bump cryptoki to 0.6.1 [\#180](https://github.com/parallaxsecond/rust-cryptoki/pull/180) ([tgonzalezorlandoarm](https://github.com/tgonzalezorlandoarm))
- Bump psa-crypto to 0.12.0 [\#179](https://github.com/parallaxsecond/rust-cryptoki/pull/179) ([tgonzalezorlandoarm](https://github.com/tgonzalezorlandoarm))

## [cryptoki-0.6.0](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-0.6.0) (2023-10-06)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-sys-0.1.7...cryptoki-0.6.0)

**Merged pull requests:**

- Update Changelog with psa-crypto bump [\#177](https://github.com/parallaxsecond/rust-cryptoki/pull/177) ([tgonzalezorlandoarm](https://github.com/tgonzalezorlandoarm))
- Bump psa-crypto to 0.11.0 [\#176](https://github.com/parallaxsecond/rust-cryptoki/pull/176) ([tgonzalezorlandoarm](https://github.com/tgonzalezorlandoarm))
- Update cryptoki crate version and add changelog [\#175](https://github.com/parallaxsecond/rust-cryptoki/pull/175) ([tgonzalezorlandoarm](https://github.com/tgonzalezorlandoarm))
- Update -sys crate version and add changelog [\#174](https://github.com/parallaxsecond/rust-cryptoki/pull/174) ([tgonzalezorlandoarm](https://github.com/tgonzalezorlandoarm))
- Fix spelling and Update Cargo.lock [\#172](https://github.com/parallaxsecond/rust-cryptoki/pull/172) ([tgonzalezorlandoarm](https://github.com/tgonzalezorlandoarm))
- Start tracking Cargo.lock file [\#171](https://github.com/parallaxsecond/rust-cryptoki/pull/171) ([tgonzalezorlandoarm](https://github.com/tgonzalezorlandoarm))
- ci: Add workflow dispatch [\#170](https://github.com/parallaxsecond/rust-cryptoki/pull/170) ([tgonzalezorlandoarm](https://github.com/tgonzalezorlandoarm))
- Drop unused target-lexicon crate [\#169](https://github.com/parallaxsecond/rust-cryptoki/pull/169) ([tgonzalezorlandoarm](https://github.com/tgonzalezorlandoarm))
- Change lints for the library and allow unknown lints [\#168](https://github.com/parallaxsecond/rust-cryptoki/pull/168) ([tgonzalezorlandoarm](https://github.com/tgonzalezorlandoarm))
- Bump bindgen to 0.66.1 [\#167](https://github.com/parallaxsecond/rust-cryptoki/pull/167) ([tgonzalezorlandoarm](https://github.com/tgonzalezorlandoarm))
- Fix RSA OKCS OAEP mechanism [\#165](https://github.com/parallaxsecond/rust-cryptoki/pull/165) ([wiktor-k](https://github.com/wiktor-k))
- elliptic\_curve: Fix broken references [\#161](https://github.com/parallaxsecond/rust-cryptoki/pull/161) ([wiktor-k](https://github.com/wiktor-k))
- Make generic bindings [\#154](https://github.com/parallaxsecond/rust-cryptoki/pull/154) ([arjennienhuis](https://github.com/arjennienhuis))

## [cryptoki-sys-0.1.7](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-sys-0.1.7) (2023-10-06)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-0.5.0...cryptoki-sys-0.1.7)

**Closed issues:**

- PKCS OAEP padding always returns: Pkcs11\(ArgumentsBad\) [\#163](https://github.com/parallaxsecond/rust-cryptoki/issues/163)

## [cryptoki-0.5.0](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-0.5.0) (2023-08-12)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-sys-0.1.6...cryptoki-0.5.0)

**Closed issues:**

- Signing and Verifying [\#159](https://github.com/parallaxsecond/rust-cryptoki/issues/159)
- UserNotLoggedIn calling decrypt after login.... [\#157](https://github.com/parallaxsecond/rust-cryptoki/issues/157)
- Wrapper for C\_WaitForSlotEvent [\#145](https://github.com/parallaxsecond/rust-cryptoki/issues/145)

**Merged pull requests:**

- Bump cryptoki to 0.5.0 [\#160](https://github.com/parallaxsecond/rust-cryptoki/pull/160) ([ionut-arm](https://github.com/ionut-arm))
- "fix" for clone-then-initialize problem [\#152](https://github.com/parallaxsecond/rust-cryptoki/pull/152) ([arjennienhuis](https://github.com/arjennienhuis))
- Fix codespell action [\#148](https://github.com/parallaxsecond/rust-cryptoki/pull/148) ([wiktor-k](https://github.com/wiktor-k))
- Add wait\_for\_slot\_event and get\_slot\_event [\#146](https://github.com/parallaxsecond/rust-cryptoki/pull/146) ([arjennienhuis](https://github.com/arjennienhuis))
- Add AES-GCM mechanism [\#144](https://github.com/parallaxsecond/rust-cryptoki/pull/144) ([wiktor-k](https://github.com/wiktor-k))
- Add documentation check to CI test suite [\#141](https://github.com/parallaxsecond/rust-cryptoki/pull/141) ([wiktor-k](https://github.com/wiktor-k))
- Add EdDSA mechanism [\#140](https://github.com/parallaxsecond/rust-cryptoki/pull/140) ([wiktor-k](https://github.com/wiktor-k))
- Remove derivative crate [\#139](https://github.com/parallaxsecond/rust-cryptoki/pull/139) ([a1ien](https://github.com/a1ien))

## [cryptoki-sys-0.1.6](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-sys-0.1.6) (2023-04-25)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-0.3.1...cryptoki-sys-0.1.6)

**Closed issues:**

- Set homepage in GitHub project info [\#129](https://github.com/parallaxsecond/rust-cryptoki/issues/129)

**Merged pull requests:**

- Cryptoki-sys 0.1.6 [\#138](https://github.com/parallaxsecond/rust-cryptoki/pull/138) ([ionut-arm](https://github.com/ionut-arm))
- Add binding for single-part digest function [\#132](https://github.com/parallaxsecond/rust-cryptoki/pull/132) ([ellerh](https://github.com/ellerh))
- Bump bindgen version [\#130](https://github.com/parallaxsecond/rust-cryptoki/pull/130) ([gowthamsk-arm](https://github.com/gowthamsk-arm))
- Add new Pin type with secrecy/zeroize wrapper [\#128](https://github.com/parallaxsecond/rust-cryptoki/pull/128) ([sbihel](https://github.com/sbihel))
- fixup clippy errors [\#127](https://github.com/parallaxsecond/rust-cryptoki/pull/127) ([baloo](https://github.com/baloo))
- Fix CI \(clippy warnings\) [\#125](https://github.com/parallaxsecond/rust-cryptoki/pull/125) ([Bobo1239](https://github.com/Bobo1239))
- Implement PartialEq/Eq for Attribute [\#124](https://github.com/parallaxsecond/rust-cryptoki/pull/124) ([Bobo1239](https://github.com/Bobo1239))
- Update to remove const\_err lint [\#122](https://github.com/parallaxsecond/rust-cryptoki/pull/122) ([wiktor-k](https://github.com/wiktor-k))
- Simplify tests using TestResult [\#120](https://github.com/parallaxsecond/rust-cryptoki/pull/120) ([wiktor-k](https://github.com/wiktor-k))
- Implement update attributes for objects [\#119](https://github.com/parallaxsecond/rust-cryptoki/pull/119) ([baloo](https://github.com/baloo))
- Split the implementation of session and pkcs11 [\#118](https://github.com/parallaxsecond/rust-cryptoki/pull/118) ([baloo](https://github.com/baloo))
- Fix CI [\#117](https://github.com/parallaxsecond/rust-cryptoki/pull/117) ([Bobo1239](https://github.com/Bobo1239))
- Fix wrong mapping of AttributeType::CertificateType [\#116](https://github.com/parallaxsecond/rust-cryptoki/pull/116) ([Bobo1239](https://github.com/Bobo1239))
- Add CBC mode block ciphers [\#111](https://github.com/parallaxsecond/rust-cryptoki/pull/111) ([jhagborgftx](https://github.com/jhagborgftx))
- Make RSA OAEP and ECDH1 safe using lifetime parameters [\#110](https://github.com/parallaxsecond/rust-cryptoki/pull/110) ([jhagborgftx](https://github.com/jhagborgftx))
- Add several no-parameter mechanisms [\#108](https://github.com/parallaxsecond/rust-cryptoki/pull/108) ([jhagborgftx](https://github.com/jhagborgftx))

## [cryptoki-0.3.1](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-0.3.1) (2023-03-15)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-sys-0.1.5...cryptoki-0.3.1)

## [cryptoki-sys-0.1.5](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-sys-0.1.5) (2023-03-15)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-0.4.1...cryptoki-sys-0.1.5)

**Closed issues:**

- `#[hsm_test]` attribute/macro [\#121](https://github.com/parallaxsecond/rust-cryptoki/issues/121)
- RSA OAEP interface is unsound [\#107](https://github.com/parallaxsecond/rust-cryptoki/issues/107)

## [cryptoki-0.4.1](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-0.4.1) (2022-09-29)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-0.4.0...cryptoki-0.4.1)

**Merged pull requests:**

- Bump to v0.4.1 [\#104](https://github.com/parallaxsecond/rust-cryptoki/pull/104) ([ionut-arm](https://github.com/ionut-arm))
- Implement Eq for SessionState [\#103](https://github.com/parallaxsecond/rust-cryptoki/pull/103) ([a1ien](https://github.com/a1ien))

## [cryptoki-0.4.0](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-0.4.0) (2022-09-07)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-sys-0.1.4...cryptoki-0.4.0)

**Merged pull requests:**

- Bump version and update CHANGELOG [\#102](https://github.com/parallaxsecond/rust-cryptoki/pull/102) ([ionut-arm](https://github.com/ionut-arm))
- Make separate constructors for RO/RW sessions [\#101](https://github.com/parallaxsecond/rust-cryptoki/pull/101) ([ionut-arm](https://github.com/ionut-arm))
- Fix issues reported by clippy [\#98](https://github.com/parallaxsecond/rust-cryptoki/pull/98) ([gowthamsk-arm](https://github.com/gowthamsk-arm))

## [cryptoki-sys-0.1.4](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-sys-0.1.4) (2022-08-11)

[Full Changelog](https://github.com/parallaxsecond/rust-cryptoki/compare/cryptoki-0.2.1...cryptoki-sys-0.1.4)

**Implemented enhancements:**

- Solve open issues [\#84](https://github.com/parallaxsecond/rust-cryptoki/pull/84) ([ionut-arm](https://github.com/ionut-arm))
- Add SHAn-RSA-PKCS-PSS mechanisms [\#81](https://github.com/parallaxsecond/rust-cryptoki/pull/81) ([ionut-arm](https://github.com/ionut-arm))

**Closed issues:**

- How to test for supported functions? [\#78](https://github.com/parallaxsecond/rust-cryptoki/issues/78)
- Add `is_initialized()` to `Pkcs11` [\#77](https://github.com/parallaxsecond/rust-cryptoki/issues/77)
- Segmentation fault on parsing `Date` [\#74](https://github.com/parallaxsecond/rust-cryptoki/issues/74)

**Merged pull requests:**

- Prepare release of changes to bindings [\#96](https://github.com/parallaxsecond/rust-cryptoki/pull/96) ([ionut-arm](https://github.com/ionut-arm))
- Fix CI error for x86\_64-pc-windows-msvc [\#95](https://github.com/parallaxsecond/rust-cryptoki/pull/95) ([hug-dev](https://github.com/hug-dev))
- Add bindings for FreeBSD on x86-64. [\#94](https://github.com/parallaxsecond/rust-cryptoki/pull/94) ([ximon18](https://github.com/ximon18))
- Add script for regenerating bindings [\#91](https://github.com/parallaxsecond/rust-cryptoki/pull/91) ([ionut-arm](https://github.com/ionut-arm))
- session\_management: Add ability to login with raw bytes [\#90](https://github.com/parallaxsecond/rust-cryptoki/pull/90) ([Subject38](https://github.com/Subject38))
- Add bindings for aarch64-darwin [\#89](https://github.com/parallaxsecond/rust-cryptoki/pull/89) ([Subject38](https://github.com/Subject38))
- Remove serial\_test\_derive from deps [\#86](https://github.com/parallaxsecond/rust-cryptoki/pull/86) ([palfrey](https://github.com/palfrey))
- Fix typos and add automatic check to CI [\#83](https://github.com/parallaxsecond/rust-cryptoki/pull/83) ([wiktor-k](https://github.com/wiktor-k))
- Info flags refactor [\#68](https://github.com/parallaxsecond/rust-cryptoki/pull/68) ([vkkoskie](https://github.com/vkkoskie))

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
- Updates for getting attribute info - \#42 [\#48](https://github.com/parallaxsecond/rust-cryptoki/pull/48) ([mike-boquard](https://github.com/mike-boquard))
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
- Implemented new way of holding the context within the session [\#59](https://github.com/parallaxsecond/rust-cryptoki/pull/59) ([mike-boquard](https://github.com/mike-boquard))
- Module tree hygiene [\#56](https://github.com/parallaxsecond/rust-cryptoki/pull/56) ([vkkoskie](https://github.com/vkkoskie))
- Fixes to address \#50 [\#52](https://github.com/parallaxsecond/rust-cryptoki/pull/52) ([mike-boquard](https://github.com/mike-boquard))
- Merge `devel` into `main` [\#51](https://github.com/parallaxsecond/rust-cryptoki/pull/51) ([hug-dev](https://github.com/hug-dev))
- Added support for `C_SetPIN` [\#49](https://github.com/parallaxsecond/rust-cryptoki/pull/49) ([mike-boquard](https://github.com/mike-boquard))
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
