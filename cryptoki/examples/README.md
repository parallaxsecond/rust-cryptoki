# Writing new examples

Examples are run during CI, so new examples must follow these rules:

- Use the same test credentials as other examples and tests.
- Keep each example to a single file (1 example = 1 file).
- Do not expect command-line arguments.
- Do not require environment variables other than `TEST_PKCS11_MODULE`.
- Keep runtime relatively fast; verbose output is fine.
- Ensure it runs on the MSRV.
- Exit with status 0 on normal execution; any non-zero status is treated as an error.
- Use `testresult::TestResult` as the return type of `main` for easier error handling.

In addition, examples should be extensively documented and designed to be educative.

Suggested best practices:

- Reference the same SoftHSM setup used by CI; avoid introducing new credentials.
- Clean up any tokens, keys, or objects created by the example. When possible, use session (i.e. non-persistent) objects.
- Ensure the example works with SoftHSM2.

