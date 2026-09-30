# Security Policy

## Supported Versions

Security fixes are provided for the following released versions. Users should
upgrade to the latest release before reporting or evaluating a vulnerability.

| Version   | Supported          |
| --------- | ------------------ |
|   0.12.x  | :white_check_mark: |
|   0.11.x  | :white_check_mark: |
| <= 0.10.x | :x:                |

## Reporting a Vulnerability

Please report suspected vulnerabilities privately. Do not disclose security
issues in public issues, pull requests, or discussions until maintainers have
had an opportunity to investigate and release a fix.

Contact points:

- [Hugues de Valon](https://github.com/hug-dev) (<hugues.devalon@gmail.com>)
- [Jakub Jelen](https://github.com/Jakuje) (<jakuje@gmail.com>)
- [Wiktor Kwapisiewicz](https://github.com/wiktor-k) (<wiktor@metacode.biz>)
- [Ionut Mihalcea](https://github.com/ionut-arm) (<ionut.mihalcea@arm.com>)

Please include the affected version or commit, the relevant crate and API,
the impact, reproduction steps or a proof of concept, and any proposed
mitigation. Do not include production credentials, private keys, PINs, or
other sensitive data in a report.

We will acknowledge reports as soon as practical, investigate the issue, and
coordinate disclosure and remediation with the reporter. The final response
time may depend on the affected PKCS #11 provider or HSM.

## Scope

Reports involving `cryptoki` or `cryptoki-sys`, including unsafe FFI bindings,
secret handling, session and object access, and provider interaction, are in
scope. Vulnerabilities in a third-party PKCS #11 provider should also be
reported to that provider; please mention it in the report to us when it
affects this project.
