# Security Policy

## Scope

CryptoVault is a local security-focused portfolio project. It has not undergone an
independent security audit or formal cryptographic review.

## Reporting a vulnerability

Please do not publish a suspected vulnerability with exploit details in a public
issue before the maintainer has had an opportunity to investigate it. Contact the
maintainer through the contact method listed on the GitHub profile/repository.

When reporting, include:
- affected version/commit;
- operating system and Python version;
- minimal reproduction steps;
- security impact;
- whether the issue affects the vault, file encryption, HMAC, GUI, or web demo.

Do not include real passwords, private keys, API tokens, or personal data.

## Security guarantees and limitations

CryptoVault is designed to protect secrets at rest against an attacker who obtains
only encrypted vault/file data and does not know the passphrase. It does not protect
against malware on an unlocked machine, keyloggers, clipboard capture, process-memory
inspection, weak/reused passphrases, filesystem rollback, deletion, or all forms of
local metadata leakage.

The GitHub Pages website contains an educational WebCrypto sandbox. It is not the
desktop vault and must not be used with production credentials or real secrets.
