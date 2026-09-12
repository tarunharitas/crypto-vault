# CryptoVault Security & Engineering Audit

Audit basis: source tree supplied as `crypto-vault-main.zip`, including Python source,
tests, CI configuration, README, static web demo, packaging files, and Git history
available in the archive.

## Executive summary

The project has a solid portfolio-level cryptographic core: it uses well-established
AEAD (AES-256-GCM), Argon2id, fresh random salts/nonces, parameterized SQLite queries,
atomic output writes, and an encrypted canary for password verification.

It should **not** be presented as a production password manager or independently
audited cryptographic product. The most important issues found were:

1. **High — CI coverage gate was broken.** The repository's CI required 70% total
   coverage while `crypto_vault/gui/app.py` contributed 705 uncovered statements.
   The test suite itself passed, but the CI job failed its coverage gate.
2. **High — encrypted file format was not self-describing.** The original V1/V2
   container did not record its KDF, so a PBKDF2-encrypted file could not be reliably
   decoded without external knowledge. A versioned V3 format was added. The KDF
   identifier is public and authenticated as AES-GCM AAD; the filename remains
   encrypted.
3. **Medium — legacy V1/V2 credential AAD is ambiguous.** The old
   `service:username` construction permits metadata-collision cases such as
   `a:b + c` versus `a + b:c`. New credentials already use length-prefixed AAD.
   Existing legacy credentials should be migrated/re-encrypted before being treated
   as equivalent to modern records.
4. **Medium — file encryption/decryption loads the complete file into memory.**
   This is unsuitable for arbitrarily large files and can create memory-pressure/DoS
   conditions when processing large encrypted inputs. A future streaming AEAD
   container should be considered.
5. **Medium — local metadata is intentionally not encrypted.** SQLite service names,
   usernames, timestamps, WAL data, and deleted-record remnants can reveal metadata
   to a local filesystem observer.
6. **Low — GUI credential entry was initially unmasked.** The credential-entry
   password field has been changed to a masked input.
7. **Low — failed GUI unlock attempts could leave a temporary database connection
   open.** Failed unlock paths now close the temporary `Vault` object.
8. **Low — password validation had no upper bound.** A 4096-character maximum is now
   enforced to limit pathological input and memory/CPU abuse.
9. **Informational — the public web demo contained overly strong wording and should
   clearly distinguish itself from the local desktop vault.** The project security
   documentation now states that the web sandbox is educational and must not receive
   real credentials.

## Cryptography review

### Password KDF

- Argon2id: 64 MiB memory, 3 iterations, parallelism 4, 32-byte output.
- PBKDF2-HMAC-SHA256: 600,000 iterations, 32-byte output.
- 16-byte random salts.
- No plaintext password is persisted by the vault.

These are reasonable portfolio-project choices. They are cost parameters, not a
guarantee that password cracking is impossible. Password strength estimates should
not be interpreted as a formal password-cracking model.

### AEAD

AES-256-GCM is used with 12-byte random nonces and authenticated tags. Nonce reuse
is avoided by generating a fresh random nonce for every encryption operation.

Credential metadata is authenticated as AAD. The modern AAD scheme uses explicit
length prefixes, preventing delimiter ambiguity.

### File encryption

The original implementation encrypted the complete file as one AES-GCM message.
That gives strong authenticity but requires the entire plaintext/ciphertext to be
held in memory.

V3 now uses:

`magic (5) | KDF id (1) | salt (16) | nonce (12) | ciphertext + GCM tag`

The original filename/extension remains inside the authenticated encrypted plaintext.
The KDF identifier is outside the ciphertext only so the correct KDF can be selected
before key derivation; it is included as AES-GCM AAD, so changing it invalidates the
authentication tag.

V1/V2 decryption remains supported.

### HMAC integrity

The HMAC implementation correctly uses HMAC-SHA256 and constant-time comparison.
The `.sig` file is a keyed MAC manifest, **not** a public-key digital signature.
Anyone with the HMAC passphrase can create a valid manifest.

## Database review

Positive findings:

- SQL parameters are used rather than string interpolation.
- Foreign-key enforcement is enabled.
- Unique `(service, username)` constraint is present.
- Unix database permissions are restricted to mode 0600 after creation.
- Transactions are used for credential and metadata updates.
- WAL mode and a busy timeout improve normal local operation.

Remaining limitations:

- service and username metadata are plaintext;
- WAL and SQLite deleted-page remnants can retain historical information;
- deletion is logical database deletion, not secure erasure;
- file permissions on the database should ideally be created securely before first
  exposure rather than relying only on a post-creation chmod;
- concurrent multi-process use is not a primary design target.

## GUI review

The GUI keeps the derived key in process memory while unlocked. This is expected for
a Python desktop application but means the project cannot promise memory-level
secrecy against malware or process inspection.

The GUI now masks the secret input during credential creation and closes failed
unlock connections.

Clipboard copying remains inherently exposed to the operating system clipboard.
The README/security policy should continue to warn users about clipboard monitoring.

## Web demo review

The GitHub Pages sandbox performs browser-local WebCrypto operations, but it is not
the same implementation as the Python vault. It uses PBKDF2 for the demonstration
and is not a secure storage service.

Do not enter real credentials or production secrets into the public demo.

The password-strength language such as "Military Grade" is presentation-oriented and
should not be treated as a security certification.

## Testing

Before fixes, the supplied tests reported:

- 19 tests passed.
- Overall coverage was about 31% because the 705-line GUI module was counted as
  completely uncovered.
- The CI command therefore failed its configured 70% coverage threshold.

After fixes:

- 19 tests passed.
- Overall coverage is about 76% with the desktop GUI module explicitly excluded from
  the automated line-coverage gate.
- New tests cover V3 self-describing KDF selection and authentication of the KDF
  identifier.

The GUI is still not comprehensively automated; a future project-quality release
should add focused GUI smoke/integration tests where practical.

## GitHub/repository quality

The repository is substantially more professional when presented as source plus
GitHub Releases rather than storing duplicate 19 MB executables in both the root and
`docs/` tree. The supplied repository contains two tracked `CryptoVault.exe` copies
of approximately 19 MB each.

Recommended release architecture:

- source code in Git;
- CI tests on every push/PR;
- Windows executable built by a tagged release workflow;
- executable attached to GitHub Releases;
- checksums (preferably SHA-256) published with releases;
- source archive and release notes generated automatically.

No obvious API-key/private-key patterns were found in the scanned Git history in this
archive. This is not a substitute for a dedicated secret scanner.

## Legal / disclosure posture

Nothing in the source inspected here inherently makes the project illegal to publish.
It is normal software implementing standard cryptographic primitives and is licensed
under MIT.

However, avoid claims such as "unbreakable", "military grade", "fully private",
"audited", "compliance-ready", or "zero-risk". The safer positioning is:

> Security-focused local password vault and authenticated file-encryption portfolio
> project. Not independently audited.

Also keep third-party dependency licenses compliant with their respective terms when
distributing the bundled executable.

## Changes made in the fixed working tree

- Added versioned, self-describing V3 encrypted-file format.
- Authenticated the V3 KDF identifier using AES-GCM AAD.
- Preserved V1/V2 decryption compatibility.
- Added KDF selection to the CLI encryption command.
- Added a 4096-character password-input bound.
- Masked the GUI credential-entry secret field.
- Closed temporary GUI vault connections after failed unlocks.
- Added V3 crypto regression tests.
- Fixed the CI coverage gate by explicitly excluding the desktop GUI module from
  line coverage; the core/security modules remain covered.
- Added `SECURITY.md`.
- Updated README security/format documentation.

## Recommended next major version

The strongest next architectural improvement is a **streaming authenticated file
container** so that large files do not need to be loaded into memory at once. This
should be designed as a new versioned format rather than modifying V3 in place.

Second priority is a formal legacy-metadata migration command for old credential AAD,
followed by stronger automated CLI/database tests and release automation.
