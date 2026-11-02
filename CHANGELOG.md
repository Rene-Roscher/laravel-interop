# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `Envelope::seal()` / `open()`: the Interop Envelope v1, an expiring and scoped payload that is
  encrypted with `encryptString()`, with `Expiry::in()`, `at()` and `never()`, `notBefore:`,
  `leeway:` and `now:`.
- The exceptions `EnvelopeInvalid`, `EnvelopeUnsupportedVersion`, `EnvelopeScopeMismatch`,
  `EnvelopeNotYetValid` and `EnvelopeExpired`, with the verdict names shared by all implementations.
- A service provider that binds `Envelope` to the application's encrypter.
- Shared test vectors (`fixtures/envelope-vectors.json`), `bin/verify-tokens.php` for the Rust, Go and
  Node.js packages, and an end-to-end matrix (`e2e/run.sh`) in which PHP, Rust, Go and Node.js each
  judge the tokens of each of the four.
