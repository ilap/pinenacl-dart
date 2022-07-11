# Changelog

## v0.4.2
Added bytes length for decoding ByteList

## v0.4.1
Updated CHANGELOG
Updated README.md
Switched to lint

## v0.4.0
Bumped to v0.4.0 due to the v0.3.5's API breaks

## v0.3.5
Fixing LateInitializationError: Field 'prefixLength' has not been initialized - take 2 (#18).

## v0.3.4
Fixing SigningKey decode issue (#17).

## v0.3.3
Remove unnecessry 0xff masks.

## v0.3.2
Fixed #15 that caused the ciphertext differ from messages bigger than 16KB

## v0.3.0

Breaking Changes

## [v0.2.1](https://github.com/ilap/pinenacl-dart/tree/v0.2.1) (2021-05-23)

## [v0.2.0](https://github.com/ilap/pinenacl-dart/tree/v0.2.0) (2021-03-06)

## [v0.2.0-nullsafety.8](https://github.com/ilap/pinenacl-dart/tree/v0.2.0-nullsafety.8) (2021-01-20)

[Full Changelog](https://github.com/ilap/pinenacl-dart/compare/v0.2.0-nullsafety.7...v0.2.0-nullsafety.8)

## [v0.2.0-nullsafety.7](https://github.com/ilap/pinenacl-dart/tree/v0.2.0-nullsafety.7) (2021-01-19)

[Full Changelog](https://github.com/ilap/pinenacl-dart/compare/v0.2.0-nullsafety.6...v0.2.0-nullsafety.7)

## [v0.2.0-nullsafety.6](https://github.com/ilap/pinenacl-dart/tree/v0.2.0-nullsafety.6) (2021-01-17)

[Full Changelog](https://github.com/ilap/pinenacl-dart/compare/v0.2.0-nullsafety.5...v0.2.0-nullsafety.6)

# Changelog

## [v0.2.0-nullsafety.5](https://github.com/ilap/pinenacl-dart/tree/v0.2.0-nullsafety.5) (2021-01-15)

[Full Changelog](https://github.com/ilap/pinenacl-dart/compare/v0.2.0-nullsafety.4...v0.2.0-nullsafety.5)

# Changelog

## [v0.2.0-nullsafety.4](https://github.com/ilap/pinenacl-dart/tree/v0.2.0-nullsafety.4) (2021-01-13)

[Full Changelog](https://github.com/ilap/pinenacl-dart/compare/v0.2.0-nullsafety.3...v0.2.0-nullsafety.4)

# Changelog

## [v0.2.0-nullsafety.3](https://github.com/ilap/pinenacl-dart/tree/v0.2.0-nullsafety.3) (2021-01-11)

[Full Changelog](https://github.com/ilap/pinenacl-dart/compare/v0.2.0-nullsafety.2...v0.2.0-nullsafety.3)

# Changelog

## [v0.2.0-nullsafety.2](https://github.com/ilap/pinenacl-dart/tree/v0.2.0-nullsafety.2) (2021-01-10)

[Full Changelog](https://github.com/ilap/pinenacl-dart/compare/v0.2.0-nullsafety.1...v0.2.0-nullsafety.2)

# Changelog

## [v0.2.0-nullsafety.1](https://github.com/ilap/pinenacl-dart/tree/v0.2.0-nullsafety.1) (2020-12-21)

[Full Changelog](https://github.com/ilap/pinenacl-dart/compare/v0.2.0-nullsafety.0...v0.2.0-nullsafety.1)

**Merged pull requests:**

- Pre-release for the null safety migration of this package. [\#7](https://github.com/ilap/pinenacl-dart/pull/7) ([ilap](https://github.com/ilap))

# Changelog

[Full Changelog](https://github.com/ilap/pinenacl-dart/compare/v0.2.0-nullsafety.0...HEAD)

**Merged pull requests:**

- Pre-release for the null safety migration of this package. [\#7](https://github.com/ilap/pinenacl-dart/pull/7) ([ilap](https://github.com/ilap))

## [v0.2.0-nullsafety.0](https://github.com/ilap/pinenacl-dart/tree/v0.2.0-nullsafety.0) (2020-11-20)

[Full Changelog](https://github.com/ilap/pinenacl-dart/compare/v0.1.5...v0.2.0-nullsafety.0)

- Pre-release for the null safety migration of this package.
- Reformatted CHANGELOG.md
- Added `in-house` HexCoder class
- Refactored, cleaned the code for preparing `null-safety`
- Removed `hex`, `bech32` and `convert` package dependencies
- Added analyzer strong-mode's `implicit-casts: false` and `implicit-dynamic: false`


## [v0.1.5](https://github.com/ilap/pinenacl-dart/tree/v0.1.5) (2020-11-20)

[Full Changelog](https://github.com/ilap/pinenacl-dart/compare/v0.1.4...v0.1.5)

- Reverted SHA-256 changes back as it behaved differently on JIT and AOT
  i.e. failed test for `pub run test` but not for `pub run tests/all*dart`
- Fixed imports

## [v0.1.4](https://github.com/ilap/pinenacl-dart/tree/v0.1.4) (2020-11-20)

[Full Changelog](https://github.com/ilap/pinenacl-dart/compare/v0.1.3...v0.1.4)

- Removed fixnum dependency from poly1305
- Code cleanup and removing fixnum dependencies from some modules.
- Bumped version to 0.1.4

**Closed issues:**

- Will this project be supported and maintained going forward? [\#5](https://github.com/ilap/pinenacl-dart/issues/5)
- Support for HKDF \(RFC 5869\) [\#4](https://github.com/ilap/pinenacl-dart/issues/4)
- Second constructor for EncryptedMessage [\#3](https://github.com/ilap/pinenacl-dart/issues/3)

## [v0.1.3](https://github.com/ilap/pinenacl-dart/tree/v0.1.3) (2019-10-03)

[Full Changelog](https://github.com/ilap/pinenacl-dart/compare/v0.1.2...v0.1.3)

- Added constructor for `EncryptedMessage` class, see ilap/pinenacl-dart#3


## [v0.1.2](https://github.com/ilap/pinenacl-dart/tree/v0.1.2) (2019-10-01)

[Full Changelog](https://github.com/ilap/pinenacl-dart/compare/v0.1.1...v0.1.2)

- Complete refactor of the API and the base classes.
- Added API class diagrams.
- Swapped `Bech32` back to the latest and working pub package.
- Refactored the `decode` factories.

### v0.1.2-dev.4

- Refactored `SuffixByteList` class to `Suffix` mixin.
- Updated README.md (added HMAC, SHA-256)
- Refactored the `Encoding` classes.
- Swapped `Bech32` to the github version, as pub package does not have custom length for messages.

### v0.1.2-dev.3

- Added SHA-256.
- Added SHA-256 unit tests with the official testvectors.
- Fixed some typos.
- Added crypto_scalar_base for Ed25519Bip32 compatibility
- Added Encoding classes.
- Renamed `ed25519_vectors.json` (RFC8032's EdDSA) to `eddsa_ed25519_vectors.json`.

### v0.1.2-dev.2

- Added TweetNaclExt (Extension) class, that implements the HMAC-SHA-512's based `crypto_auth` 
and `crypto_auth_verify` functions of the `NaCl` library (does not exists in TweetNaCl).
- Added HMAC-SHA-512.
- Added HMAC-SHA-512 unit tests.
- Added some `TweetNaCl`'s tests.
- Cleaned some code.
- Fixed exports.
- Renamed _EncryptionMessage class to SuffixByteList.
- Fixed `ByteList`'s constructor

### v0.1.2-dev.1

- Added Class diagrams.
- Added ByteList's immutability tests.

## [v0.1.1](https://github.com/ilap/pinenacl-dart/tree/v0.1.1) (2019-09-08)

[Full Changelog](https://github.com/ilap/pinenacl-dart/compare/v0.1.0...v0.1.1)

- Refactored the library for using a simplified API.
- Refactored `AsymmetricKey` and `AsymmetricPrivateKey` classes.
- Refactored `ByteList` to be `unmodofiable`
- Refactored `EncrytpionMessage` based classes e.g. `EncryptedMessage`, `SealedMessage` and `SignedMessage`.
- Refactored `SigningKey` and `VerifyKey` by adding `Sign` and `Verify` interfaces.
- Bumped version to 0.1.1

### v0.1.1-dev.2

- Refactored the `EncryptionMessage` classes

### v0.1.1-dev.1

- Added the `Curve25519`'s official `DH (Diffie-Hellman)` test vector.
- Added the `Wycheproof`'s X25519 test vectors.


## [v0.1.0](https://github.com/ilap/pinenacl-dart/tree/v0.1.0) (2019-09-07)

[Full Changelog](https://github.com/ilap/pinenacl-dart/compare/dec86ad613679b046dac1044db4744024efba6b9...v0.1.0)

- Added the `byte-length` official SHA-512 test vectors.
- Added `hashing` example
- Allowed `personalisation` paramater to be less then 16 bytes long by zero-padding to 16 bytes.

### v0.1.0-dev.1

- The initial `draft` version.
