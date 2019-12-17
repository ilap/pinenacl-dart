## 0.1.0-dev.1

- The initial `draft` version.

## 0.1.0

- Added the `byte-length` official SHA-512 test vectors.
- Added `hashing` example
- Allowed `personalisation` paramater to be less then 16 bytes long by zero-padding to 16 bytes.

## 0.1.1-dev.1

- Added the `Curve25519`'s official `DH (Diffie-Hellman)` test vector.
- Added the `Wycheproof`'s X25519 test vectors.

## 0.1.1-dev.2

- Refactored the `EncryptionMessage` classes

## 0.1.1

- Refactored the library for using a simplified API.
- Refactored `AsymmetricKey` and `AsymmetricPrivateKey` classes.
- Refactored `ByteList` to be `unmodofiable`
- Refactored `EncrytpionMessage` based classes e.g. `EncryptedMessage`, `SealedMessage` and `SignedMessage`.
- Refactored `SigningKey` and `VerifyKey` by adding `Sign` and `Verify` interfaces.
- Bumped version to 0.1.1

## 0.1.2-dev.1

- Added Class diagrams.
- Added ByteList's immutability tests.

## 0.1.2-dev.2

- Added TweetNaclExt (Extension) class, that implements the HMAC-SHA-512's based `crypto_auth` 
and `crypto_auth_verify` functions of the `NaCl` library (does not exists in TweetNaCl).
- Added HMAC-SHA-512.
- Added HMAC-SHA-512 unit tests.
- Added some `TweetNaCl`'s tests.
- Cleaned some code.
- Fixed exports.
- Renamed _EncryptionMessage class to SuffixByteList.
- Fixed `ByteList`'s constructor

## 0.1.2-dev.3

- Added SHA-256.
- Added SHA-256 unit tests with the official testvectors.
- Fixed some typos.
- Added scalar_base for Ed25519Bip32 compatibility
- Added Encoding classes.
- Renamed `ed25519_vectors.json` (RFC8032's EdDSA) to `eddsa_ed25519_vectors.json`.

## 0.1.2-dev.4

- Refactored `SuffixByteList` class to `Suffix` mixin.
- Updated README.md (added HMAC, SHA-256)
- Refactored the `Encoding` classes.
- Swapped `Bech32` to the github version, as pub package does not have custom length for messages.

## 0.1.2
- Complete refactor of the API and the base classes.
- Added API class diagrams.
- Swapped `Bech32` back to the latest and working pub package.
- Refactored the `decode` factories.

## 0.1.3-dev.1
- Added constructor for `EncryptedMessage` class, see ilap/pinenacl-dart#3
