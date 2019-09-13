## 0.1.0-dev.1

- The initial `draft` version.

## 0.1.0

- Added the `byte-length` official SHA512 test vectors.
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

## 0.1.1-dev.1

- Added Class diagrams.
