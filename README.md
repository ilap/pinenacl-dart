# PineNaCl

[![Pub Version (stable)](https://img.shields.io/pub/v/pinenacl?color=important&label=pub%20stable&logo=dart)](https://pub.dartlang.org/packages/pinenacl) 
[![Pub Version (including pre-releases)](https://img.shields.io/pub/v/pinenacl?color=blueviolet&label=pub%20prerelease&include_prereleases&logo=dart)](https://pub.dartlang.org/packages/pinenacl)
[![Dart Test CI](https://github.com/ilap/pinenacl-dart/workflows/Dart%20Test%20CI/badge.svg)](https://github.com/ilap/pinenacl-dart/actions?query=workflow%3A%22Dart+Test+CI%22)


PineNaCl is a Dart implementation of the [`TweetNaCl`](https://tweetnacl.cr.yp.to/) the world's first auditable [high-security cryptographic library](https://tweetnacl.cr.yp.to/tweetnacl-20140917.pdf).

This dart implementation based on the [`tweetnacl-dart`](https://github.com/jspschool/tweetnacl-dart) library, but it's slightly rewritten and extended by some higher level API implementations, similar to the [PyNaCl library's APIs and concepts](https://github.com/pyca/pynacl),  for `real-life` applications.

Thes library has the aim of 
- improving the
    - usability, by implementing high-level and simple-to-use APIs,
    - security and speed, by using the dart implementation of the high-security `TweetNaCl` library.
- and providing a simple API for creating real-life applications easier.

# Installing

1. Add the following into the `pubspec.yaml` of your dart package:
``` yaml
dependencies:
  pinenacl: ^0.1.5
```

2. You can install now from the command line with pub:
```
$ pub get
```

3. In your `Dart` code, you can use the similar:

``` dart
import 'package:pinenacl/api.dart';
import 'package:pinenacl/public.dart';
```

# Features

`PineNaCl` reuses a lot of terminologies, concepts, sections of documents and implements examples and some features from, the before mentioned [PyNaCl](https://github.com/pyca/pynacl)'s publicly available  [readthedocs.io](https://pynacl.readthedocs.io).

Implemented features:
- __ECDH__ (with Curve25519) for key exchange (authenticated encryptions)
  - **_Public-key Encryption_** 
    - Box (public-key authenticated encryption) and
    - SealedBox
  - **_Private-key encryption_**
    - SecretBox (private-key authenticated encryption)
- __EdDSA__ for **_Digital signatures_** (signing). It is complete (they are valid for all points on the curve) and deterministic i.e. no unique random nonce is required.
  - __Ed25519__ Signatures i.e. Curve25519 with SHA-512.
- **_Hashing_** and **_message authentication_**
  - SHA-256,
  - SHA-512, the default hashing algorithm of the original `TweetNaCl`
  - BLAKE2b for KDF and MAC (not implemented in `TweetNaCl`).
  - HMAC-SHA512.
- **_Password based key derivation_** and **_password hashing_**.
  - **PBKDF2** with `HMAC-SHA512`, iterating the `HMAC-SHA512` many times on a combination of the password and a **_random salt_**.


## Low-level Functions supported by `PineNaCl`

This library supports all 25 of the [C NaCl functions](#functions_supported_by_tweetnacl), that can be used to build `NaCl` applications.
1. crypto_box = crypto_box_curve25519xsalsa20poly1305
2. crypto_box_open
3. crypto_box_keypair
4. crypto_box_beforenm
5. crypto_box_afternm
6. crypto_box_open_afternm
7. crypto_core_salsa20
8. crypto_core_hsalsa20
9. crypto_hashblocks = crypto_hashblocks_sha512
10. crypto_hash = crypto_hash_sha512
11. crypto_onetimeauth = crypto_onetimeauth_poly1305
12. crypto_onetimeauth_verify
13. crypto_scalarmult = crypto_scalarmult_curve25519
14. crypto_scalarmult_base
15. crypto_secretbox = crypto_secretbox_xsalsa20poly1305
16. crypto_secretbox_open
17. crypto_sign = crypto_sign_ed25519
18. crypto_sign_keypair
19. crypto_sign_open
20. crypto_stream = crypto_stream_xsalsa20
21. crypto_stream_salsa20
22. crypto_stream_salsa20_xor
23. crypto_stream_xor
24. crypto_verify_16
25. crypto_verify_32

However a simple `NaCl` application would only need the following six high-level NaCl API functions.
- crypto_box for public-key authenticated encryption;
- crypto_box_open for verification and decryption;
- crypto_box_keypair to create a public key (scalarmult _k_ with basepoint _B_=9) for key exchange.

Similarly for signatures
- crypto_sign,
- crypto_sign_open, and
- crypto_sign_keypair, to create signing keypair for signing (scalarmult _k_ with basepoint _B_=(x, 4/5))

### Extension to the `TweetNaCl`

The following `NaCl` library's high-level functions are implemented as the extension to the `TweetNaCl` library.

- HMAC-SHA512 and HMAC-SHA256
   - crypto_auth = crypto_auth_hmacsha512, HMAC-SHA-512
   - crypto_auth_hmacsha256, HMAC-SHA-256
 - Hashing algorithm
   - crypto_hash_sha256, SHA-256
 - Utils
   - crypto_verify_64, verifying function for SHA-512 as an example
 - X25519 conversion utilities
   - crypto_sign_ed25519_sk_to_x25519_sk
   - crypto_sign_ed25519_pk_to_x25519_pk
 - Curve25519 low-level functions
   - scalar_base, for retrieving different type of public-keys e.g. `A = k * B`.
   - point_add, for adding two public keys' point together `A = y1 : y2`.


## Key Types

| Key id*     | Alt key id   | Key length | Function                        | Comment                                                                                          |
|-------------|---------------|------------|---------------------------------|--------------------------------------------------------------------------------------------------|
| ed25519_sk  | ed25519_skpk  |     64     | Digital Signatures (EdDSA)      | `Ed25519` signing key. It can be converted to `X25519` secret key for authenticated encryption.  |
| ed25519_pk  |               |     32     | Digital Signatures (EdDSA)      | `Ed25519` verifying key. It can be converted to `X25519` public key for authenticated encryption |
| x25519_sk   | curve25519_sk |     32     | Authenticated encryption (ECDH) | `X25519` private key.                                                                            |
| x25519_pk   | curve25519_pk |     32     | Authenticated encryption (ECDH) | `X25519` public key.                                                                             |
| ed25519e_sk | ed25519_esk   |     64     | EdDSA and ECDH                  | The first 32 byte is a valid `X25519` secret key.                                                |
| ed25519_pk  | ed25519e_pk   |     32     | EdDSA                           | It's an `Ed25519` verifying key, so it can be converted to `X25519` public key.                  |


__*__: Key id is the Human-Readable Part (HRP) of the Bech32 (binary-to-text encoding standard/scheme) encoded keys used in `pinenacl-dart`.

## Examples

`PineNaCl` comes /w the following examples:
- `Public Key Encryption` examples
  - [Box](#box) example and its [source code](example/box.dart).
  - [SealedBox](#sealedbox) example and its [source code](example/sealedbox.dart).
- `Private Key Encryption` example
  - [SecretBox](#secretbox) example and its [source code](example/secretbox.dart).
- `Digital Signatures` example
  - [Signatures](#signing) example and its [source code](example/signature.dart).
- `Hashing` example
  - [Hashing](#hashing) example and its [source code](example/hashing.dart).


### `Public Key Encryption` example

Implemented from [PyNaCl's example](https://pynacl.readthedocs.io/en/stable/public/#examples)

#### Box 
> Imagine Alice wants something valuable shipped to her. Because it’s valuable, she wants to make sure it arrives securely (i.e. hasn’t been opened or tampered with) and that it’s not a forgery (i.e. it’s actually from the sender she’s expecting it to be from and nobody’s pulling the old switcheroo).
>
> One way she can do this is by providing the sender (let’s call him Bob) with a high-security box of her choosing. She provides Bob with this box, and something else: a padlock, but a padlock without a key. Alice is keeping that key all to herself. Bob can put items in the box then put the padlock onto it. But once the padlock snaps shut, the box cannot be opened by anyone who doesn’t have Alice’s private key.
>
> Here’s the twist though: Bob also puts a padlock onto the box. This padlock uses a key Bob has published to the world, such that if you have one of Bob’s keys, you know a box came from him because Bob’s keys will open Bob’s padlocks (let’s imagine a world where padlocks cannot be forged even if you know the key). Bob then sends the box to Alice.
>
> In order for Alice to open the box, she needs two keys: her private key that opens her own padlock, and Bob’s well-known key. If Bob’s key doesn’t open the second padlock, then Alice knows that this is not the box she was expecting from Bob, it’s a forgery.
>
>This bidirectional guarantee around identity is known as mutual authentication.
>
> -- <cite>[PyNaCl](https://pynacl.readthedocs.io/en/stable/public/#examples)</cite>

``` dart
import 'package:pinenacl/api.dart';
import 'package:pinenacl/public.dart' show PrivateKey;

void main() {
  // Generate Bob's private key, which must be kept secret
  final skbob = PrivateKey.generate();

  // Bob's public key can be given to anyone wishing to send
  // Bob an encrypted message
  final pkbob = skbob.publicKey;

  // Alice does the same and then Alice and Bob exchange public keys
  final skalice = PrivateKey.generate();

  final pkalice = skalice.publicKey;

  // Bob wishes to send Alice an encrypted message so Bob must make a Box with
  // his private key and Alice's public key
  final bobBox = Box(myPrivateKey: skbob, theirPublicKey: pkalice);

  // This is our message to send, it must be a bytestring as Box will treat it
  // as just a binary blob of data.
  final message = 'There is no conspiracy out there, but lack of the incentives to drive the people towards the answers.';

  // TweetNaCl can automatically generate a random nonce for us, making the encryption very simple:
  // Encrypt our message, it will be exactly 40 bytes longer than the
  // original message as it stores authentication information and the
  // nonce alongside it.
  final encrypted = bobBox.encrypt(message.codeUnits);

  // Finally, the message is decrypted (regardless of how the nonce was generated):
  // Alice creates a second box with her private key to decrypt the message
  final aliceBox = Box(myPrivateKey: skalice, theirPublicKey: pkbob);

  // Decrypt our message, an exception will be raised if the encryption was
  // tampered with or there was otherwise an error.
  final decrypted = aliceBox.decrypt(encrypted);
  print(String.fromCharCodes(decrypted.plaintext));
}
```

#### SealedBox

> The SealedBox class encrypts messages addressed to a specified key-pair by using ephemeral sender’s keypairs, which will be discarded just after encrypting a single plaintext message.
> 
> This kind of construction allows sending messages, which only the recipient can decrypt without providing any kind of cryptographic proof of sender’s authorship.
> 
> __Warning__
>
> By design, the recipient will have no means to trace the ciphertext to a known author, since the sending keypair itself is not bound to any sender’s identity, and the sender herself will not be able to decrypt the ciphertext she just created, since the private part of the key cannot be recovered after use.
>
> -- <cite>[PyNaCl](https://pynacl.readthedocs.io/en/stable/public/#examples)</cite>

``` dart
import 'package:pinenacl/public.dart' show SealedBox, PrivateKey;

void main() {

  // Generate Bob's private key, which must be kept secret
  final skbob = PrivateKey.generate();
  final pkbob = skbob.publicKey;

  // Alice wishes to send a encrypted message to Bob,
  // but prefers the message to be untraceable
  // she puts it into a secretbox and seals it.
  final sealedBox = SealedBox(pkbob);

  final message = 'The world is changing around us and we can either get '
      'with the change or we can try to resist it';

  final encrypted = sealedBox.encrypt(message.codeUnits);

  // Bob unseals the box with his privatekey, and decrypts it.
  final unsealedBox = SealedBox(skbob);

  final plainText = unsealedBox.decrypt(encrypted);
  print(String.fromCharCodes(plainText));
  assert(message == String.fromCharCodes(plainText));
}
```
### A `Secret Key Encryption` example 

Implemented from [PyNaCl's example](https://pynacl.readthedocs.io/en/stable/private/#examples)

#### SecretBox
> Secret key encryption (also called symmetric key encryption) is analogous to a safe. You can store something secret through it and anyone who has the key can open it and view the contents. SecretBox functions as just such a safe, and like any good safe any attempts to tamper with the contents are easily detected.
>
> Secret key encryption allows you to store or transmit data over insecure channels without leaking the contents of that message, nor anything about it other than the length.
>
> -- <cite>[PyNaCl](https://pynacl.readthedocs.io/en/stable/secret/#secret-key-encryption)</cite>

``` dart
import 'package:pinenacl/api.dart';
import 'package:pinenacl/secret.dart' show SecretBox;

void main() {
  final key = Utils.randombytes(SecretBox.keyLength);
  final box = SecretBox(key);

  final message = 'Change is a tricky thing, it threatens what we find familiar with...';

  final encrypted = box.encrypt(message.codeUnits);

  final decrypted = box.decrypt(encrypted);

  final ctext = encrypted.ciphertext;

  assert(ctext.length == message.length + SecretBox.macBytes);

  final plaintext = String.fromCharCodes(decrypted.plaintext);
  print(plaintext);
  assert(message == plaintext);
}
```

### `Digital Signatures` example 

Implemented from [PyNaCl's example](https://pynacl.readthedocs.io/en/stable/public/#examples)

#### Signing
> You can use a digital signature for many of the same reasons that you might sign a paper document. A valid digital signature gives a recipient reason to believe that the message was created by a known sender such that they cannot deny sending it (authentication and non-repudiation) and that the message was not altered in transit (integrity).
> 
> Digital signatures allow you to publish a public key, and then you can use your private signing key to sign messages. Others who have your public key can then use it to validate that your messages are actually authentic.
>
> -- <cite>[PyNaCl](https://pynacl.readthedocs.io/en/stable/signing)</cite>

``` dart
import 'package:convert/convert.dart';
import 'package:pinenacl/signing.dart';

void main() {
  /// 
  /// Signer’s perspective (SigningKey)
  ///
 
  // Generate a new random signing key
  final signingKey = SigningKey.generate();

  final message = 'People see the things they want to see...';
  // Sign a message with the signing key
  final signed = signingKey.sign(message.codeUnits);

  //  Obtain the verify key for a given signing key
  final verifyKey = signingKey.verifyKey;

  // Serialize the verify key to send it to a third party
  final verifyKeyHex = hex.encode(verifyKey);

  /// 
  /// Verifier’s perspective (VerifyKey)
  /// 
  final verifyKey2 = VerifyKey.fromHexString(verifyKeyHex);
  assert(verifyKey == verifyKey2);
  print('The "$message" is successfully verified');

  // Check the validity of a message's signature
  // The message and the signature can either be passed separately or
  // concatenated together.  These are equivalent:
  verifyKey.verify(signed);
  verifyKey.verify(signed.message, signed.signature);

  // Alter the signed message text
  signed[0] ^= signed[0] + 1;

  try {
    // Forged message.
    verifyKey.verify(signed);
  } on Exception catch(e) {
    print('Successfully cought: $e');
  }
}
```

### `Hashing` example 
Implemented from [PyNaCl's example](https://pynacl.readthedocs.io/en/stable/hashing/#examples)

> Cryptographic secure hash functions are irreversible transforms of input data to a fixed length digest.
> 
> The standard properties of a cryptographic hash make these functions useful both for standalone usage as data integrity checkers, as well as `black-box` building blocks of other kind of algorithms and data structures.
> 
> All of the hash functions exposed in `hashing` can be used as data integrity checkers.
>
>
> As already hinted above, traditional cryptographic hash functions can be used as building blocks for other uses, typically combining a secret-key with the message via some construct like the HMAC one.
>
> -- <cite>[PyNaCl](https://pynacl.readthedocs.io/en/stable/signing)</cite>

### Blake2b

> The `blake2b` hash function can be used directly both for `message authentication` and `key derivation`, replacing the HMAC construct and the HKDF one by setting the additional parameters `key`, `salt` and `person`.
> 
> __`Warning`__
>
> Please note that key stretching procedures like `HKDF` or the one outlined in `Key derivation` are not suited to derive a `cryptographically-strong key` from a `low-entropy input` like a `plain-text password` or to compute a strong long-term stored hash used as password verifier.
>
>
> -- <cite>[PyNaCl](https://pynacl.readthedocs.io/en/stable/hashing)</cite>

#### Hashing
``` dart
...
void main() {

  final hasher = Hash.blake2b;


  print('Hash example\nH(\'\'): ${hex.encode(hasher(''))}');
```

#### Message authentication

> To authenticate a message, using a secret key, the blake2b function must be called as in the following example.

``` dart
  /// It can ganarate a MAC to be sure that the message is not forged.

  final msg = '256 BytesMessage' * 16;

  // the simplest way to get a cryptographic quality authKey
  // is to generate it with a cryptographic quality
  // random number generator
  final authKey = Utils.randombytes(64);
  final mac = hasher(msg, key: authKey);

  print('MAC(msg, authKey): ${hex.encode(mac)}.\n');
```

#### Key derivation

> The blake2b algorithm can replace a key derivation function by following the lines of:
``` dart
  print('Key derivation example');
  final masterKey = Utils.randombytes(64);
  final derivationSalt = Utils.randombytes(16);

  final personalisation = Uint8List.fromList('<DK usage>'.codeUnits);

  final subKey = hasher('', key: masterKey, salt: derivationSalt, personalisation: personalisation);
  print('KDF(\'\', masterKey, salt, personalisation): ${hex.encode(subKey)}');
```

> By repeating the key derivation procedure before encrypting our messages,  and sending the derivationSalt along with the encrypted message, we can expect to never reuse a key, drastically reducing the risks which ensue from such a reuse.
# TODOS

- [ ] **Important**: refactor for working in 32-bit systems and browser (js).
- [ ] Implement proper Error/Exception handling.
- [x] Implement encoding/decoding) classes. 
- [x] Add more unit tests.
- [x] Refactor to much simpler code.
- [x] Simplify or refactor the APIs and modules' dependencies.
- [x] Remove [bech32], [hex] and [convert] pakages dependency.
- [x] Remove [fixnum] pakage dependency.
- [x] Add Ed25519 to X25519 function, to allow Ed25519 to be used in
authenticated encryption too, see note below.
- [ ] Refactor hashers to have some similar methods such: init(), update(), finalize() etc.
- [x] Refactor key derivation function to be able to use diff `hmac`s.
- [x] Optimise `SHA-256` for faster execution. Done 5 time faster now 0.41 sec instead of 3.1 sec for 256K iterations.
- [ ] Optimise `SHA-512` for faster execution. 
- [x] Add some benchmark files.
- [ ] **IMPORTANT**. refactor, rewrite source code for security auditing.

Note: `Ed25519` keys that are used only for digital signatures (EdDSA), can be
converted to `Curve25519/X25519` key (that is used only for authenticated encryption i.e.
ECDH), therefore the same key pairs can be used for
- digital signatures (EdDSA), as it's already used, using `crypto_sign` and
- authenticated encryption (ECDH) using `crypto_box`.

# Thanks and Credits

- [PyNaCl library](https://github.com/pyca/pynacl)
- [TweetNaCl dart implementation](https://github.com/jspschool/tweetnacl-dart)
- [TweetNaCl: a crypto library in 100 tweets](https://tweetnacl.cr.yp.to/index.html)
- [blake2b](https://github.com/emilbayes/blake2b)
- [bech32](https://github.com/haarts/bech32)
- And many others...

# References
- [How do Ed5519 keys work?](https://blog.mozilla.org/warner/2011/11/29/ed25519-keys/)
- [Using Ed25519 signing keys for authenticated encryption](https://blog.filippo.io/using-ed25519-keys-for-encryption/)
- [The Provable Security of Ed25519: Theory and Practice](https://eprint.iacr.org/2020/823.pdf)
- [Implementing Curve25519/X25519: A Tutorial on Elliptic Curve Cryptography](https://martin.kleppmann.com/papers/curve25519.pdf)

# License

- [MIT License](LICENSE)
