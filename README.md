# PineNaCl

[![pub package](https://img.shields.io/pub/v/pinenacl.svg)](https://pub.dartlang.org/packages/pinenacl)

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
  slip39: ^0.1.0-dev.1
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

## Examples

`DartNaCl` comes /w the following examples:
- [Box](example/box.dart)
- [SealedBox](example/sealedbox.dart)
- [SecretBox](example/secretbox.dart)
- [Signatures](example/signature.dart)

### The Public Key Encryption example from [PyNaCl](https://pynacl.readthedocs.io/en/stable/public/#examples)

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

# TODOS

- [ ] Add more unit tests.
- [ ] Refactor to much simpler code.
- [ ] Simplify the APIs and modules' dependencies.
- [ ] Remove [fixnum] and [convert] pakages' dependency.

# Features

`PineNaCl` reuses a lot of terminologies, concepts, sections of documents and implements examples and some features from, the before mentioned [PyNaCl](https://github.com/pyca/pynacl)'s publicly available  [readthedocs.io](https://pynacl.readthedocs.io).

Implemented features:
- Public-key Encryption
  - Box (public-key authenticated encryption) and
  - SealedBox
- Private-key encryption
  - SecretBox (private-key authenticated encryption)
- Digital signatures
  - Signatures, curve25519 and ed25519.
- Hashing
  - SHA512, the default hashing algorithm of the original `TweetNaCl`
  - BLAKE2b, for KDF and MAC.

## Low-level Functions supported by DartNaCl

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
- crypto_box_keypair to create a public key

Similarly for signatures
- crypto_sign,
- crypto_sign_open, and
- crypto_sign_keypair.

# Thanks and Credits

- [PyNaCl library](https://github.com/pyca/pynacl)
- [TweetNaCl dart implementation](https://github.com/jspschool/tweetnacl-dart)
- [TweetNaCl: a crypto library in 100 tweets](https://tweetnacl.cr.yp.to/index.html)
- [blake2b](https://github.com/emilbayes/blake2b)

# License

- [MIT License](LICENSE)
