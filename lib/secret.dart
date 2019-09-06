import "dart:core";
import 'dart:typed_data';

import 'package:pinenacl/src/crypto/tweetnacl.dart';

import 'api.dart';

/// From: [PyNaCl's readthedocs](https://pynacl.readthedocs.io)
///
/// Secret Key Encryption
///
/// Secret key encryption (also called symmetric key encryption) is analogous to a safe.
/// You can store something secret through it and anyone who has the key can open it and view the contents.
/// SecretBox functions as just such a safe, and like any good safe any attempts to tamper
/// with the contents are easily detected.
///
/// Secret key encryption allows you to store or transmit data over insecure channels without leaking the contents of that message,
/// nor anything about it other than the length.
///
/// Secretbox uses XSalsa20 and Poly1305 to encrypt and authenticate messages with secret-key cryptography.
/// The length of messages is not hidden.
///
/// It is the caller's responsibility to ensure the uniqueness of nonces—for example,
/// by using nonce 1 for the first message, nonce 2 for the second message, etc.
/// Nonces are long enough that randomly generated nonces have negligible risk of collision.
///
/// Messages should be small because:
/// 1. The whole message needs to be held in memory to be processed.
/// 2. Using large messages pressures implementations on small machines to decrypt and
/// process plaintext before authenticating it. This is very dangerous, and this API
/// does not allow it, but a protocol that uses excessive message sizes might present
/// some implementations with no other choice.
/// 3. Fixed overheads will be sufficiently amortised by messages as small as 8KB.
/// 4. Performance may be improved by working with messages that fit into data caches.
/// Thus large amounts of data should be chunked so that each message is small.
/// (Each message still needs a unique nonce.) If in doubt, 16KB is a reasonable chunk size.
///
class SecretBox extends BaseBox {
  SecretBox(List<int> secret) : super.fromList(secret);
  SecretBox.fromHexString(String hexaString) : super.fromHexString(hexaString);
  static const keyLength = TweetNaCl.keyLength;
  static const macBytes = TweetNaCl.macBytes;
  @override
  AsymmetricKey get key => this;

  @override
  Uint8List doEncrypt(Uint8List ciphertext, Uint8List plaintext, int pLen,
      Uint8List nonce, Uint8List k) {
    return TweetNaCl.crypto_secretbox(
        ciphertext, plaintext, pLen, nonce, k);
  }

  @override
  Uint8List doDecrypt(Uint8List plaintext, Uint8List ciphertext, int cLen,
      Uint8List nonce, Uint8List k) {
    return TweetNaCl.crypto_secretbox_open(
        plaintext, ciphertext, cLen, nonce, k);
  }
}
