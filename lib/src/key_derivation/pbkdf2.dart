import 'dart:typed_data';

import 'package:pinenacl/tweetnacl.dart';
import 'package:pinenacl/src/utils/utils.dart';

///
/// PBKDF2 (RFC 2898) is a cryptographic key derivation function, which is
/// resistant to rainbow table- and dictionary attacks.
///
/// This is very simple implementation of the PBKDF2 that iteratively deriving
/// hmac (currently only HMAC-SHA512) with a cryptographically secure `salt`.
///
class PBKDF2 {
  // TODO: currently only HMAC-SHA-512 and HMAC-SHA-256 are implemented.
  static Uint8List hmac_sha512(
      Uint8List password, Uint8List salt, int count, int key_length) {
    var hasher = TweetNaClExt.crypto_auth_hmacsha512;
    return _deriveKey(hasher, 64, password, salt, count, key_length);
  }

  static Uint8List hmac_sha256(
      Uint8List password, Uint8List salt, int count, int key_length) {
    var hasher = TweetNaClExt.crypto_auth_hmacsha256;
    return _deriveKey(hasher, 32, password, salt, count, key_length);
  }

  static Uint8List _deriveKey(MacHasher hasher, int hash_length,
      Uint8List password, Uint8List salt, int count, int key_length) {
    if (count <= 0 || key_length < 1 || key_length > 0xffffffff) {
      throw Exception();
    }

    final block_count = (key_length / hash_length).ceil();

    final derived_key = Uint8List(key_length + hash_length);
    final _U = Uint8List(hash_length);

    final idx = [0, 0, 0, 0];

    for (var i = 1; i <= block_count; i++) {
      // `block` is encoded as 4 bytes big endian
      idx[0] = (i >> 24) & 0xff;
      idx[1] = (i >> 16) & 0xff;
      idx[2] = (i >> 8) & 0xff;
      idx[3] = i & 0xff;

      final message = Uint8List.fromList([...salt, ...idx]);

      hasher(_U, message, password);

      final offset = (i - 1) * hash_length;

      PineNaClUtils.listCopy(_U, hash_length, derived_key, offset);

      for (var j = 1; j < count; j++) {
        hasher(_U, _U, password);

        for (var k = 0; k < hash_length; k++) {
          derived_key[k + offset] ^= _U[k];
        }
      }
    }

    var result = derived_key.sublist(0, key_length);

    PineNaClUtils.listZero(_U);
    PineNaClUtils.listZero(derived_key);

    return result;
  }
}
