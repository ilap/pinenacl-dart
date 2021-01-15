import 'dart:typed_data';

import '../api.dart';

typedef Hasher = void Function(Uint8List out, Uint8List text, Uint8List k);

// TODO: currently it uses only HMAC-SHA512
/// A very simple implementation of the HMAC-SHA512 based pbkdf2 for Icarus
/// style master key generation.
///
class PBKDF2 {
  static void _memcopy(Uint8List from, int from_length, Uint8List to,
      [int toOffset = 0]) {
    for (var i = 0; i < from_length; i++) {
      to[i + toOffset] = from[i];
    }
  }

  static void _memzero(Uint8List list) {
    for (var i = 0; i < list.length; i++) {
      list[i] = 0x00;
    }
  }

  static Uint8List hmac_sha512(
      Uint8List password, Uint8List salt, int count, int key_length) {
    var hasher = HmacSha512.mac;
    return _deriveKey(hasher, password, salt, count, key_length);
  }

  static Uint8List _deriveKey(Hasher hasher, Uint8List password, Uint8List salt,
      int count, int key_length) {
    if (count <= 0 || key_length < 1 || key_length > 0xffffffff) {
      throw Exception();
    }

    final hash_length = 64;
    final block_count = (key_length / hash_length).round();

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

      HmacSha512.mac(_U, message, password);

      final offset = (i - 1) * hash_length;

      _memcopy(_U, hash_length, derived_key, offset);

      for (var j = 1; j < count; j++) {
        HmacSha512.mac(_U, _U, password);

        for (var k = 0; k < hash_length; k++) {
          derived_key[k + offset] ^= _U[k];
        }
      }
    }

    var result = derived_key.sublist(0, key_length);

    _memzero(_U);
    _memzero(derived_key);

    return result;
  }
}

void main() {
  final hex = HexCoder.instance;
  final entropy = '46e62370a138a182a498b8e2885bc032379ddf38';
  final seedBytes = hex.decode(entropy);
  final password = <int>[].toUint8List();
  final iter = 4096;
  final outLen = 96;

  final out = PBKDF2.hmac_sha512(password, seedBytes, iter, outLen);

  print(hex.encode(out));
}
