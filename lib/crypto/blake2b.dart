import 'dart:typed_data';

import '../api.dart';

class _Context {
  _Context(this.b, this.h, this.t, this.c, this.outLen);
  final Uint8List b;
  final Uint32List h;
  int t;
  int c;
  final int outLen;
}

class Blake2b {
  static const bytes = 32;
  static const minBytes = 16;
  static const maxBytes = 64;
  // FIXME: we should only support 16 for min key length,
  // but testvectors use shorter.
  static const minKeyBytes = 1;
  static const maxKeyBytes = maxBytes;
  static const keyBytes = bytes;
  static const saltBytes = minBytes;
  static const personalBytes = minBytes;

  static final _blake2bIv32 = <int>[
    0xF3BCC908, 0x6A09E667, 0x84CAA73B, 0xBB67AE85, // 0-3
    0xFE94F82B, 0x3C6EF372, 0x5F1D36F1, 0xA54FF53A, // 4-7
    0xADE682D1, 0x510E527F, 0x2B3E6C1F, 0x9B05688C,
    0xFB41BD6B, 0x1F83D9AB, 0x137E2179, 0x5BE0CD19
  ];

  static const List<int> _sigma8 = <int>[
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, // 0-15
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
    11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
    7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
    9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
    2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
    12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
    13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
    6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
    10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3
  ];

  static final _sigma82 =
      Uint8List.fromList(_sigma8.map((x) => x * 2).toList());

  /// 64-bit unsigned addition
  /// Sets v[a,a+1] += v[b,b+1]
  /// v should be a Uint32List
  static void _add64aa(Uint32List v, int a, int b) {
    final o0 = v[a] + v[b];
    var o1 = v[a + 1] + v[b + 1];
    if (o0 >= 0x100000000) {
      o1++;
    }
    v[a] = o0;
    v[a + 1] = o1;
  }

  /// 64-bit unsigned addition
  /// Sets v[a,a+1] += b
  /// b0 is the low 32 bits of b, b1 represents the high 32 bits
  static void _add64ac(Uint32List v, int a, int b0, int b1) {
    var o0 = v[a] + b0;
    if (b0 < 0) {
      o0 += 0x100000000;
    }
    var o1 = v[a + 1] + b1;
    if (o0 >= 0x100000000) {
      o1++;
    }
    v[a] = o0;
    v[a + 1] = o1;
  }

  /// Little-endian byte access
  static int _b2bGET32(Uint8List arr, int i) {
    return (arr[i] ^
        (arr[i + 1] << 8) ^
        (arr[i + 2] << 16) ^
        (arr[i + 3] << 24));
  }

  /// Compression function. [last] flag indicates last block.
  static void _blake2bCompress(_Context context, bool last) {
    final v = Uint32List(32);
    final m = Uint32List(32);

    /// G Mixing function
    /// The ROTRs are inlined for speed
    void _b2bG(int a, int b, int c, int d, int ix, int iy) {
      var x0 = m[ix];
      var x1 = m[ix + 1];
      var y0 = m[iy];
      var y1 = m[iy + 1];

      // v[a,a+1] += v[b,b+1]
      _add64aa(v, a, b);
      // v[a, a+1] += x
      _add64ac(v, a, x0, x1);

      // v[d,d+1] = (v[d,d+1] xor v[a,a+1]) rotated to the right by 32 bits
      var xor0 = v[d] ^ v[a];
      var xor1 = v[d + 1] ^ v[a + 1];
      v[d] = xor1;
      v[d + 1] = xor0;

      _add64aa(v, c, d);

      // v[b,b+1] = (v[b,b+1] xor v[c,c+1]) rotated right by 24 bits
      xor0 = v[b] ^ v[c];
      xor1 = v[b + 1] ^ v[c + 1];
      v[b] = (xor0 >> 24) ^ (xor1 << 8);
      v[b + 1] = (xor1 >> 24) ^ (xor0 << 8);

      _add64aa(v, a, b);
      _add64ac(v, a, y0, y1);

      // v[d,d+1] = (v[d,d+1] xor v[a,a+1]) rotated right by 16 bits
      xor0 = v[d] ^ v[a];
      xor1 = v[d + 1] ^ v[a + 1];
      v[d] = (xor0 >> 16) ^ (xor1 << 16);
      v[d + 1] = (xor1 >> 16) ^ (xor0 << 16);

      _add64aa(v, c, d);

      // v[b,b+1] = (v[b,b+1] xor v[c,c+1]) rotated right by 63 bits
      xor0 = v[b] ^ v[c];
      xor1 = v[b + 1] ^ v[c + 1];
      v[b] = (xor1 >> 31) ^ (xor0 << 1);
      v[b + 1] = (xor0 >> 31) ^ (xor1 << 1);
    }

    // init work variables
    for (var i = 0; i < 16; i++) {
      v[i] = context.h[i];
      v[i + 16] = _blake2bIv32[i];
    }

    // low 64 bits of offset
    v[24] = v[24] ^ context.t;
    v[25] = v[25] ^ (context.t ~/ 0x100000000);
    // high 64 bits not supported, offset may not be higher than 2**53-1

    // last block flag set ?
    if (last) {
      v[28] = ~v[28];
      v[29] = ~v[29];
    }

    // get little-endian words
    for (var i = 0; i < 32; i++) {
      m[i] = _b2bGET32(context.b, 4 * i);
    }

    for (var i = 0; i < 12; i++) {
      _b2bG(0, 8, 16, 24, _sigma82[i * 16 + 0], _sigma82[i * 16 + 1]);
      _b2bG(2, 10, 18, 26, _sigma82[i * 16 + 2], _sigma82[i * 16 + 3]);
      _b2bG(4, 12, 20, 28, _sigma82[i * 16 + 4], _sigma82[i * 16 + 5]);
      _b2bG(6, 14, 22, 30, _sigma82[i * 16 + 6], _sigma82[i * 16 + 7]);
      _b2bG(0, 10, 20, 30, _sigma82[i * 16 + 8], _sigma82[i * 16 + 9]);
      _b2bG(2, 12, 22, 24, _sigma82[i * 16 + 10], _sigma82[i * 16 + 11]);
      _b2bG(4, 14, 16, 26, _sigma82[i * 16 + 12], _sigma82[i * 16 + 13]);
      _b2bG(6, 8, 18, 28, _sigma82[i * 16 + 14], _sigma82[i * 16 + 15]);
    }

    for (var i = 0; i < 16; i++) {
      context.h[i] = context.h[i] ^ v[i] ^ v[i + 16];
    }
  }

  /// Creates a BLAKE2b hashing context.
  ///
  /// Requires an output length between 1 and 64 bytes
  /// Takes an optional Uint8List key, salte and personalisation parameters
  /// for KDF or MAC.
  static _Context init(int outlen,
      [Uint8List? key, Uint8List? salt, Uint8List? personal]) {
    if (outlen <= 0 || outlen > maxBytes) {
      throw Exception('Illegal output length, expected 0 < length <= 64');
    }
    if (key != null && (key.length < minKeyBytes || key.length > maxKeyBytes)) {
      throw Exception(
          'Illegal key, expected Uint8List with $minKeyBytes <= length <= $maxKeyBytes');
    }
    if (salt != null && salt.length != saltBytes) {
      throw Exception(
          'Illegal salt parameter, expected Uint8List of $saltBytes length');
    }
    if (personal != null &&
        (personal.isEmpty || personal.length > personalBytes)) {
      throw Exception(
          'Illegal personalization parameter, expected Uint8List of 0 < $personalBytes <= length');
    }
    // Initialise the context.
    final context = _Context(Uint8List(128), Uint32List(16), 0, 0, outlen);

    // Initialise the parameter block
    //  0- 3: outlen, keylen, fanout, depth
    //  4- 7: leaf length, sequential mode
    //  8-15: node offset
    // 16   : node depth, inner length, rfu
    // 20-31: rfu
    // 32-47: salt
    // 48-63: personal
    final params = Uint8List(maxBytes);
    // In default, t's filled /w zero but, better safe than sorry
    Utils.listZero(params);

    params[0] = outlen;
    if (key != null) {
      params[1] = key.length;
    }
    // Fanout
    params[2] = 1;
    // Depth
    params[3] = 1;

    if (salt != null) {
      Utils.listCopy(salt, salt.length, params, 32);
    }

    if (personal != null) {
      // padding if length < $personalBytes
      final offset = 48 + personalBytes - personal.length;
      Utils.listCopy(personal, personal.length, params, offset);
    }

    for (var i = 0; i < 16; i++) {
      context.h[i] = _blake2bIv32[i] ^ _b2bGET32(params, i * 4);
    }

    // key the hash, if applicable
    if (key != null) {
      update(context, key);
      // at the end
      context.c = 128;
    }

    return context;
  }

  /// Updates a BLAKE2b streaming hash.
  ///
  /// Requires hash [context] and Uint8List [input] (byte array)
  static void update(_Context context, Uint8List input) {
    for (var i = 0; i < input.length; i++) {
      if (context.c == 128) {
        context.t += context.c; // add counters
        _blake2bCompress(context, false);
        context.c = 0; // reset the counter
      }
      context.b[context.c++] = input[i];
    }
  }

  /// Completes a BLAKE2b streaming hash.
  ///
  /// Returns a Uint8List containing the message digest
  static Uint8List finalise(_Context context) {
    context.t += context.c; // mark last block offset

    while (context.c < 128) {
      // fill up with zeros
      context.b[context.c++] = 0;
    }
    _blake2bCompress(context, true); // final block flag = 1

    // little endian convert and store
    final out = Uint8List(context.outLen);
    for (var i = 0; i < context.outLen; i++) {
      out[i] = context.h[i >> 2] >> (8 * (i & 3));
    }
    return out;
  }

  /// Computes the BLAKE2B hash of a string or byte array, and returns a Uint8List
  ///
  /// Returns a n-byte Uint8List
  ///
  /// Parameters:
  /// - input - the input bytes, as a string, Buffer or Uint8List
  /// - key - optional key Uint8List, up to 64 bytes
  /// - outlen - optional output length in bytes, default 64
  static Uint8List digest(Uint8List data,
      {int? digestSize, Uint8List? key, Uint8List? salt, Uint8List? personal}) {
    digestSize = digestSize ?? 64;

    final context = init(digestSize, key, salt, personal);
    update(context, data);
    return finalise(context);
  }
}

/*
void main() {
  final state = Blake2b.init(24);
  Blake2b.update(state, List<int>.generate(32, (i) => 1));
  Blake2b.update(state, List<int>.generate(32, (i) => 2));
  final result = Blake2b.finalise(state);
  print(hex.encode(result));

  // FIXME: Implement similar API
  /*
  abstract Digest {
    Digest init(length, key, salt, personalisation)
    Digest update(List<int> message);
    Uint8List finalise(); 
  }
  
  var blake = Blake2b(24);
  /// Context is unmodifiable, therefore new opject is created
  /// similar to the copyWith();
  blake = blake.init();
  blake = blake.update(message);
  blake = blake.update(message);
  var result = blake.finalise();
  */
}
*/
