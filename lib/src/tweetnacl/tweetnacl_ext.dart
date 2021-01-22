part of pinenacl.tweetnacl;

extension ToInt32 on int {
  int toInt32() => (this & 0x7fffffff) - (this & 0x80000000);
}

typedef Hasher = void Function(Uint8List out, Uint8List m);
typedef MacHasher = void Function(Uint8List out, Uint8List m, Uint8List k);

///
/// TweetNaCl's extension class.
/// Following the TweetNaCl convention and added some extras.
/// Extension is just an eye-candy here as it uses only static methods.
///
/// Implemented features:
/// - HMAC-SHA512 and HMAC-SHA256
///   - crypto_auth_hmacsha512, HMAC-SHA-512
///   - crypto_auth_hmacsha256, HMAC-SHA-256
/// - Hashing algorithm
///   - SHA256
/// - Utils
///   - crypto_verify_64, verifying function for SHA-512 as an example
/// - X25519 conversion utulities
///   - crypto_sign_ed25519_sk_to_x25519_sk
///   - crypto_sign_ed25519_pk_to_x25519_pk
/// - Curve25519 low-level functions
///   - crypto_scalar_base, for retrieving different type of public-keys e.g. `A = k * B`.
///   - crypto_point_add, for adding two public keys' point together `A = y1 : y2`.
///
extension TweetNaClExt on TweetNaCl {
  static int crypto_auth_hmacsha512(Uint8List out, Uint8List m, Uint8List k) {
    _crypto_auth(TweetNaCl.crypto_hash, 128, out, m, k);
    return 0;
  }

  static int crypto_auth_hmacsha256(Uint8List out, Uint8List m, Uint8List k) {
    _crypto_auth(crypto_hash_sha256, 64, out, m, k);
    return 0;
  }

  static int _crypto_verify_64(
      Uint8List x, final int xoff, Uint8List y, final int yoff) {
    return TweetNaCl._vn(x, xoff, y, yoff, 32);
  }

  static int crypto_verify_64(Uint8List x, Uint8List y) {
    return _crypto_verify_64(x, 0, y, 0);
  }

  static int crypto_scalar_base(Uint8List pk, Uint8List sk) {
    final p = List<Int32List>.generate(4, (_) => Int32List(16));

    TweetNaCl._scalarbase(p, sk, 0);
    TweetNaCl._pack(pk, p);

    return 0;
  }

  /// Converts Ed25519 private/signing key to Curve25519 private key.
  /// It's just simply the SHA512 and prone-to-buffered seed.
  static int crypto_sign_ed25519_sk_to_x25519_sk(
      Uint8List x25519_sk, Uint8List ed25519_sk) {
    final h = Uint8List(64);

    TweetNaCl._crypto_hash_off(h, ed25519_sk, 0, 32);

    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;

    for (var i = 0; i < 32; i++) {
      x25519_sk[i] = h[i];
    }

    for (var i = 0; i < 64; i++) {
      h[i] = 0;
    }
    return 0;
  }

  /// Converts Ed25519 public/verifying key to Curve25519 public key.
  /// Xmont = (1 + Yed)/(1 - Yed) mod p
  static int crypto_sign_ed25519_pk_to_x25519_pk(
      Uint8List x25519_pk, Uint8List ed25519_pk) {
    final z = Uint8List(32);
    final q = List<Int32List>.generate(4, (_) => Int32List(16));
    final a = Int32List(16);
    final b = Int32List(16);

    if (TweetNaCl._unpackneg(q, ed25519_pk) != 0) return -1;

    var y = q[1];

    // b = 1 + Yed
    TweetNaCl._A(a, TweetNaCl._gf1, y);
    // b = 1 - Yed
    TweetNaCl._Z(b, TweetNaCl._gf1, y);
    // b = inv(b)
    TweetNaCl._inv25519(b, 0, b, 0);
    // a = a * inv(b) i.e. a / b
    TweetNaCl._M(a, a, b);
    TweetNaCl._pack25519(z, a, 0);

    for (var i = 0; i < 32; i++) {
      x25519_pk[i] = z[i];
    }

    return 0;
  }

  static int crypto_point_add(Uint8List out, Uint8List p1, Uint8List p2) {
    final p =
        List<Int32List>.generate(4, (_) => Int32List(16), growable: false);

    final q =
        List<Int32List>.generate(4, (_) => Int32List(16), growable: false);

    if (TweetNaCl._unpackneg(p, p1) != 0) return -1;
    if (TweetNaCl._unpackneg(q, p2) != 0) return -1;

    TweetNaCl._add(p, q);
    TweetNaCl._pack(out, p);

    out[31] ^= 0x80;

    return 0;
  }

  /// crypto_auth_
  /// https://csrc.nist.gov/csrc/media/publications/fips/198/1/final/documents/fips-198-1_final.pdf
  /// HMAC-SHA-256 and HMAC-SHA-512 implementation
  ///
  /// https://tools.ietf.org/html/rfc2104
  ///
  /// HMACs uses shared key which may lead to non-repudiation. If either sender or receiver’s
  /// key is compromised then it will be easy for attackers to create unauthorized messages.
  ///
  /// `ipad` Inner pad; the byte x‘36’ repeated B times.
  static const _ipad = <int>[
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, // 16*8 = 128
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36
  ];

  /// `opad `Outer pad; the byte x‘5c’ repeated B times.
  static const _opad = <int>[
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, // 16*8 = 128
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c
  ];

  static void _crypto_auth(Hasher hasher, int blockSize, Uint8List out,
      Uint8List message, Uint8List key) {

    final k0 = Uint8List(blockSize);
    final k0i = Uint8List.fromList([...Uint8List(blockSize), ...message]);
    final k0o = Uint8List(blockSize);

    if (key.length <= blockSize) {
      PineNaClUtils.listCopy(key, key.length, k0);
    } else {
      hasher(k0, key);
    }

    _xor(k0i, k0, blockSize, _ipad);
    _xor(k0o, k0, blockSize, _opad);

    hasher(out, k0i);
    hasher(out, Uint8List.fromList([...k0o, ...out]));

    // For safety clear the key's data
    // Check Dart's GC what does it do /w local variables.
    PineNaClUtils.listZero(k0);
    PineNaClUtils.listZero(k0o, blockSize);
    PineNaClUtils.listZero(k0i, blockSize);
  }

  static void _xor(List<int> out, List<int> a, int l, List<int> b) {
    for (var i = 0; i < l; i++) {
      out[i] = a[i] ^ b[i];
    }
  }

  ///
  /// SHA-256 Implementation
  ///
  static const K = [
    // 4x16
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];

  static int _rotr(int x, int n) => _shr(x, n) | _shl(x, (32 - n));
  static int _shr(int x, int n) =>
      (x >= 0 ? x >>= n : (x >> n) & ((1 << (32 - n)) - 1)).toInt32();
  static int _shl(int x, int n) => (x <<= n).toInt32();
  static int _ch(int x, int y, int z) => ((x & y) ^ ((~x) & z));
  static int _maj(int x, int y, int z) => ((x & y) ^ (x & z) ^ (y & z));
  static int _sigma0(int x) => (_rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22));
  static int _sigma1(int x) => (_rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25));
  static int _gamma0(int x) => (_rotr(x, 7) ^ _rotr(x, 18) ^ _shr(x, 3));
  static int _gamma1(int x) => (_rotr(x, 17) ^ _rotr(x, 19) ^ _shr(x, 10));

  static Uint8List crypto_hash_sha256(Uint8List out, Uint8List m) {
    return _crypto_hash_sha256(out, m, m.length);
  }

  static Uint8List _crypto_hash_sha256(Uint8List out, Uint8List m, int l) {
    /// It assumes at least 32-byte long sequence.
    if (out.length < 32) {
      throw Exception('Invalid block for the message to digest.');
    }

    final w = Uint32List(64);
    int a, b, c, d, e, f, g, h, T1, T2;

    final hh = Int32List.fromList([
      0x6a09e667,
      0xbb67ae85,
      0x3c6ef372,
      0xa54ff53a,
      0x510e527f,
      0x9b05688c,
      0x1f83d9ab,
      0x5be0cd19
    ]);

    final paddedLen = ((l + 8 >> 6) << 4) + 16;
    final padded = Uint32List(paddedLen);

    final bitLength = l << 3;
    final dataLength = bitLength >> 5;

    for (var i = 0; i < bitLength; i += 8) {
      padded[i >> 5] |= (m[i ~/ 8]) << (24 - i % 32);
    }

    padded[dataLength] |= 0x80 << (24 - bitLength % 32);
    padded[paddedLen - 1] = bitLength;

    for (var i = 0; i < padded.length; i += 16) {
      a = hh[0];
      b = hh[1];
      c = hh[2];
      d = hh[3];
      e = hh[4];
      f = hh[5];
      g = hh[6];
      h = hh[7];

      for (var j = 0; j < 64; j++) {
        if (j < 16) {
          w[j] = padded[j + i];
        } else {
          w[j] = _gamma1(w[j - 2]) + w[j - 7] + _gamma0(w[j - 15]) + w[j - 16];
        }

        T1 = _sigma1(e) + _ch(e, f, g) + h + K[j] + w[j];
        T2 = _sigma0(a) + _maj(a, b, c);

        h = g;
        g = f;
        f = e;
        e = d + T1.toInt32();
        d = c;
        c = b;
        b = a;
        a = (T1.toInt32() + T2.toInt32()).toInt32();
      }

      hh[0] = a + hh[0];
      hh[1] = b + hh[1];
      hh[2] = c + hh[2];
      hh[3] = d + hh[3];
      hh[4] = e + hh[4];
      hh[5] = f + hh[5];
      hh[6] = g + hh[6];
      hh[7] = h + hh[7];
    }

    for (var i = 0; i < hh.length; i++) {
      out[4 * i + 0] = (hh[i] >> 24) & 0xff;
      out[4 * i + 1] = (hh[i] >> 16) & 0xff;
      out[4 * i + 2] = (hh[i] >> 8) & 0xff;
      out[4 * i + 3] = hh[i] & 0xff;
    }

    return out;
  }
}
