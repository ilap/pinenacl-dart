part of pinenacl.api.crypto.tweetnacl;

///
/// TweetNaCl's extension class.
/// Following the TweetNaCl convention and added some extras.
/// Extension is just an eye-candy here as it uses only static methods.
///
extension TweetNaClExt on TweetNaCl {
  /// HMAC bytes
  /// @nodoc
  static const hmacBytes = 64;

  /// Extended secret key's length
  /// @nodoc
  static const int extendedSecretKeyLength = 32;

  static int _crypto_auth(Uint8List out, Uint8List m, Uint8List k) {
    HmacSha512.mac(out, m, k);
    return 0;
  }

  static int crypto_auth(Uint8List out, Uint8List m, Uint8List k) {
    return _crypto_auth(out, m, k);
  }

  static int _crypto_auth_verify(Uint8List h, Uint8List m, Uint8List k) {
    final x = Uint8List(hmacBytes);
    _crypto_auth(x, m, k);
    return _crypto_verify_64(h, 0, x, 0);
  }

  static int _crypto_auth_verify_len(Uint8List h, Uint8List m, Uint8List k) {
    return _crypto_auth_verify(h, m, k);
  }

  static int crypto_auth_verify(Uint8List h, Uint8List m, Uint8List k) {
    return _crypto_auth_verify_len(h, m, k);
  }

  static int _crypto_verify_64(
      Uint8List x, final int xoff, Uint8List y, final int yoff) {
    return TweetNaCl._vn(x, xoff, y, yoff, 64);
  }

  static int scalar_base(Uint8List pk, Uint8List sk) {
    final p =
        List<Uint64List>.generate(4, (_) => Uint64List(16), growable: false);

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
    final q = List<Uint64List>.generate(4, (_) => Uint64List(16));
    final a = Uint64List(16);
    final b = Uint64List(16);

    if (TweetNaCl._unpackneg(q, ed25519_pk) != 0) return -1;

    var y = q[1];

    // b = 1 + Yed
    TweetNaCl._A(a, Uint64List.fromList(TweetNaCl._gf1), y);
    // b = 1 - Yed
    TweetNaCl._Z(b, Uint64List.fromList(TweetNaCl._gf1), y);
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
}
