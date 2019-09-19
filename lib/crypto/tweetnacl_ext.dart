part of pinenacl.api.crypto.tweetnacl;


/// Following the TweetNaCl convention.
class TweetNaClExt {
  static const hmacBytes = 64;

  static int _crypto_auth(Uint8List out, Uint8List m, Uint8List k) {
    HmacSha512.mac(out, m, k);
    return 0;
  }

  static int crypto_auth(Uint8List out, Uint8List m, Uint8List k) {
    return _crypto_auth(out, m, k);
  }

  static int _crypto_auth_verify(Uint8List h, Uint8List m, Uint8List k) {
    Uint8List x = Uint8List(hmacBytes);
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
}
