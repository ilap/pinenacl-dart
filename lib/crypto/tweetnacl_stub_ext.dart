part of pinenacl.api.crypto.tweetnacl_stub;

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

  static int crypto_auth(Uint8List out, Uint8List m, Uint8List k) => 0;

  static int crypto_auth_verify(Uint8List h, Uint8List m, Uint8List k) => 0;

  static int scalar_base(Uint8List pk, Uint8List sk) => 0;
}
