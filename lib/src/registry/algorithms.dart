part of pinenacl.api;

/// Algorithm's params of the ECDH
class Curve25519 extends AlgorithmParams {
  @override
  PrivateParams get prvParams => const PrivateParams(
      pubAlg: TweetNaCl.crypto_scalarmult_base,
      hashAlg: TweetNaCl.crypto_hash,
      codec: Bech32Encoder(hrp: 'curve25519_sk'),
      length: TweetNaCl.secretKeyLength);

  @override
  PublicParams get pubParams => const PublicParams(
      codec: Bech32Encoder(hrp: 'curve25519_pk'),
      length: TweetNaCl.publicKeyLength);

  /// It's a ECDH and not EdDSA
  @override
  SignatureParams get sigParams =>
      throw Exception('Signing is not supported on Curve25519\'s ECDH');

  @override
  Uint8List normalizeBytes(Uint8List k) => k;

  @override
  bool validateBytes(Uint8List k) => true;
}

class Ed25519 extends AlgorithmParams {
  @override
  PrivateParams get prvParams => const PrivateParams(
      pubAlg: TweetNaClExt.scalar_base_seed,
      hashAlg: TweetNaCl.crypto_hash,
      codec: Bech32Encoder(hrp: 'ed25519_sk'),
      length: TweetNaCl.secretKeyLength);

  @override
  PublicParams get pubParams => const PublicParams(
      codec: Bech32Encoder(hrp: 'ed25519_pk'),
      length: TweetNaCl.publicKeyLength);

  @override
  SignatureParams get sigParams => const SignatureParams(
      signAlg: TweetNaCl.crypto_sign,
      verifyAlg: TweetNaCl.crypto_sign_open,
      codec: Bech32Encoder(hrp: 'ed25519_sig'),
      length: TweetNaCl.signatureLength);

  @override
  Uint8List normalizeBytes(Uint8List k) => k;

  @override
  bool validateBytes(Uint8List k) => true;
}
