import 'dart:typed_data';

import 'package:pinenacl/api.dart';
export 'package:pinenacl/api.dart';

class VerifyKey<T extends AlgorithmParams> extends GenericPublicKey<T>
    with Verify<T> {
  VerifyKey(List<int> bytes) : super(bytes);

  factory VerifyKey.decode(String data, [Codec decoder]) {
    AlgorithmParams alg = Registrar.getInstance(T.toString());
    final decoded = (decoder ?? alg.pubParams.codec).decode(data);
    return VerifyKey<T>(decoded);
  }

  @override
  Codec get encoder => Registrar.getInstance(T.toString()).pubParams.codec;
}

/// Cannot extends `AsymmetricPrivateKey` as it would have to implement
/// the final `publicKey`.
///
class SigningKey<T extends AlgorithmParams> extends ByteList
    with Sign<T>
    implements AsymmetricPrivateKey {
  SigningKey._fromValidBytes(List<int> secret, List<int> public)
      : this.publicKey = VerifyKey<T>(public),
        super(secret, secret.length);

  factory SigningKey({List<int> seed}) {
    return SigningKey<T>.fromSeed(seed);
  }

  factory SigningKey.fromSeed(List<int> seed) {
    AlgorithmParams alg = Registrar.getInstance(T.toString());
    final pub = _seedToPublic(seed, alg);
    return SigningKey<T>._fromValidBytes(seed + pub, pub);
  }

  @override
  factory SigningKey.generate() =>
      SigningKey.fromSeed(TweetNaCl.randombytes(seedSize));

  factory SigningKey.decode(String data, [Codec decoder]) {
    AlgorithmParams alg = Registrar.getInstance(T.toString());

    final decoded = (decoder ?? alg.prvParams.codec).decode(data);
    return SigningKey<T>(seed: decoded);
  }

  @override
  Codec get encoder => Registrar.getInstance(T.toString()).prvParams.codec;

  @override
  final VerifyKey<T> publicKey;

  VerifyKey<T> get verifyKey => publicKey;

  static const seedSize = TweetNaCl.seedSize;
  static final keyLength = TweetNaCl.secretKeyLength;

  static Uint8List _seedToPublic(List<int> seed, AlgorithmParams alg) {
    if (seed == null || seed.length != seedSize) {
      throw Exception(
          'PrivateKey\'s seed must be a $seedSize bytes long binary sequence');
    }

    final public = Uint8List(TweetNaCl.publicKeyLength);
    return alg.prvParams.pubAlg(public, Uint8List.fromList(seed));
  }
}
