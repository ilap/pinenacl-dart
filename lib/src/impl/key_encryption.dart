import 'package:pinenacl/api.dart';

class GenericPublicKey<T extends AlgorithmParams> extends ByteList
    implements AsymmetricPublicKey {
  GenericPublicKey(List<int> bytes)
      : super(bytes, Registrar.getInstance(T.toString()).pubParams.length);

  factory GenericPublicKey.decode(String data, [Codec decoder]) {
    AlgorithmParams alg = Registrar.getInstance(T.toString());
    final decoded = (decoder ?? alg.pubParams.codec).decode(data);
    return GenericPublicKey<T>(decoded);
  }

  @override
  Codec get encoder => Registrar.getInstance(T.toString()).pubParams.codec;
}

/// Generic PrivateKey class.
/// The following cronstructors should be implemented.
/// - GenericPrivateKey<Alg>(seed), where seed is the randomness/enctropy i.e. ~k
/// - GenericPrivateKey<Alg>.fromValidBytes(Uint8List validBytes), where validBytes are
/// validated for normalisation.
/// - GenericPrivateKey<Alg>.decode(String decodable, {Codec decoder, bool isSeed}),
/// If it's a seed then no validation is necessary.
///
class GenericPrivateKey<T extends AlgorithmParams> extends ByteList
    implements AsymmetricPrivateKey {
  // private constructor
  GenericPrivateKey._fromValidBytes(List<int> secret, List<int> public)
      : this.publicKey = GenericPublicKey<T>(public),
        super(secret, Registrar.getInstance(T.toString()).prvParams.length);

  factory GenericPrivateKey(List<int> seed) {
    return GenericPrivateKey<T>.fromSeed(seed);
  }

  factory GenericPrivateKey.fromSeed(List<int> seed) {
    AlgorithmParams alg = Registrar.getInstance(T.toString());

    return GenericPrivateKey<T>._fromValidBytes(
        alg.normalizeBytes(seed), _seedToPublic(seed, alg));
  }

  @override
  factory GenericPrivateKey.generate() =>
      GenericPrivateKey.fromSeed(TweetNaCl.randombytes(seedSize));

  factory GenericPrivateKey.decode(String data,
      {Codec decoder, isSeed = false}) {
    AlgorithmParams alg = Registrar.getInstance(T.toString());
    final decoded = (decoder ?? alg.prvParams.codec).decode(data);
    if (!isSeed) {
      final isValid = alg.validateBytes(decoded);
      if (!isValid) {
        throw Exception('The decoded string is not valid');
      }
      return GenericPrivateKey<T>._fromValidBytes(
          decoded, _seedToPublic(decoded.sublist(0, 32), alg));
    } else {
      return GenericPrivateKey<T>(decoded);
    }
  }

  @override
  Codec get encoder => Registrar.getInstance(T.toString()).prvParams.codec;

  @override
  final GenericPublicKey<T> publicKey;

  static const seedSize = TweetNaCl.seedSize;

  static Uint8List _seedToPublic(List<int> seed, AlgorithmParams alg) {
    if (seed == null || seed.length != seedSize) {
      throw Exception(
          'PrivateKey\'s seed must be a $seedSize bytes long binary sequence');
    }
    final public = Uint8List(alg.pubParams.length);
    return alg.prvParams.pubAlg(public, Uint8List.fromList(seed));
  }
}
