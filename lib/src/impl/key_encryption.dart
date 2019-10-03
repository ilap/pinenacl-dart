import 'package:pinenacl/api.dart';

class GenericPublicKey<T extends AlgorythmParams> extends ByteList
    implements AsymmetricPublicKey {
  GenericPublicKey(List<int> bytes) : super(bytes, TweetNaCl.publicKeyLength);

  factory GenericPublicKey.decode(String data, [Codec decoder]) {
    AlgorythmParams alg = Registrar.getInstance(T.toString());
    //alg.length

    final decoded = (decoder ?? alg.pubParams.codec).decode(data);
    return GenericPublicKey<T>(decoded);
  }

  @override
  Codec get encoder => Registrar.getInstance(T.toString()).pubEncoder;
}

class GenericPrivateKey<T extends AlgorythmParams> extends ByteList
    implements AsymmetricPrivateKey {
  // private constructor
  GenericPrivateKey._fromValidBytes(List<int> secret, List<int> public)
      : this.publicKey = GenericPublicKey<T>(public),
        super(secret, keyLength);

  factory GenericPrivateKey(List<int> seed) {
    return GenericPrivateKey<T>.fromSeed(seed);
  }

  factory GenericPrivateKey.fromSeed(List<int> seed) {
    AlgorythmParams alg = Registrar.getInstance(T.toString());
    return GenericPrivateKey<T>._fromValidBytes(seed, _seedToPublic(seed, alg));
  }

  @override
  factory GenericPrivateKey.generate() =>
      GenericPrivateKey.fromSeed(TweetNaCl.randombytes(seedSize));

  factory GenericPrivateKey.decode(String data, [Codec decoder]) {
    AlgorythmParams alg = Registrar.getInstance(T.toString());

    final decoded = (decoder ?? alg.prvParams.codec).decode(data);
    return GenericPrivateKey<T>(decoded);
  }

  @override
  Codec get encoder => Registrar.getInstance(T.toString()).prvEncoder;

  @override
  final GenericPublicKey<T> publicKey;

  static const seedSize = TweetNaCl.seedSize;
  static final keyLength = TweetNaCl.secretKeyLength;

  static Uint8List _seedToPublic(List<int> seed, AlgorythmParams alg) {
    if (seed == null || seed.length != seedSize) {
      throw Exception(
          'PrivateKey\'s seed must be a $seedSize bytes long binary sequence');
    }

    final public = Uint8List(TweetNaCl.publicKeyLength);
    //Algorythm alg = Registrar.getInstance(T.toString());
    return alg.prvParams.pubAlg(public, Uint8List.fromList(seed));
  }
}
