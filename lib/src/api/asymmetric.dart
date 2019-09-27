part of pinenacl.api;

abstract class AsymmetricKey with Encodable {}

abstract class AsymmetricPrivateKey implements AsymmetricKey {
  factory AsymmetricPrivateKey.generate() {
    throw Exception('Should not reach this');
  }
  final AsymmetricKey publicKey;
}

class Signature extends ByteList {
  Signature(List<int> bytes) : super(bytes, bytesLength);
  static const bytesLength = TweetNaCl.signatureLength;
}

class PublicKey extends ByteList with Encodable implements AsymmetricKey {
  PublicKey(List<int> bytes) : super(bytes, keyLength);
  PublicKey.fromHexString(String hexString) : super.fromHexString(hexString);
  static const int keyLength = TweetNaCl.publicKeyLength;
}

class PrivateKey extends ByteList
    with Encodable
    implements AsymmetricPrivateKey {
  // private constructor
  PrivateKey._fromValidBytes(List<int> secret, List<int> public)
      : this.publicKey = PublicKey(public),
        super(secret, keyLength);

  factory PrivateKey(List<int> seed) {
    return PrivateKey.fromSeed(seed);
  }

  factory PrivateKey.fromHexString(String hexaString) {
    return PrivateKey.fromSeed(Uint8List.fromList(hex.decode(hexaString)));
  }

  PrivateKey.fromSeed(List<int> seed)
      : this._fromValidBytes(seed, _seedToPublic(seed));

  @override
  factory PrivateKey.generate() =>
      PrivateKey.fromSeed(TweetNaCl.randombytes(seedSize));

  @override
  final PublicKey publicKey;

  static const seedSize = TweetNaCl.seedSize;
  static final keyLength = TweetNaCl.secretKeyLength;

  static Uint8List _seedToPublic(Uint8List seed) {
    if (seed == null || seed.length != seedSize) {
      throw Exception(
          'PrivateKey\'s seed must be a $seedSize bytes long binary sequence');
    }

    final public = Uint8List(TweetNaCl.publicKeyLength);
    return TweetNaCl.crypto_scalarmult_base(public, Uint8List.fromList(seed));
  }
}
