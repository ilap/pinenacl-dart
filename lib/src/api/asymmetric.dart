part of pinenacl.api;

abstract class AsymmetricKey {}

abstract class AsymmetricPrivateKey implements AsymmetricKey {
  factory AsymmetricPrivateKey.generate() {
    throw Exception('Should not reach this');
  }
  final AsymmetricKey publicKey;
}

abstract class Sign {
  Verify get verifyKey;
  SignedMessage sign(List<int> message);
}

abstract class Verify {
  bool verify({Signature signature, ByteList message});
  bool verifySignedMessage({SignedMessage signedMessage});
}

class Signature extends ByteList {
  Signature(List<int> bytes) : super(bytes, bytesLength);
  static const bytesLength = TweetNaCl.signatureLength;
}

class PublicKey extends ByteList implements AsymmetricKey {
  PublicKey(List<int> bytes) : super(bytes, keyLength);
  PublicKey.fromHexString(String hexString) : super.fromHexString(hexString);
  static const int keyLength = TweetNaCl.publicKeyLength;
}

class PrivateKey extends ByteList implements AsymmetricPrivateKey {
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

  factory PrivateKey.fromSeed(List<int> seed) {
    if (seed == null || seed.length != seedSize) {
      throw Exception(
          'PrivateKey\'s seed must be a $seedSize bytes long binary sequence');
    }

    final public = Uint8List(PublicKey.keyLength);

    TweetNaCl.crypto_scalarmult_base(public, Uint8List.fromList(seed));

    return PrivateKey._fromValidBytes(seed, public);
  }

  @override
  factory PrivateKey.generate() {
    final secret = TweetNaCl.randombytes(keyLength);
    return PrivateKey.fromSeed(secret);
  }

  static const seedSize = TweetNaCl.seedSize;
  static const keyLength = TweetNaCl.secretKeyLength;

  @override
  final PublicKey publicKey;
}
