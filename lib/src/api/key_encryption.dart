part of pinenacl.api;

typedef Crypting = Uint8List Function(
    Uint8List out, Uint8List text, int textLen, Uint8List nonce, Uint8List k);

abstract class BoxBase extends AsymmetricKey {
  BoxBase.fromList(List<int> list) : super.fromList(list);

  Crypting doEncrypt;
  Crypting doDecrypt;
  ByteList get key;

  Uint8List decrypt(Uint8List encryptedMessage, {Uint8List nonce}) {
    var ciphertext;
    if (encryptedMessage is EncryptedMessage) {
      nonce = encryptedMessage.nonce;
      ciphertext = encryptedMessage.cipherText;
    } else if (nonce != null) {
      ciphertext = encryptedMessage;
    } else {
      throw Exception('Nonce is required for a message');
    }

    final c = Uint8List(TweetNaCl.boxzerobytesLength) + ciphertext;
    final m = Uint8List(c.length);
    final plaintext =
        doDecrypt(m, Uint8List.fromList(c), c.length, nonce, this.key);
    return Uint8List.fromList(plaintext);
  }

  EncryptedMessage encrypt(List<int> plainText, {List<int> nonce}) {
    nonce = nonce ?? TweetNaCl.randombytes(TweetNaCl.nonceLength);

    final m = Uint8List(TweetNaCl.zerobytesLength) + plainText;
    final c = Uint8List(m.length);
    final cipherText =
        doEncrypt(c, Uint8List.fromList(m), m.length, nonce, this.key);

    return EncryptedMessage(nonce: nonce, cipherText: cipherText);
  }
}

class EncryptedMessage extends ByteList with Suffix {
  EncryptedMessage({List<int> nonce, List<int> cipherText})
      : super(nonce + cipherText);

  static const nonceLength = 24;

  @override
  int prefixLength = nonceLength;

  ByteList get nonce => prefix;
  ByteList get cipherText => suffix;
}

class PublicKey extends ByteList implements AsymmetricPublicKey {
  PublicKey(List<int> bytes) : super(bytes, TweetNaCl.publicKeyLength);

  factory PublicKey.decode(String data, [Encoder defaultDecoder = decoder]) {
    final decoded = defaultDecoder.decode(data);
    return PublicKey(decoded);
  }
  static const decoder = Bech32Encoder(hrp: 'ed25519_pk');

  @override
  Encoder get encoder => decoder;
}

class PrivateKey extends ByteList implements AsymmetricPrivateKey {
  // private constructor
  PrivateKey._fromValidBytes(List<int> secret, List<int> public)
      : this.publicKey = PublicKey(public),
        super(secret, keyLength);

  factory PrivateKey(List<int> seed) {
    return PrivateKey.fromSeed(seed);
  }

  PrivateKey.fromSeed(List<int> seed)
      : this._fromValidBytes(seed, _seedToPublic(seed));

  @override
  factory PrivateKey.generate() =>
      PrivateKey.fromSeed(TweetNaCl.randombytes(seedSize));

  factory PrivateKey.decode(String data, [Encoder defaultDecoder = decoder]) {
    final decoded = defaultDecoder.decode(data);
    return PrivateKey(decoded);
  }

  static const decoder = Bech32Encoder(hrp: 'ed25519_sk');

  @override
  Encoder get encoder => decoder;

  @override
  final PublicKey publicKey;

  static const seedSize = TweetNaCl.seedSize;
  static final keyLength = TweetNaCl.secretKeyLength;

  static Uint8List _seedToPublic(List<int> seed) {
    if (seed == null || seed.length != seedSize) {
      throw Exception(
          'PrivateKey\'s seed must be a $seedSize bytes long binary sequence');
    }

    final public = Uint8List(TweetNaCl.publicKeyLength);
    return TweetNaCl.crypto_scalarmult_base(public, Uint8List.fromList(seed));
  }
}

class SealedMessage extends ByteList with Suffix {
  SealedMessage({List<int> public, List<int> cipherText})
      : super(public + cipherText);

  @override
  int prefixLength = publicLength;

  static const publicLength = 32;
  ByteList get public => prefix;
  ByteList get cipherText => suffix;
}
