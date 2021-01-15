//part of pinenacl.api;
import '../api.dart';
import '../src/tweetnacl/tweetnacl.dart';

typedef Crypting = Uint8List Function(
    Uint8List out, Uint8List text, int textLen, Uint8List nonce, Uint8List k);

abstract class BoxBase extends ByteList {
  BoxBase.fromList(List<int> list) : super.fromList(list);

  late Crypting doEncrypt;
  late Crypting doDecrypt;
  ByteList get key;

  Uint8List decrypt(Uint8List encryptedMessage, {Uint8List? nonce}) {
    Uint8List ciphertext;
    if (encryptedMessage is EncryptedMessage) {
      nonce = encryptedMessage.nonce;
      ciphertext = encryptedMessage.cipherText;
    } else if (nonce != null) {
      ciphertext = encryptedMessage;
    } else {
      throw Exception('Nonce is required for a message');
    }

    final c =
        Uint8List(TweetNaCl.boxzerobytesLength).toList() + ciphertext.toList();
    final m = Uint8List(c.length);
    final plaintext = doDecrypt(m, Uint8List.fromList(c), c.length, nonce, key);
    return Uint8List.fromList(plaintext);
  }

  EncryptedMessage encrypt(List<int> plainText, {List<int>? nonce}) {
    final nonce1 = nonce ?? TweetNaCl.randombytes(TweetNaCl.nonceLength);

    final m = Uint8List(TweetNaCl.zerobytesLength).toList() + plainText;
    final c = Uint8List(m.length);

    final cipherText = doEncrypt(
        c, Uint8List.fromList(m), m.length, Uint8List.fromList(nonce1), key);

    return EncryptedMessage(
        nonce: nonce1.toList(), cipherText: cipherText.toList());
  }
}

class EncryptedMessage extends ByteList with Suffix {
  EncryptedMessage({required List<int> nonce, required List<int> cipherText})
      : super.fromList(nonce + cipherText, nonceLength);

  EncryptedMessage.fromList(List<int> list) : super.fromList(list, nonceLength);

  static const nonceLength = 24;

  @override
  int prefixLength = nonceLength;

  ByteList get nonce => prefix;
  ByteList get cipherText => suffix;
}

class PublicKey extends AsymmetricPublicKey {
  PublicKey(List<int> bytes) : super(bytes, keyLength);

  PublicKey.decode(String keyString, [Encoder coder = decoder])
      : this(coder.decode(keyString));

  static const decoder = Bech32Coder(hrp: 'x25519_pk');

  @override
  PublicKey get publicKey => this;

  @override
  Encoder get encoder => decoder;

  static const keyLength = TweetNaCl.publicKeyLength;
}

///
/// The PrivateKey implements the X25519 key agreement scheme (ECDH) using
/// Curve25519 that provides a fast, simple, constant time, and fast
/// `variable-base` scalar multiplication algorithm, which is is optimal for
/// ECDH
///
class PrivateKey extends AsymmetricPrivateKey {
  PrivateKey(List<int> secret) : super(secret, keyLength);

  PrivateKey.fromSeed(List<int> seed) : this(_seedToHash(seed));

  PrivateKey.generate() : this(TweetNaCl.randombytes(seedSize));

  PrivateKey.decode(String keyString, [Encoder coder = decoder])
      : this(coder.decode(keyString));

  static const decoder = Bech32Coder(hrp: 'x25519_sk');
  static const seedSize = TweetNaCl.seedSize;
  static const keyLength = TweetNaCl.secretKeyLength;

  @override
  Encoder get encoder => decoder;

  PublicKey? _publicKey;

  @override
  PublicKey get publicKey => _publicKey ??= PublicKey(_secretToPublic(this));

  static Uint8List _secretToPublic(List<int> secret) {
    if (secret.length != keyLength) {
      throw Exception(
          'PrivateKey\'s seed must be a $seedSize bytes long binary sequence');
    }

    final public = Uint8List(TweetNaCl.publicKeyLength);
    return TweetNaCl.crypto_scalarmult_base(public, Uint8List.fromList(secret));
  }

  static Uint8List _seedToHash(List<int> seed) {
    if (seed.length != seedSize) {
      throw Exception(
          'PrivateKey\'s seed must be a $seedSize bytes long binary sequence');
    }

    final out = Uint8List(64);
    TweetNaCl.crypto_hash(out, Uint8List.fromList(seed));
    return out.sublist(0, keyLength);
  }
}

class SealedMessage extends ByteList with Suffix {
  SealedMessage({required List<int> public, required List<int> cipherText})
      : super(public + cipherText);

  @override
  int prefixLength = publicLength;

  static const publicLength = 32;
  ByteList get public => prefix;
  ByteList get cipherText => suffix;
}
