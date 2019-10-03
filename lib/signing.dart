import 'dart:typed_data';

import 'package:pinenacl/api.dart';
export 'package:pinenacl/api.dart';

class VerifyKey<T extends AlgorythmParams> extends GenericPublicKey<T>
    with Verify<T> {
  VerifyKey(List<int> bytes) : super(bytes);

  factory VerifyKey.decode(String data, [Codec decoder]) {
    AlgorythmParams alg = Registrar.getInstance(T.toString());
    final decoded = (decoder ?? alg.pubParams.codec).decode(data);
    return VerifyKey<T>(decoded);
  }

  @override
  Codec get encoder => Registrar.getInstance(T.toString()).pubEncoder;
}

/*
class VerifyKey extends AsymmetricPublicKey implements Verify {
  VerifyKey(List<int> list) : super(list);

  factory VerifyKey.decode(String data, [Encoder defaultDecoder = decoder]) {
    final decoded = defaultDecoder.decode(data);
    return VerifyKey(decoded);
  }

  static const decoder = Bech32Encoder(hrp: 'ed25519_pk');

  @override
  Encoder get encoder => decoder;

  @override
  bool verifySignedMessage({EncryptionMessage signedMessage}) => verify(
      signature: signedMessage.signature, message: signedMessage.message);
  @override
  bool verify({SignatureBase signature, List<int> message}) {
    if (signature != null) {
      if (signature.length != TweetNaCl.signatureLength) {
        throw Exception(
            'Signature length (${signature.length}) is invalid, expected "${TweetNaCl.signatureLength}"');
      }
      message = signature + message;
    }
    if (message == null || message.length < TweetNaCl.signatureLength) {
      throw Exception(
          'Signature length (${message.length}) is invalid, expected "${TweetNaCl.signatureLength}"');
    }

    Uint8List m = Uint8List(message.length);

    final result = TweetNaCl.crypto_sign_open(
        m, -1, Uint8List.fromList(message), 0, message.length, this);
    if (result != 0) {
      throw Exception(
          'The message is forged or malformed or the signature is invalid');
    }
    return true;
  }
}
*/

/// Cannot extends `AsymmetricPrivateKey` as it would have to implement
/// the final `publicKey`.

//class SigningKey extends ByteList implements AsymmetricPrivateKey, Sign {
class SigningKey<T extends AlgorythmParams> extends ByteList
    with Sign<T>
    implements AsymmetricPrivateKey {
  SigningKey._fromValidBytes(List<int> secret, List<int> public)
      : this.publicKey = VerifyKey<T>(public),
        super(secret, secret.length);

  factory SigningKey({List<int> seed}) {
    return SigningKey<T>.fromSeed(seed);
  }

  factory SigningKey.fromSeed(List<int> seed) {
    AlgorythmParams alg = Registrar.getInstance(T.toString());
    final pub = _seedToPublic(seed, alg);
    return SigningKey<T>._fromValidBytes(seed + pub, pub);
  }

  @override
  factory SigningKey.generate() =>
      SigningKey.fromSeed(TweetNaCl.randombytes(seedSize));

  factory SigningKey.decode(String data, [Codec decoder]) {
    AlgorythmParams alg = Registrar.getInstance(T.toString());

    final decoded = (decoder ?? alg.prvParams.codec).decode(data);
    return SigningKey<T>(seed: decoded);
  }

  @override
  Codec get encoder => Registrar.getInstance(T.toString()).prvEncoder;

  @override
  final VerifyKey<T> publicKey;

  VerifyKey<T> get verifyKey => publicKey;

  static const seedSize = TweetNaCl.seedSize;
  static final keyLength = TweetNaCl.secretKeyLength;

  static Uint8List _seedToPublic(List<int> seed, AlgorythmParams alg) {
    if (seed == null || seed.length != seedSize) {
      throw Exception(
          'PrivateKey\'s seed must be a $seedSize bytes long binary sequence');
    }

    final public = Uint8List(TweetNaCl.publicKeyLength);
    return alg.prvParams.pubAlg(public, Uint8List.fromList(seed));
  }
}
