import 'dart:typed_data';

import 'package:pinenacl/api.dart';

class Signature extends ByteList implements SignatureBase {
  Signature(List<int> bytes) : super(bytes, bytesLength);
  static const bytesLength = TweetNaCl.signatureLength;
}

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

/// Cannot extends `AsymmetricPrivateKey` as it would have to implement
/// the final `publicKey`.
class SigningKey extends ByteList implements AsymmetricPrivateKey, Sign {
  // Private constructor.
  SigningKey._fromValidBytes(List<int> secret, List<int> public)
      : this.verifyKey = VerifyKey(public),
        super(secret, secret.length);

  factory SigningKey({List<int> seed}) {
    return SigningKey.fromSeed(seed);
  }

  factory SigningKey.fromSeed(List<int> seed) {
    if (seed == null || seed?.length != seedSize) {
      throw Exception('SigningKey must be created from a $seedSize byte seed');
    }

    final priv =
        Uint8List.fromList(seed + Uint8List(TweetNaCl.publicKeyLength));
    final pub = Uint8List(TweetNaCl.publicKeyLength);
    TweetNaCl.crypto_sign_keypair(pub, priv, Uint8List.fromList(seed));

    return SigningKey._fromValidBytes(priv, pub);
  }

  factory SigningKey.generate() {
    final secret = TweetNaCl.randombytes(seedSize);
    return SigningKey.fromSeed(secret);
  }

  factory SigningKey.decode(String data, [Encoder defaultDecoder = decoder]) {
    final decoded = defaultDecoder.decode(data);
    return SigningKey(seed: decoded);
  }

  static const decoder = Bech32Encoder(hrp: 'ed25519_sk');

  @override
  Encoder get encoder => decoder;

  static const seedSize = TweetNaCl.seedSize;

  @override
  AsymmetricPublicKey get publicKey => verifyKey;

  @override
  final VerifyKey verifyKey;

  @override
  SignedMessage sign(List<int> message) {
    // signed message
    Uint8List sm = Uint8List(message.length + TweetNaCl.signatureLength);
    final result = TweetNaCl.crypto_sign(
        sm, -1, Uint8List.fromList(message), 0, message.length, this);
    if (result != 0) {
      throw Exception('Signing the massage is failed');
    }

    return SignedMessage.fromList(signedMessage: sm);
  }
}

class SignedMessage extends ByteList with Suffix implements EncryptionMessage {
  SignedMessage({SignatureBase signature, List<int> message})
      : super(signature + message, signatureLength);
  SignedMessage.fromList({List<int> signedMessage}) : super(signedMessage);

  @override
  int prefixLength = signatureLength;

  static const signatureLength = 64;

  @override
  SignatureBase get signature => Signature(prefix);

  @override
  ByteList get message => suffix;
}
