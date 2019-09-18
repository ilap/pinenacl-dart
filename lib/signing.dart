library pinenacl.api.signatures;

import "dart:core";
import 'dart:typed_data';

import 'package:convert/convert.dart';

import 'package:pinenacl/api.dart';

class VerifyKey extends ByteList implements AsymmetricKey, Verify {
  VerifyKey(List<int> list) : super(list, TweetNaCl.publicKeyLength);
  VerifyKey.fromHexString(String hexaString) : super.fromHexString(hexaString);

  @override
  bool verifySignedMessage({SignedMessage signedMessage}) => verify(
      signature: signedMessage.signature, message: signedMessage.message);

  @override
  bool verify({Signature signature, List<int> message}) {
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

class SigningKey extends ByteList implements AsymmetricPrivateKey, Sign {
  // Private constructor.
  SigningKey._fromValidBytes(List<int> secret, List<int> public)
      : this.verifyKey = VerifyKey(public),
        super(secret, secret.length);

  factory SigningKey({List<int> seed}) {
    return SigningKey.fromSeed(seed);
  }

  factory SigningKey.fromHexString(String hexaString) {
    return SigningKey.fromSeed(Uint8List.fromList(hex.decode(hexaString)));
  }

  factory SigningKey.fromSeed(List<int> seed) {
    if (seed == null || seed?.length != seedSize) {
      throw Exception('SigningKey must be created from a $seedSize byte seed');
    }

    final priv = Uint8List.fromList(seed + Uint8List(32));
    final pub = Uint8List(TweetNaCl.publicKeyLength);
    TweetNaCl.crypto_sign_keypair(pub, priv, Uint8List.fromList(seed));

    return SigningKey._fromValidBytes(priv, pub);
  }

  factory SigningKey.generate() {
    final secret = TweetNaCl.randombytes(seedSize);
    return SigningKey.fromSeed(secret);
  }

  static const seedSize = TweetNaCl.seedSize;

  @override
  AsymmetricKey get publicKey => verifyKey;

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
