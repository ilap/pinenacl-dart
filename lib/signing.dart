import "dart:core";
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:pinenacl/src/crypto/tweetnacl.dart';

import 'package:pinenacl/api.dart';

const _kSignatureLength = 64;

class SignedMessage extends EncryptionMessage {
  SignedMessage.fromList(List<int> list) : super.fromList(list);
  Uint8List get signature =>
      Uint8List.fromList(sublist(0, _kSignatureLength));
  Uint8List get message =>
      Uint8List.fromList(sublist(_kSignatureLength));
}

class VerifyKey extends AsymmetricKey {
  VerifyKey([List<int> list]) : super.fromList(list);
  VerifyKey.fromList(List<int> list) : super.fromList(list);
  VerifyKey.fromHexString(String hexaString) : super.fromHexString(hexaString);

  bool verify(List<int> message, [List<int> signature]) {

    if (signature != null) {
      if (signature.length != _kSignatureLength) {
        throw Exception('Signature length (${signature.length}) is invalid, expected "$_kSignatureLength"');
      }
      message = signature + message;
    } if (message == null || message.length < _kSignatureLength) {
        throw Exception('Signature length (${message.length}) is invalid, expected "$_kSignatureLength"');
    }

    Uint8List m = Uint8List(message.length);

    final result = TweetNaCl.crypto_sign_open(m, -1, Uint8List.fromList(message), 0, message.length, this);
    if (result != 0) {
      throw Exception('The message is forged or malformed or the signature is invalid');
    }
    return true;
  }
}

class SigningKey extends AsymmetricKey {

  // Private constructor
  factory SigningKey(List<int> key) {
    return SigningKey.fromList(key);
  }

  SigningKey._fromValidBytes(List<int> secret, List<int> public)
      : this.verifyKey = VerifyKey.fromList(public),
        super.fromList(secret, secret.length, secret.length);

  factory SigningKey.fromHexString(String hexaString) {
    return SigningKey.fromSeed(Uint8List.fromList(hex.decode(hexaString)));
  }

  factory SigningKey.fromList(List<int> rawKey) {
    return SigningKey.fromSeed(rawKey);
  }

  factory SigningKey.fromSeed(List<int> seed) {
    if (seed == null || seed?.length != seedSize) {
      throw Exception(
          'SigningKey must be created from a $seedSize byte seed');
    }

    // It generates a valid length Uin8List
    final priv = Uint8List.fromList(seed + AsymmetricKey(32));
    final pub = AsymmetricKey(TweetNaCl.publicKeyLength);
    TweetNaCl.crypto_sign_keypair(pub, priv, seed);
    return SigningKey._fromValidBytes(priv, pub);
  }

  factory SigningKey.generate() {
    final secret = TweetNaCl.randombytes(AsymmetricKey.keyLength);
    return SigningKey.fromSeed(secret);
  }

  static const seedSize = TweetNaCl.seedSize;
  final VerifyKey verifyKey;

  SignedMessage sign(List<int> message) {
    // signed message
    Uint8List sm = Uint8List(message.length + _kSignatureLength);
    final result = TweetNaCl.crypto_sign(sm, -1, Uint8List.fromList(message), 0, message.length, this);
    if (result != 0 ) {
      throw Exception('Signing the massage is failed');
    }
    //final bytesLength = 64;
    return SignedMessage.fromList(sm);
  }
}
