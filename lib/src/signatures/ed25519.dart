import 'dart:typed_data';

import 'package:pinenacl/api.dart';
import 'package:pinenacl/api/signatures.dart';
import 'package:pinenacl/src/tweetnacl/tweetnacl.dart';

class Signature extends ByteList implements SignatureBase {
  Signature(List<int> bytes) : super(bytes, signatureLength);
  static const signatureLength = TweetNaCl.signatureLength;
}

class VerifyKey extends AsymmetricPublicKey implements Verify {
  VerifyKey(List<int> bytes, [int keyLength = keyLength])
      : super(bytes, keyLength);
  VerifyKey.decode(String keyString, {Encoder coder = decoder})
      : this(coder.decode(keyString), coder.decode(keyString).length);

  static const keyLength = TweetNaCl.publicKeyLength;

  static const decoder = Bech32Coder(hrp: 'ed25519_pk');

  @override
  VerifyKey get publicKey => this;

  @override
  Encoder get encoder => decoder;

  @override
  bool verifySignedMessage({required EncryptionMessage signedMessage}) =>
      verify(
          signature: signedMessage.signature, message: signedMessage.message);
  @override
  bool verify({required SignatureBase signature, required List<int> message}) {
    if (signature.length != TweetNaCl.signatureLength) {
      throw Exception(
          'Signature length (${signature.length}) is invalid, expected "${TweetNaCl.signatureLength}"');
    }
    message = signature + message;

    if (message.length < TweetNaCl.signatureLength) {
      throw Exception(
          'Signature length (${message.length}) is invalid, expected "${TweetNaCl.signatureLength}"');
    }

    var m = Uint8List(message.length);

    final result = TweetNaCl.crypto_sign_open(
        m, -1, Uint8List.fromList(message), 0, message.length, this);
    if (result != 0) {
      throw Exception(
          'The message is forged or malformed or the signature is invalid');
    }
    return true;
  }
}

///
/// SigningKey implements the Ed25519 deterministic signature scheme (EdDSA)
/// using Curve25519, that provides a very fast `fixed-base` and `double-base`
/// scalar multiplications, which faster on most platform than the
/// `variable-base` algorithm of X25519, due to the fast and complete twisted
/// Edwards addition law.
///
/// Cannot extends `AsymmetricPrivateKey` as it would have to implement
/// the final `publicKey`.
///
class SigningKey extends AsymmetricPrivateKey implements Sign {
  /// An Ed25519 signingKey is the private key for producing digital signatures
  /// using the Ed25519 algorithm.
  ///  simply the concatenation of the seed and
  /// the generated public key from the `SHA512`-ed and `prone-to-buffer`-ed
  /// seed as a private key.
  ///
  /// seed (i.e. private key) is a random 32-byte value.
  SigningKey({required List<int> seed}) : this.fromSeed(seed);

  SigningKey.fromValidBytes(List<int> secret,
      {int keyLength = TweetNaCl.signingKeyLength})
      : super(secret, keyLength);

  SigningKey.fromSeed(List<int> seed)
      : this.fromValidBytes(_seedToSecret(seed));

  SigningKey.generate()
      : this.fromSeed(TweetNaCl.randombytes(TweetNaCl.seedSize));

  SigningKey.decode(String keyString, [Encoder coder = decoder])
      : this(seed: coder.decode(keyString));

  static const decoder = Bech32Coder(hrp: 'ed25519_sk');

  @override
  Encoder get encoder => decoder;

  static const seedSize = TweetNaCl.seedSize;

  VerifyKey? _verifyKey;

  @override
  VerifyKey get verifyKey => _verifyKey ??= VerifyKey(sublist(32));

  @override
  AsymmetricPublicKey get publicKey => verifyKey;

  static List<int> _seedToSecret(List<int> seed) {
    if (seed.length != seedSize) {
      throw Exception('SigningKey must be created from a $seedSize byte seed');
    }

    if (seed is Uint8List) {
      seed = seed.toList();
    }

    final priv = Uint8List.fromList(
        seed + List<int>.filled(TweetNaCl.publicKeyLength, 0));
    final pub = Uint8List(TweetNaCl.publicKeyLength);
    TweetNaCl.crypto_sign_keypair(pub, priv, Uint8List.fromList(seed));

    return SigningKey.fromValidBytes(priv);
  }

  @override
  SignedMessage sign(List<int> message) {
    // signed message
    var sm = Uint8List(message.length + TweetNaCl.signatureLength);
    final result = TweetNaCl.crypto_sign(
        sm, -1, Uint8List.fromList(message), 0, message.length, this);
    if (result != 0) {
      throw Exception('Signing the massage is failed');
    }

    return SignedMessage.fromList(signedMessage: sm);
  }
}

class SignedMessage extends ByteList with Suffix implements EncryptionMessage {
  SignedMessage({required SignatureBase signature, required List<int> message})
      : super(signature + message, signatureLength);
  SignedMessage.fromList({required List<int> signedMessage})
      : super(signedMessage);

  @override
  int prefixLength = signatureLength;

  static const signatureLength = TweetNaCl.signatureLength;

  @override
  SignatureBase get signature => Signature(prefix);

  @override
  ByteList get message => suffix;
}
