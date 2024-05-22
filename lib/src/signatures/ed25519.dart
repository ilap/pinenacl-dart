import 'package:pinenacl/api.dart';
import 'package:pinenacl/api/signatures.dart';
import 'package:pinenacl/src/tweetnacl/tweetnacl.dart';

class Signature extends ByteList implements SignatureBase {
  Signature(Uint8List super.bytes)
      : super.withConstraint(constraintLength: signatureLength);
  static const signatureLength = TweetNaCl.signatureLength;
}

class VerifyKey extends AsymmetricPublicKey implements Verify {
  VerifyKey(super.bytes, {super.keyLength = keyLength});
  VerifyKey.decode(String keyString,
      {Encoder coder = decoder, int keyLength = keyLength})
      : this(coder.decode(keyString), keyLength: keyLength);

  static const keyLength = TweetNaCl.publicKeyLength;

  static const decoder = Bech32Encoder(hrp: 'ed25519_pk');

  @override
  VerifyKey get publicKey => this;

  @override
  Encoder get encoder => decoder;

  @override
  bool verifySignedMessage({required EncryptionMessage signedMessage}) =>
      verify(
          signature: signedMessage.signature,
          message: signedMessage.message.asTypedList);
  @override
  bool verify({required SignatureBase signature, required Uint8List message}) {
    if (signature.length != TweetNaCl.signatureLength) {
      throw Exception(
          'Signature length (${signature.length}) is invalid, expected "${TweetNaCl.signatureLength}"');
    }
    final newmessage = signature.asTypedList + message;

    if (newmessage.length < TweetNaCl.signatureLength) {
      throw Exception(
          'Signature length (${newmessage.length}) is invalid, expected "${TweetNaCl.signatureLength}"');
    }

    var m = Uint8List(newmessage.length);

    final result = TweetNaCl.crypto_sign_open(m, -1,
        Uint8List.fromList(newmessage), 0, newmessage.length, asTypedList);
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
class SigningKey extends AsymmetricPrivateKey with Suffix implements Sign {
  /// An Ed25519 signingKey is the private key for producing digital signatures
  /// using the Ed25519 algorithm.
  ///  simply the concatenation of the seed and
  /// the generated public key from the `SHA512`-ed and `prone-to-buffer`-ed
  /// seed as a private key.
  ///
  /// seed (i.e. private key) is a random 32-byte value.
  SigningKey({required Uint8List seed}) : this.fromSeed(seed);

  SigningKey.fromValidBytes(super.secret,
      {super.keyLength = TweetNaCl.signingKeyLength});

  SigningKey.fromSeed(Uint8List seed)
      : this.fromValidBytes(_seedToSecret(seed));

  SigningKey.generate()
      : this.fromSeed(TweetNaCl.randombytes(TweetNaCl.seedSize));

  SigningKey.decode(String keyString, [Encoder coder = decoder])
      : this.fromValidBytes(coder.decode(keyString));

  static const decoder = Bech32Encoder(hrp: 'ed25519_sk');

  @override
  Encoder get encoder => decoder;

  static const seedSize = TweetNaCl.seedSize;

  @override
  int get prefixLength => seedSize;

  ByteList get seed => prefix;

  VerifyKey? _verifyKey;

  @override
  VerifyKey get verifyKey => _verifyKey ??= VerifyKey(suffix.asTypedList);

  @override
  AsymmetricPublicKey get publicKey => verifyKey;

  static Uint8List _seedToSecret(Uint8List seed) {
    if (seed.length != seedSize) {
      throw Exception('SigningKey must be created from a $seedSize byte seed');
    }

    //if (seed is Uint8List) {
    //  seed = seed.toList();
    //}

    final priv =
        Uint8List.fromList(seed + Uint8List(TweetNaCl.publicKeyLength));
    final pub = Uint8List(TweetNaCl.publicKeyLength);
    TweetNaCl.crypto_sign_keypair(pub, priv, Uint8List.fromList(seed));

    return SigningKey.fromValidBytes(priv).asTypedList;
  }

  @override
  SignedMessage sign(Uint8List message) {
    // signed message
    var sm = Uint8List(message.length + TweetNaCl.signatureLength);
    final result = TweetNaCl.crypto_sign(
        sm, -1, Uint8List.fromList(message), 0, message.length, asTypedList);
    if (result != 0) {
      throw Exception('Signing the massage is failed');
    }

    return SignedMessage.fromList(signedMessage: sm);
  }
}

class SignedMessage extends ByteList with Suffix implements EncryptionMessage {
  SignedMessage({required SignatureBase signature, required Uint8List message})
      : super.withConstraint(signature + message,
            constraintLength: signatureLength);
  SignedMessage.fromList({required Uint8List signedMessage})
      : super(signedMessage);

  @override
  int get prefixLength => signatureLength;

  static const signatureLength = TweetNaCl.signatureLength;

  @override
  SignatureBase get signature => Signature(prefix.asTypedList);

  @override
  ByteList get message => suffix;
}
