import 'package:pinenacl/signing.dart';

void main() {
  print('\n### Digital Signatures - Signing Example ###\n');

  /// Signer’s perspective (SigningKey)
  ///
  // Generate a new random signing key
  final signingKey = SigningKey<Ed25519>.generate();

  final message = 'People see the things they want to see...';
  final forgedMessage = 'people see the things they want to see...';
  // Sign a message with the signing key
  final signed = signingKey.sign(message.codeUnits);

  //  Obtain the verify key for a given signing key
  final verifyKey = signingKey.verifyKey;

  // Serialize the verify key to send it to a third party
  // TODO: implements similar: verifyKey.encode(Bech32Encoder(hrp: 'ed25519_pk'));
  final verifyKeyHex = verifyKey.encode(hexEncoder);

  ///
  /// Verifier’s perspective (VerifyKey)
  ///
  // TODO: implements similar: VerifyKey.decode(verifyKeyHex, decoder: HexEncoder());
  final verifyKey2 = VerifyKey<Ed25519>.decode(verifyKeyHex, hexEncoder);
  assert(verifyKey == verifyKey2);
  print('The "$message" is successfully verified');

  // Check the validity of a message's signature
  // The message and the signature can either be passed separately or
  // concatenated together.  These are equivalent:
  verifyKey.verifySignedMessage(signedMessage: signed);
  verifyKey.verify(signature: signed.signature, message: signed.message);

  try {
    // Forged message.
    verifyKey.verify(
        signature: signed.signature, message: forgedMessage.codeUnits);
  } on Exception catch (e) {
    print('Exception\'s successfully cought:\n$e');
  }
}
