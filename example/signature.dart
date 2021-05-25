import 'package:pinenacl/ed25519.dart';

void main() {
  const hex = HexCoder.instance;
  print('\n### Digital Signatures - Signing Example ###\n');

  /// Signer’s perspective (SigningKey)
  //final signingKey = SigningKey.generate();
  const seed =
      '19a91fe23a4e9e33ecc474878f57c64cf154b394203487a7035e1ad9cd697b0d';
  const publ =
      '2bf32ba142ba4622d8f3e29ecd85eea07b9c47be9d64412c9b510b27dd218b23';

  const mesg = '82cb53c4d5a013bae5070759ec06c3c6955ab7a4050958ec328c';
  const sigd =
      '881f5b8c5a030df0f75b6634b070dd27bd1ee3c08738ae349338b3ee6469bbf9760b13578a237d5182535ede121283027a90b5f865d63a6537dca07b44049a0f82cb53c4d5a013bae5070759ec06c3c6955ab7a4050958ec328c';

  final signingKey = SigningKey(seed: hex.decode(seed));
  final verifyKey = signingKey.verifyKey;
  final publicKey = VerifyKey(hex.decode(publ));
  assert(publicKey == verifyKey);
  print('Verify Key: ${hex.encode(verifyKey)}');

  final signed = signingKey.sign(hex.decode(mesg));
  final encoded = hex.encode(signed);

  print(encoded);
  assert(sigd == encoded);
  //  Obtain the verify key for a given signing key

  // Serialize the verify key to send it to a third party
  final verifyKeyHex = verifyKey.encode(hex);

  ///
  /// Verifier’s perspective (VerifyKey)
  ///
  final verifyKey2 = VerifyKey.decode(verifyKeyHex, coder: hex);
  assert(verifyKey == verifyKey2);

  // Check the validity of a message's signature
  // The message and the signature can either be passed separately or
  // concatenated together.  These are equivalent:
  var isVerified = verifyKey.verifySignedMessage(signedMessage: signed);
  isVerified &=
      verifyKey.verify(signature: signed.signature, message: signed.message.asTypedList);

  final resString = isVerified ? '' : 'UN';
  print('Verification of the signature was: ${resString}SUCCESSFULL ');
}
