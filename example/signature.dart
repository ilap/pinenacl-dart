import 'package:convert/convert.dart';
import 'package:pinenacl/signing.dart';

void main() {
  /// 
  /// Signer’s perspective (SigningKey)
  ///
 
  // Generate a new random signing key
  final signingKey = SigningKey.generate();

  final message = 'People see the things they want to see...';
  // Sign a message with the signing key
  final signed = signingKey.sign(message.codeUnits);

  //  Obtain the verify key for a given signing key
  final verifyKey = signingKey.verifyKey;

  // Serialize the verify key to send it to a third party
  // TODO: implements similar: verifyKey.encode(Bech32Encoder(hrp: 'ed25519_pk'));
  final verifyKeyHex = hex.encode(verifyKey);

  /// 
  /// Verifier’s perspective (VerifyKey)
  /// 
  // TODO: implements similar: VerifyKey.decode(verifyKeyHex, decoder: HexEncoder());
  final verifyKey2 = VerifyKey.fromHexString(verifyKeyHex);
  assert(verifyKey == verifyKey2);
  print('The "$message" is successfully verified');

  // Check the validity of a message's signature
  // The message and the signature can either be passed separately or
  // concatenated together.  These are equivalent:
  verifyKey.verify(signed);
  verifyKey.verify(signed.message, signed.signature);

  // Alter the signed message text
  signed[0] ^= signed[0] + 1;

  try {
    // Forged message.
    verifyKey.verify(signed);
  } on Exception catch(e) {
    print('Successfully cought: $e');
  }
}
