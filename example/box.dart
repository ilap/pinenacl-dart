import 'package:pinenacl/api.dart';
import 'package:pinenacl/public.dart' show PrivateKey;

void main() {
  // Generate Bob's private key, which must be kept secret
  final skbob = PrivateKey.generate();

  // Bob's public key can be given to anyone wishing to send
  // Bob an encrypted message
  final pkbob = skbob.publicKey;

  // Alice does the same and then Alice and Bob exchange public keys
  final skalice = PrivateKey.generate();

  final pkalice = skalice.publicKey;

  // Bob wishes to send Alice an encrypted message so Bob must make a Box with
  // his private key and Alice's public key
  final bobBox = Box(myPrivateKey: skbob, theirPublicKey: pkalice);

  // This is our message to send, it must be a bytestring as Box will treat it
  // as just a binary blob of data.
  final message = 'There is no conspiracy out there, but lack of the incentives to drive the people towards the answers.';

  // TweetNaCl can automatically generate a random nonce for us, making the encryption very simple:
  // Encrypt our message, it will be exactly 40 bytes longer than the
  // original message as it stores authentication information and the
  // nonce alongside it.
  final encrypted = bobBox.encrypt(message.codeUnits);

  // Finally, the message is decrypted (regardless of how the nonce was generated):
  // Alice creates a second box with her private key to decrypt the message
  final aliceBox = Box(myPrivateKey: skalice, theirPublicKey: pkbob);

  // Decrypt our message, an exception will be raised if the encryption was
  // tampered with or there was otherwise an error.
  final decrypted = aliceBox.decrypt(encrypted);
  print(String.fromCharCodes(decrypted.plaintext));

  
}
