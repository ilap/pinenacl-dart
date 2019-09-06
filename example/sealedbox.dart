import 'package:pinenacl/public.dart' show SealedBox, PrivateKey;

void main() {

  // Generate Bob's private key, which must be kept secret
  final skbob = PrivateKey.generate();
  final pkbob = skbob.publicKey;

  // Alice wishes to send a encrypted message to Bob,
  // but prefers the message to be untraceable
  // she puts it into a secretbox and seals it.
  final sealedBox = SealedBox(pkbob);

  final message = 'The world is changing around us and we can either get '
      'with the change or we can try to resist it';

  final encrypted = sealedBox.encrypt(message.codeUnits);

  // Bob unseals the box with his privatekey, and decrypts it.
  final unsealedBox = SealedBox(skbob);

  final plainText = unsealedBox.decrypt(encrypted);
  print(String.fromCharCodes(plainText));
  assert(message == String.fromCharCodes(plainText));
}
