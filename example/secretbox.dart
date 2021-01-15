import 'package:pinenacl/api.dart';
import 'package:pinenacl/x25519.dart' show SecretBox;

void main() {
  print('\n### Secret Key Encryption - SecretBox Example ###\n');
  final key = PineNaClUtils.randombytes(SecretBox.keyLength);
  final box = SecretBox(key);

  final message =
      'Change is a tricky thing, it threatens what we find familiar with...';

  final encrypted = box.encrypt(message.codeUnits);

  final decrypted = box.decrypt(encrypted);

  final ctext = encrypted.cipherText;

  assert(ctext.length == message.length + SecretBox.macBytes);

  final plaintext = String.fromCharCodes(decrypted);
  print(plaintext);
  assert(message == plaintext);
}
