import 'package:pinenacl/api.dart';
import 'package:pinenacl/secret.dart' show SecretBox;

void main() {
  final key = Utils.randombytes(SecretBox.keyLength);
  final box = SecretBox(key);

  final message = 'Change is a tricky thing, it threatens what we find familiar with...';

  final encrypted = box.encrypt(message.codeUnits);

  final decrypted = box.decrypt(encrypted);

  final ctext = encrypted.ciphertext;

  assert(ctext.length == message.length + SecretBox.macBytes);

  final plaintext = String.fromCharCodes(decrypted.plaintext);
  print(plaintext);
  assert(message == plaintext);
}
