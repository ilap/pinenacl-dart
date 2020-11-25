import 'dart:typed_data';

import 'package:pinenacl/encoding.dart';
import 'package:test/test.dart';

import 'package:pinenacl/secret.dart' show SecretBox;

const _vectors = {
  'key': '1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389',
  'nonce': '69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37',
  'plaintext':
      'be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5e'
          'cbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb310e3be8'
          '250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde048977eb4'
          '8f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848645e0705',
  'ciphertext':
      'f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce483'
          '32ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c97271d2c2'
          '0f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae902243685'
          '17acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d'
          '14a6599b1f654cb45a74e355a5'
};

void main() {
  const hex = HexCoder.instance;
  group('Secret Key Encryption', () {
    test('SecretBox basic', () {
      final s = SecretBox.decode(
          'ec2bee2d5be613ca82e377c96a0bf2220d823ce980cdff6279473edc52862798');
      assert(s == s.key);
    });

    test('SecretBox encryption', () {
      final box = SecretBox.decode(_vectors['key']!);

      final nonce = _vectors['nonce']!;
      final cipherText = _vectors['ciphertext']!;
      final plainText = _vectors['plaintext']!;

      final encrypted =
          box.encrypt(hex.decode(plainText), nonce: hex.decode(nonce));

      final expected = hex.decode(nonce + cipherText);

      assert(hex.encode(encrypted) == hex.encode(expected));
      assert(hex.encode(encrypted.nonce) == nonce);
      assert(hex.encode(encrypted.cipherText) == cipherText);
    });

    test('SecretBox decryption', () {
      final box = SecretBox.decode(_vectors['key']!);

      final nonce = _vectors['nonce']!;
      final ciphertext = _vectors['ciphertext']!;
      final plaintext = _vectors['plaintext']!;

      final decrypted = box.decrypt(Uint8List.fromList(hex.decode(ciphertext)),
          nonce: Uint8List.fromList(hex.decode(nonce)));

      assert(hex.encode(decrypted) == plaintext);
    });

    test('SecretBox decryption (no nonce)', () {
      final box = SecretBox.decode(_vectors['key']!);

      final plaintext = _vectors['plaintext'];

      final encrypted = box.encrypt(hex.decode(plaintext!));
      final decrypted = box.decrypt(encrypted);

      assert(hex.encode(decrypted) == plaintext);
    });
  });
}
