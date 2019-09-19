import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:test/test.dart';

import 'package:pinenacl/hashing.dart';

void main() {
  group('Hashing', () {
    group('SHA-512', () {
      final dir = Directory.current;
      final file = File('${dir.path}/test/data/sha512_vectors.json');
      final contents = file.readAsStringSync();
      final tests = JsonDecoder().convert(contents);

      int idx = 0;
      tests.forEach((vector) {
        final description = 'SHA Validation System\'s testvectors (${++idx})';
        test(description, () {
          String digest = vector['digest'];
          final message = Uint8List.fromList(hex.decode(vector['message']));

          final hash = Hash.sha512(message);

          assert(digest == hex.encode(hash));
        });
      });
    });

    group('Blake2B', () {
      final dir = Directory.current;
      final file = File('${dir.path}/test/data/blake2b_vectors.json');
      final contents = file.readAsStringSync();
      final tests = JsonDecoder().convert(contents);

      int idx = 0;
      tests.forEach((vector) {
        ++idx;
        final origin = idx < 513 ? 'RFC7693' : 'Libsodium';
        final offset = idx < 513 ? idx : idx - 512;
        final description = '$origin testvectors ($offset)';
        test(description, () {
          final out = vector['out'];
          final outlen = vector['outlen'];
          final input = Uint8List.fromList(hex.decode(vector['input']));
          final key = Uint8List.fromList(hex.decode(vector['key']));
          final salt = Uint8List.fromList(hex.decode(vector['salt']));
          final personal = Uint8List.fromList(hex.decode(vector['personal']));

          final hash = Hash.blake2b(input,
              digestSize: outlen,
              key: key.isEmpty ? null : key,
              salt: salt.isEmpty ? null : salt,
              personalisation: personal.isEmpty ? null : personal);

          assert(out == hex.encode(hash));
        });
      });
    });
  });
}
