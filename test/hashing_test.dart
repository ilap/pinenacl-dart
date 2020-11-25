import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';

import 'package:pinenacl/encoding.dart';
import 'package:test/test.dart';

import 'package:pinenacl/hashing.dart';

void main() {
  const hex = HexCoder.instance;
  group('Hashing', () {
    group('SHA-256', () {
      final dir = Directory.current;
      final file = File('${dir.path}/test/data/sha256_vectors.json');
      final contents = file.readAsStringSync();
      final dynamic tests = JsonDecoder().convert(contents);

      var idx = 0;
      tests.forEach((dynamic vector) {
        final description = 'SHA Validation System\'s testvectors (${++idx})';
        test(description, () {
          final digest = vector['digest']! as String;
          final message =
              Uint8List.fromList(hex.decode(vector['message']! as String));

          final hash = Hash.sha256(message);
          assert(digest == hex.encode(hash));
        });
      });
    });

    group('SHA-512', () {
      final dir = Directory.current;
      final file = File('${dir.path}/test/data/sha512_vectors.json');
      final contents = file.readAsStringSync();
      final dynamic tests = JsonDecoder().convert(contents);

      var idx = 0;
      tests.forEach((dynamic vector) {
        final description = 'SHA Validation System\'s testvectors (${++idx})';
        test(description, () {
          final digest = vector['digest']! as String;
          final message =
              Uint8List.fromList(hex.decode(vector['message']! as String));

          final hash = Hash.sha512(message);

          assert(digest == hex.encode(hash));
        });
      });
    });

    group('Blake2B', () {
      final dir = Directory.current;
      final file = File('${dir.path}/test/data/blake2b_vectors.json');
      final contents = file.readAsStringSync();
      final dynamic tests = JsonDecoder().convert(contents);

      var idx = 0;
      tests.forEach((dynamic vector) {
        ++idx;
        final origin = idx < 513 ? 'RFC7693' : 'Libsodium';
        final offset = idx < 513 ? idx : idx - 512;
        final description = '$origin testvectors ($offset)';
        test(description, () {
          final out = vector['out']! as String;
          final outlen = vector['outlen']! as int;
          final input =
              Uint8List.fromList(hex.decode(vector['input']! as String));
          final key = Uint8List.fromList(hex.decode(vector['key']! as String));
          final salt =
              Uint8List.fromList(hex.decode(vector['salt']! as String));
          final personal =
              Uint8List.fromList(hex.decode(vector['personal']! as String));

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
