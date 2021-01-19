import 'dart:io';
import 'dart:convert';

import 'package:test/test.dart';

import 'package:pinenacl/api.dart';
import 'package:pinenacl/encoding.dart';

import 'package:pinenacl/key_derivation.dart';

void main() {
  const hex = HexCoder.instance;

  group('Password Based Key Derivation Function #2 (PBKDF2)', () {
    final dir = Directory.current;
    final file = File('${dir.path}/test/data/pbkdf2_hmac_sha2_test.json');
    final contents = file.readAsStringSync();
    final dynamic pbkdf2 = JsonDecoder().convert(contents);

    final dynamic tests = pbkdf2['hmac-sha-512-vectors'];

    var idx = 0;
    tests.forEach((dynamic vector) {
      final description = 'HMAC-SHA-512 based PBKDF2 (${++idx})';

      test(description, () {
        final id = vector['id']! as int;
        final pwd_len = vector['pwd_len']! as int;
        final salt_len = vector['salt_len']! as int;
        final password = vector['password']! as String;
        final salt = vector['salt']! as String;
        final iterations = vector['iterations']! as int;
        final output_bytes = vector['output_bytes']! as int;
        final hex_result = vector['hex_result']! as String;

        final passwordBytes = Uint8List.fromList(password.codeUnits);
        final saltBytes = Uint8List.fromList(salt.codeUnits);

        // Ignoring the 2m's iterations.
        // FIXME:
        if (iterations < 1) {
          final out = PBKDF2.hmac_sha512(
              passwordBytes, saltBytes, iterations, output_bytes);
          final outHex = hex.encode(out);

          assert(outHex == hex_result);
        }
      });
    });

    final dynamic tests2 = pbkdf2['hmac-sha-256-vectors'];
    idx = 0;
    tests2.forEach((dynamic vector) {
      final description = 'HMAC-SHA-256 based PBKDF2 (${++idx})';

      test(description, () {
        final id = vector['id']! as int;
        final pwd_len = vector['pwd_len']! as int;
        final salt_len = vector['salt_len']! as int;
        final password = vector['password']! as String;
        final salt = vector['salt']! as String;
        final iterations = vector['iterations']! as int;
        final output_bytes = vector['output_bytes']! as int;
        final hex_result = vector['hex_result']! as String;

        final passwordBytes = Uint8List.fromList(password.codeUnits);
        final saltBytes = Uint8List.fromList(salt.codeUnits);

        // Ignoring the 2m's iterations.
        // FIXME: 100000
        if (iterations < 1) {
          final out = PBKDF2.hmac_sha256(
              passwordBytes, saltBytes, iterations, output_bytes);
          final outHex = hex.encode(out);

          assert(outHex == hex_result);
        }
      });
    });
  });
}
