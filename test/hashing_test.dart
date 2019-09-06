import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:test/test.dart';

import 'package:pinenacl/hashing.dart';

const _sha512Vectors = [
  {
    'mesg': '',
    'hash':
        'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e'
  },
  {
    'mesg': 'abc',
    'hash':
        'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'
  },
  {
    'mesg':
        'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu',
    'hash':
        '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909'
  },
  {
    'mesg': 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
    'hash':
        '204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445'
  }
];

void main() {
  group('SHA512', () {
    test('Test vectors', () {
      _sha512Vectors.forEach((vector) {
        final message = vector['mesg'];
        final expected = vector['hash'];
        final hash = Hash.sha512(message);
        assert(expected == hex.encode(hash));
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
      final description = '$origin testvector($offset)';
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
}
