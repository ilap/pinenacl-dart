import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:pinenacl/api.dart';

import 'package:pinenacl/encoding.dart';
import 'package:pinenacl/message_authentication.dart';

import 'package:pinenacl/tweetnacl.dart';
import 'package:pinenacl/key_derivation.dart';

/// The official testvectors from the
///  [`Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512`](https://tools.ietf.org/html/rfc4231)
/// RFC (RFC4231)
const vectors = [
  {
    'key': '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
    'key_length': 20,
    'data': '4869205468657265', // 'Hi There',
    'hmac-sha-224': '896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22',
    'hmac-sha-256':
        'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
    'hmac-sha-384':
        'afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6',
    'hmac-sha-512':
        '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854'
  },
  {
    'key': '4a656665', // ("Jefe")
    'key_length': 4,
    'data':
        '7768617420646f2079612077616e7420666f72206e6f7468696e673f', // ("what do ya want ")("for nothing?")
    'hmac-sha-224': 'a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44',
    'hmac-sha-256':
        '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
    'hmac-sha-384':
        'af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649',
    'hmac-sha-512':
        '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737'
  },
  {
    'key': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', //(20 bytes)
    'key_length': 20,
    'data':
        'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', // (50 bytes)

    'hmac-sha-224': '7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea',
    'hmac-sha-256':
        '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe',
    'hmac-sha-384':
        '88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27',
    'hmac-sha-512':
        'fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb',
  },
  {
    'key': '0102030405060708090a0b0c0d0e0f10111213141516171819', // (25 bytes)
    'key_length': 25,
    'data':
        'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd', //  (50 bytes)
    'hmac-sha-224': '6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a',
    'hmac-sha-256':
        '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b',
    'hmac-sha-384':
        '3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb',
    'hmac-sha-512':
        'b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd'
  },
  {
    'key': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        'aaaaaa', //  (131 bytes)
    'key_length': 131,
    'data': '54657374205573696e67204c61726765' //  ("Test Using Large")
        '72205468616e20426c6f636b2d53697a' //  ("r Than Block-Siz")
        '65204b6579202d2048617368204b6579' //  ("e Key - Hash Key")
        '204669727374', //     (" First")

    'hmac-sha-224': '95e9a0db962095adaebe9b2d6f0dbce2'
        'd499f112f2d2b7273fa6870e',
    'hmac-sha-256': '60e431591ee0b67f0d8a26aacbf5b77f'
        '8e0bc6213728c5140546040f0ee37f54',
    'hmac-sha-384': '4ece084485813e9088d2c63a041bc5b4'
        '4f9ef1012a2b588f3cd11f05033ac4c6'
        '0c2ef6ab4030fe8296248df163f44952',
    'hmac-sha-512': '80b24263c7c1a3ebb71493c1dd7be8b4'
        '9b46d1f41b4aeec1121b013783f8f352'
        '6b56d037e05f2598bd0fd2215d6a1e52'
        '95e64f73f63f0aec8b915a985d786598',
  },
  {
    'key': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        'aaaaaa', //  (131 bytes)
    'key_length': 131,
    'data': '54686973206973206120746573742075' //  ("This is a test u")
        '73696e672061206c6172676572207468' //  ("sing a larger th")
        '616e20626c6f636b2d73697a65206b65' //  ("an block-size ke")
        '7920616e642061206c61726765722074' //  ("y and a larger t")
        '68616e20626c6f636b2d73697a652064' //  ("han block-size d")
        '6174612e20546865206b6579206e6565' //  ("ata. The key nee")
        '647320746f2062652068617368656420' //  ("ds to be hashed ")
        '6265666f7265206265696e6720757365' //  ("before being use")
        '642062792074686520484d414320616c' //  ("d by the HMAC al")
        '676f726974686d2e', // ("gorithm.")

    'hmac-sha-224': '3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1',
    'hmac-sha-256':
        '9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2',
    'hmac-sha-384':
        '6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e',
    'hmac-sha-512':
        'e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58',
  }
];

void main() {
  const hex = HexCoder.instance;
  group('Hash-based message authentication code', () {
    group('HMAC-SHA-', () {
      var idx = 0;
      vectors.forEach((vector) {
        final description = 'RFC4231\'s testvectors (${++idx})';
        final k = Uint8List.fromList(hex.decode(vector['key'] as String));
        final kLen = vector['key_length'];
        final data = Uint8List.fromList(hex.decode(vector['data'] as String));

        test('512 ' + description, () {
          final mac = vector['hmac-sha-512'];

          assert(k.length == kLen);
          final out = Uint8List(64);
          TweetNaClExt.crypto_auth_hmacsha512(out, data, k);

          assert(mac == hex.encode(out));
        });

        test('256 ' + description, () {
          final mac = vector['hmac-sha-256'];

          assert(k.length == kLen);

          final out = Uint8List(32);

          TweetNaClExt.crypto_auth_hmacsha256(out, data, k);

          assert(mac == hex.encode(out));
        });
      });
    });
  });
}
