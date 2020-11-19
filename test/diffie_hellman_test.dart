import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:test/test.dart';

import 'package:pinenacl/api.dart';

void _doShared(String sk, String pk, String sharedSecret) {
  final priv = PrivateKey.decode(sk, hexEncoder);
  final pub = PublicKey.decode(pk, hexEncoder);

  final expected = Uint8List(32);

  /// The expected shared secret, the
  /// K = X25519(a, X25519(b, 9)) = X25519(b, X25519(a, 9))
  TweetNaCl.crypto_scalarmult(expected, priv, pub);
  assert(sharedSecret == hex.encode(expected));
}

void main() {
  /// Official sharedkey from  the [RFC7748](https://tools.ietf.org/html/rfc7748#page-14)
  const officialVector = {
    'ask': '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
    'apk': '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
    'bsk': '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
    'bpk': 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
    'shr': '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742'
  };
  group('Digital Signatures #2', () {
    group('Curve25519 (Diffie-Hellman)', () {
      test('official testvector', () {
        final sharedSecret = officialVector['shr'];

        final alicePriv = PrivateKey.decode(officialVector['ask'], hexEncoder);
        final aliceGenPub = alicePriv.publicKey;
        final alicePub = PublicKey.decode(officialVector['apk'], hexEncoder);

        assert(hex.encode(aliceGenPub) == hex.encode(alicePub));

        final bobPriv = PrivateKey.decode(officialVector['bsk'], hexEncoder);
        final bobGenPub = bobPriv.publicKey;
        final bobPub = PublicKey.decode(officialVector['bpk'], hexEncoder);

        assert(hex.encode(bobGenPub) == hex.encode(bobPub));

        final sharedSecret1 = Uint8List(32);
        final sharedSecret2 = Uint8List(32);

        /// The expected shared secret, the
        /// K = X25519(a, X25519(b, 9)) = X25519(b, X25519(a, 9))
        TweetNaCl.crypto_scalarmult(sharedSecret1, bobPriv, alicePub);
        TweetNaCl.crypto_scalarmult(sharedSecret2, alicePriv, bobPub);

        assert(hex.encode(sharedSecret1) == hex.encode(sharedSecret2));
        assert(hex.encode(sharedSecret1) == sharedSecret);
      });
    });

    group('Wycheproof', () {
      final dir = Directory.current;
      final file = File('${dir.path}/test/wycheproof/X25519.json');
      final contents = file.readAsStringSync();
      final x25519 = JsonDecoder().convert(contents);

      final testGroups = x25519['testGroups'][0];
      final tests = testGroups['tests'];

      tests.forEach((vector) {
        final curve = vector['curve'];
        final comment = vector['comment'];
        final idx = vector['tcId'];
        var description = '$curve - $comment ($idx)';

        test(description, () {
          final public = vector['public'];
          final private = vector['private'];
          final shared = vector['shared'];
          final result = vector['result'];

          if (result == 'valid' || result == 'acceptable') {
            _doShared(private, public, shared);
          } else {
            expect(() => _doShared(private, public, shared), throwsException);
          }
        });
      });
    });
  });
}
