import 'dart:io';
import 'dart:convert';

import 'package:convert/convert.dart';
import 'package:test/test.dart';

import 'package:pinenacl/signing.dart';
import 'package:pinenacl/api.dart';

const _vectors = {
  'seed': '002fdd1f7641793ab064bb7aa848f762e7ec6e332ffc26eeacda141ae33b1783',
  'pk': '77d1d8ebacd13f4e2f8a40e28c4a63bc9ce3bfb69716334bcb28a33eb134086c',
  'public': '77d1d8ebacd13f4e2f8a40e28c4a63bc9ce3bfb69716334bcb28a33eb134086c',
  'message':
      '5ac1dfc324f43e6cb79a87ab0470fa857b51fb944982e19074ca44b1e40082c1d07b92efa7ea55ad42b7c027e0b9e33756d95a2c1796a7c2066811dc41858377d4b835c1688d638884cd2ad8970b74c1a54aadd27064163928a77988b24403aa85af82ceab6b728e554761af7175aeb99215b7421e4474c04d213e01ff03e3529b11077cdf28964b8c49c5649e3a46fa0a09dcd59dcad58b9b922a83210acd5e65065531400234f5e40cddcf9804968e3e9ac6f5c44af65001e158067fc3a660502d13fa8874fa93332138d9606bc41b4cee7edc39d753dae12a873941bb357f7e92a4498847d6605456cb8c0b425a47d7d3ca37e54e903a41e6450a35ebe5237c6f0c1bbbc1fd71fb7cd893d189850295c199b7d88af26bc8548975fda1099ffefee42a52f3428ddff35e0173d3339562507ac5d2c45bbd2c19cfe89b',
  'signature':
      '0df3aa0d0999ad3dc580378f52d152700d5b3b057f56a66f92112e441e1cb9123c66f18712c87efe22d2573777296241216904d7cdd7d5ea433928bd2872fa0c',
  'expected':
      '0df3aa0d0999ad3dc580378f52d152700d5b3b057f56a66f92112e441e1cb9123c66f18712c87efe22d2573777296241216904d7cdd7d5ea433928bd2872fa0c5ac1dfc324f43e6cb79a87ab0470fa857b51fb944982e19074ca44b1e40082c1d07b92efa7ea55ad42b7c027e0b9e33756d95a2c1796a7c2066811dc41858377d4b835c1688d638884cd2ad8970b74c1a54aadd27064163928a77988b24403aa85af82ceab6b728e554761af7175aeb99215b7421e4474c04d213e01ff03e3529b11077cdf28964b8c49c5649e3a46fa0a09dcd59dcad58b9b922a83210acd5e65065531400234f5e40cddcf9804968e3e9ac6f5c44af65001e158067fc3a660502d13fa8874fa93332138d9606bc41b4cee7edc39d753dae12a873941bb357f7e92a4498847d6605456cb8c0b425a47d7d3ca37e54e903a41e6450a35ebe5237c6f0c1bbbc1fd71fb7cd893d189850295c199b7d88af26bc8548975fda1099ffefee42a52f3428ddff35e0173d3339562507ac5d2c45bbd2c19cfe89b',
};

void main() {
  group('Secret Key Encryption', () {
    test('SecretBox basic', () {
      final seed = _vectors['seed'];
      //final public = _vectors['public'];
      final message = _vectors['message'];
      final signature = _vectors['signature'];
      final expected = SignedMessage.fromList(hex.decode(_vectors['expected']));

      final signingKey = SigningKey(hex.decode(seed));
      final signed = signingKey.sign(hex.decode(message));

      assert(signed == expected);
      assert(hex.encode(signed.message) == message);
      assert(hex.encode(signed.signature) == signature);
    });
  });

  group('Sign and verify Ed25519 test vectors ', () {
    final dir = Directory.current;
    final file = File('${dir.path}/test/data/ed25519_vectors.json');
    final contents = file.readAsStringSync();
    final tests = JsonDecoder().convert(contents);

    int idx = 0;
    tests.forEach((vector) {
      String description = 'TestVector: ${++idx}';
      test(description, () {
        final seed = hex.decode(vector['seed']).sublist(0, 32);
        final public = hex.decode(vector['publ']);
        final message = hex.decode(vector['mesg']);
        final signedMessage = hex.decode(vector['sigd']);
        final signature = signedMessage.sublist(0, 64);
        final expected = SignedMessage.fromList(signedMessage);

        final signingKey = SigningKey(seed);
        final signed = signingKey.sign(message);

        final verifyKey = VerifyKey.fromList(public);
        expect(() => verifyKey.verify(signed), returnsNormally);
        expect(() => verifyKey.verify(signed.message, signed.signature),
            returnsNormally);

        assert(signed == expected);
        assert(hex.encode(signed.message) == hex.encode(message));
        assert(hex.encode(signed.signature) == hex.encode(signature));
      });
    });

  });


    group('Wrong types test', () {
      test('SigningKey and VerifyKey', () {
        final sk = SigningKey.generate();
        final _31 = ByteList(31);
        expect(() => SigningKey(sk), throwsException);
        expect(() => SigningKey.fromSeed(_31), throwsException);
        expect(() => VerifyKey(sk), throwsException);
      });
    });
}
