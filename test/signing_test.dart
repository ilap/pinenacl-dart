import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:test/test.dart';

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

const _cardanoVectors = [
  {
    'seed': '2d2086832cc2fe3fd18cb51d6c5e99a5759f02211f85e5ff2f904a780f58006f',
    'message':
        '898f9c4b2c6ee9e228761ca50897b71ffeca1c352846f5fe13f7d3d57e2c15ac60900ca32c5b5dd953c9a6810acc64394ffd149826d99806292addd13fc3bb7dac701c5b4a2d615d15960128ed9f736b98854f6f0705b0f0dacbdc2c262d27397519149b0e4cbe1677c576c1397aae5ce34916e3513104632ec2190db8d22289c3723c8d01213cad803f4d7574c4dbb53731b01c8ec75d082ef7dc9d7f1b73159f63db56aa12a2ca39eace6b28e4c31d9d256741452e8387e1536d03026ee48410d43b219188ba14a8af',
    'signature':
        '912091661eed18a4034bc7db4bd60fe2deebf3ff3b6b998dae2094b609865c2019ec6722bfdc87bda54091922e11e393f5fdceea3e091f2ee6bc62df948e9909'
  },
  {
    'seed': '33191782c1704f60d0848d7562a2fa19f9924fea4e7733cd45f6c32f219a7291',
    'message':
        '7713435a0e346f6771ae5adea87ae7a452c65d748f4869d31ed36747c328ddc4ec0e486793a51c6766f7064826d074514dd05741f3be273ef21f280e4907ed89be301a4ec8496eb6ab900006e5a3c8e9c993621d6a3b0f6cbad0fddef3b9c82d',
    'signature':
        '4b8d9b1eca5400eac6f5cc0c9439630052f734ce453e9426f319dd9603b6aeaeb9d23a5f93f06a460018f069df194448f56051ab9e6bfaeb641016f7a90be20c'
  }
];

void main() {
  group('Digital Signatures #1', () {
    group('Basic tests', () {
      test('simple signing test', () {
        final seed = _vectors['seed'];
        //final public = _vectors['public'];
        final message = _vectors['message'];
        final signature = _vectors['signature'];
        final expected = SignedMessage.fromList(
            signedMessage: hex.decode(_vectors['expected']));

        final signingKey = SigningKey(seed: hex.decode(seed));
        final signed = signingKey.sign(hex.decode(message));

        assert(signed == expected);
        assert(hex.encode(signed.message) == message);
        assert(hex.encode(signed.signature) == signature);
      });
    });

    group('Sign and verify Cardano\'s cryptoxide ed25519 testvectors', () {
      var idx = 0;
      _cardanoVectors.forEach((vector) {
        final description = ' (${++idx})';
        test(description, () {
          final seed = vector['seed'];
          final message = vector['message'];
          final signature = vector['signature'];

          final signingKey = SigningKey(seed: hex.decode(seed));
          final signed = signingKey.sign(hex.decode(message));

          assert(hex.encode(signed.message) == message);
          assert(hex.encode(signed.signature) == signature);
        });
      });
    });

    group('Sign and verify Ed25519 testvectors', () {
      final dir = Directory.current;
      final file = File('${dir.path}/test/data/ed25519_vectors.json');
      final contents = file.readAsStringSync();
      final tests = JsonDecoder().convert(contents);

      int idx = 0;
      tests.forEach((vector) {
        String description = ' (${++idx})';
        test(description, () {
          final seed = hex.decode(vector['seed']).sublist(0, 32);
          final public = hex.decode(vector['publ']);
          final message = hex.decode(vector['mesg']);
          final signedMessage = hex.decode(vector['sigd']);
          final signature = signedMessage.sublist(0, 64);
          final expected = SignedMessage.fromList(signedMessage: signedMessage);

          final signingKey = SigningKey(seed: seed);
          final signed = signingKey.sign(message);

          final verifyKey = VerifyKey(public);
          expect(() => verifyKey.verifySignedMessage(signedMessage: signed),
              returnsNormally);
          expect(
              () => verifyKey.verify(
                  signature: signed.signature, message: signed.message),
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
        final _31 = Uint8List(31);

        expect(() => SigningKey(seed: sk), throwsException);
        expect(() => SigningKey.fromSeed(_31), throwsException);

        /// Any validlength bytes (except private key) or
        /// publicKey can be a VerifyKey
        //expect(() => VerifyKey(sk), throwsException);
      });
    });
  });
}
