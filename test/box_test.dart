import 'package:test/test.dart';

import 'package:convert/convert.dart';

import 'package:pinenacl/api.dart';
import 'package:pinenacl/public.dart';

const _vectors = {
  'privalice':
      '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
  'pubalice':
      '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
  'privbob': '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
  'pubbob': 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
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
  group('Public Key Encryption', () {
    final pub = PublicKey.fromHexString(
        'ec2bee2d5be613ca82e377c96a0bf2220d823ce980cdff6279473edc52862798');
    final priv = PrivateKey.fromHexString(
        '5c2bee2d5be613ca82e377c96a0bf2220d823ce980cdff6279473edc52862798');

    test('Boxing Test', () {
      final b1 = Box(myPrivateKey: priv, theirPublicKey: pub);
      final b2 = Box.fromSharedKey(b1.sharedKey);

      assert(b1.sharedKey == b2.sharedKey);
    });
    test('Test Box decode', () {
      final b1 = Box(myPrivateKey: priv, theirPublicKey: pub);
      final b2 = Box.decode(b1.sharedKey);
      assert(b1.sharedKey == b2.sharedKey);
    });

    test('Test Box class', () {
      final pub = PublicKey.fromHexString(
          'ec2bee2d5be613ca82e377c96a0bf2220d823ce980cdff6279473edc52862798');
      final priv = PrivateKey.fromHexString(
          '5c2bee2d5be613ca82e377c96a0bf2220d823ce980cdff6279473edc52862798');
      final b = Box(myPrivateKey: priv, theirPublicKey: pub);

      assert(b == b.sharedKey);
      assert(b.length == b.sharedKey.length);
    });

    test('Test Box encryption', () {
      final pubalice = PublicKey.fromHexString(_vectors['pubalice']);
      final privbob = PrivateKey.fromHexString(_vectors['privbob']);

      final box = Box(myPrivateKey: privbob, theirPublicKey: pubalice);

      final nonce = _vectors['nonce'];
      final ciphertext = _vectors['ciphertext'];
      final plaintext = _vectors['plaintext'];

      final encrypted =
          box.encrypt(hex.decode(plaintext), nonce: hex.decode(nonce));

      final expected = hex.decode(nonce + ciphertext);

      assert(hex.encode(encrypted) == hex.encode(expected));
      assert(hex.encode(encrypted.nonce) == nonce);
      assert(hex.encode(encrypted.ciphertext) == ciphertext);
    });

    test('Test Box decryption', () {
      final privalice = PrivateKey.fromHexString(_vectors['privalice']);
      final pubbob = PublicKey.fromHexString(_vectors['pubbob']);
      final nonce = _vectors['nonce'];
      final plaintext = _vectors['plaintext'];
      final ciphertext = _vectors['ciphertext'];

      final box = Box(myPrivateKey: privalice, theirPublicKey: pubbob);

      final decrypted =
          box.decrypt(hex.decode(ciphertext), nonce: hex.decode(nonce));

      assert(hex.encode(decrypted.plaintext) == plaintext);
    });

    test('Test Box encryption and decryption combined', () {
      final privalice = PrivateKey.fromHexString(_vectors['privalice']);
      final pubalice = PublicKey.fromHexString(_vectors['pubalice']);
      final privbob = PrivateKey.fromHexString(_vectors['privbob']);
      final pubbob = PublicKey.fromHexString(_vectors['pubbob']);

      final box = Box(myPrivateKey: privbob, theirPublicKey: pubalice);
      final box1 = Box(myPrivateKey: privalice, theirPublicKey: pubbob);

      final nonce = _vectors['nonce'];
      final plaintext = _vectors['plaintext'];

      final encrypted =
          box.encrypt(hex.decode(plaintext), nonce: hex.decode(nonce));

      // NOTE: nonce is retrieved from the EncryptedMessage class
      final decrypted = box1.decrypt(encrypted);

      assert(hex.encode(decrypted.plaintext) == plaintext);
    });

    test('Test Nonce encryption and decryption combined', () {
      final privalice = PrivateKey.fromHexString(_vectors['privalice']);
      final pubbob = PublicKey.fromHexString(_vectors['pubbob']);

      final box = Box(myPrivateKey: privalice, theirPublicKey: pubbob);

      final plaintext = _vectors['plaintext'];
      final nonce_0 = box.encrypt(hex.decode(plaintext)).nonce;

      final nonce_1 = box.encrypt(hex.decode(plaintext)).nonce;

      assert(nonce_0 != nonce_1);
    });

    test('Test Wrong AsymmetricKey types', () {
      final priv = PrivateKey.generate();
      final k32 = AsymmetricKey(32);
      final _31 = ByteList(31);

      // TODO: Generalise and implement proper rrror handling by implementing proper exception classes.
      // expect(() => PrivateKey(priv.publicKey), throwsException);
      // expect(() => PrivateKey, returnsNormally);
      // expect(() => PrivateKey(), throwsA(TypeMatcher<EXCTYPE>()));
      // expect(() => PrivateKey(priv.publicKey), throwsA(predicate((e) => e is Error)))
      // expect(() => PrivateKey(), throwsA(predicate((e) => e is ArgumentError && e.message == 'Error')));
      // expect(() => PrivateKey(), throwsA(allOf(isArgumentError, predicate((e) => e.message == 'Error'))));
      expect(() => PrivateKey(priv), returnsNormally);
      expect(() => PrivateKey.fromSeed(_31), throwsException);
      expect(() => PublicKey(), returnsNormally);
      expect(() => PublicKey.fromList(_31), throwsException);

      // Valid combinations
      expect(
          () => Box(myPrivateKey: null, theirPublicKey: null, sharedKey: k32),
          returnsNormally);
      expect(
          () => Box(
              myPrivateKey: priv,
              theirPublicKey: priv.publicKey,
              sharedKey: null),
          returnsNormally);

      // Invalid combinations
      expect(
          () => Box(myPrivateKey: null, theirPublicKey: null, sharedKey: null),
          throwsException);
      expect(
          () => Box(
              myPrivateKey: priv,
              theirPublicKey: priv.publicKey,
              sharedKey: k32),
          throwsException);
      expect(
          () => Box(
              myPrivateKey: null,
              theirPublicKey: priv.publicKey,
              sharedKey: k32),
          throwsException);
      expect(
          () => Box(
              myPrivateKey: null,
              theirPublicKey: priv.publicKey,
              sharedKey: null),
          throwsException);
      expect(
          () => Box(myPrivateKey: priv, theirPublicKey: null, sharedKey: k32),
          throwsException);
      expect(
          () => Box(myPrivateKey: priv, theirPublicKey: null, sharedKey: null),
          throwsException);
    });
  });
}
