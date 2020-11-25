import 'dart:typed_data';

import 'package:pinenacl/encoding.dart';
import 'package:test/test.dart';

import 'package:pinenacl/api.dart' show TweetNaCl;

/// The [`NaCl`](https://nacl.cr.yp.to/valid.html) official testvectors from the
/// [Cryptography in NaCl](https://cr.yp.to/highspeed/naclcrypto-20090310.pdf) paper
void main() {
  const hex = HexCoder.instance;
  const aliceSk =
      '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a';
  const alicePk =
      '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a';
  const bobSk =
      '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb';

  const bobPk =
      'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f';

  const sharedSecret =
      '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';
  final zero = Uint8List(32);
  const c = '657870616e642033322d62797465206b';
  const firstKey =
      '1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389';

  const noncesuffix = '8219e0036b7a0b37';
  const noncePrefix = '69696ee955b62b73cd62bda875fc73d6';
  const nonce = noncePrefix + noncesuffix;

  /* TODO: implement them.
  const secondKey =
      'dc908dda0b9344a953629b733820778880f3ceb421bb61b91cbd4c3e66256ce4';
  const m = '0000000000000000000000000000000000000000000000000'
      'be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44'
      'b66849b64244ffce5ecbaaf33bd751a1ac728d45e6c61296c'
      'dc3c01233561f41db66cce314adb310e3be8250c46f06dcee'
      'a3a7fa1348057e2f6556ad6b1318a024a838f21af1fde0489'
      '77eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f'
      '937763848645e0705';

  const boxedPacket =
      'f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce'
      '48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c972'
      '71d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae'
      '90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b3'
      '7973f622a43d14a6599b1f654cb45a74e355a5';
  */
  group('TweetNaCl', () {
    group('Validation', () {
      test('Alice\'s SecretKey to PublicKey to', () {
        final pk = Uint8List(TweetNaCl.publicKeyLength);

        TweetNaCl.crypto_scalarmult_base(pk, hex.decode(aliceSk));

        assert(hex.encode(pk) == alicePk);
      });
      test('Bob\'s SecretKey to PublicKey test', () {
        final pk = Uint8List(TweetNaCl.publicKeyLength);

        TweetNaCl.crypto_scalarmult_base(pk, hex.decode(bobSk));

        assert(hex.encode(pk) == bobPk);
      });
      test('Shared secret (Alice Secret, Bob pulic) test', () {
        final k = Uint8List(TweetNaCl.secretKeyLength);

        TweetNaCl.crypto_scalarmult(k, hex.decode(aliceSk), hex.decode(bobPk));

        assert(hex.encode(k) == sharedSecret);
      });
      test('Shared secret (Bob secret, Alice pulic) test', () {
        final k = Uint8List(TweetNaCl.secretKeyLength);

        TweetNaCl.crypto_scalarmult(k, hex.decode(bobSk), hex.decode(alicePk));

        assert(hex.encode(k) == sharedSecret);
      });
      test('Nonce and stream (1st key) test', () {
        final _1k = Uint8List(TweetNaCl.secretKeyLength);

        TweetNaCl.crypto_core_hsalsa20(
            _1k, zero, hex.decode(sharedSecret), hex.decode(c));

        assert(hex.encode(_1k) == firstKey);
      });
      test('Nonce and stream (4194304 long output) test', () {
        final outLen = 4194304;
        final out = Uint8List(outLen);
        final hashOut = Uint8List(64);

        expect(
            () => TweetNaCl.crypto_stream_salsa20(
                out, 0, outLen, hex.decode(nonce), hex.decode(firstKey)),
            returnsNormally);
        final hexOut = TweetNaCl.crypto_hash(hashOut, out);

        assert(hexOut == 0);
      });
    });
  });
}
