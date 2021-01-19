import 'dart:typed_data';

import 'package:pinenacl/api.dart';
import 'package:pinenacl/tweetnacl.dart';
/*
JIT - order is important for stopwatch.
500 iterations of TweetNaCl - scalarmult_base took 0.648 sec(s)
500 iterations of TweetNaCl - hsalsa20 took 0.699 sec(s)
10 iterations of TweetNaCl - salsa20 stream 4MB file took 2.411 sec(s)

AOT
500 iterations of TweetNaCl - scalarmult_base took 3.847 sec(s)
500 iterations of TweetNaCl - hsalsa20 took 3.848 sec(s)
10 iterations of TweetNaCl - salsa20 stream 4MB file took 6.274 sec(s)

Javascript
500 iterations of TweetNaCl - scalarmult_base took 2.272 sec(s)
500 iterations of TweetNaCl - hsalsa20 took 2.377 sec(s)
10 iterations of TweetNaCl - salsa20 stream 4MB file took 8.654 sec(s)
*/

void _printMessage(String alg, int iter, double sec) =>
    print('$iter iterations of $alg took $sec sec(s)');
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

  final sw = Stopwatch();

  var i = 0;
  final iteration = 500;

  // Scalarmult
  final pk = Uint8List(TweetNaCl.publicKeyLength);

  sw.start();
  for (i = 0; i < iteration; i++) {
    TweetNaCl.crypto_scalarmult_base(pk, hex.decode(aliceSk));
  }
  sw.stop();
  _printMessage(
      'TweetNaCl - scalarmult_base', iteration, sw.elapsedMilliseconds / 1000);
  final pkHex = hex.encode(pk);
  assert(pkHex == alicePk);

  // hsalsa
  final _1k = Uint8List(TweetNaCl.secretKeyLength);
  final decodedShared = hex.decode(sharedSecret);
  final decodedC = hex.decode(c);

  sw.start();
  for (i = 0; i < iteration; i++) {
    TweetNaCl.crypto_core_hsalsa20(_1k, zero, decodedShared, decodedC);
  }
  sw.stop();
  final encoded1K = hex.encode(_1k);
  assert(encoded1K == firstKey);
  _printMessage(
      'TweetNaCl - hsalsa20', iteration, sw.elapsedMilliseconds / 1000);

  // salsa
  final outLen = 4194304;
  final out = Uint8List(outLen);
  final hashOut = Uint8List(64);

  sw.start();
  for (i = 0; i < 10; i++) {
    TweetNaCl.crypto_stream_salsa20(
        out, 0, outLen, hex.decode(nonce), hex.decode(firstKey));
  }
  sw.stop();

  _printMessage(
      'TweetNaCl - salsa20 stream 4MB file', 10, sw.elapsedMilliseconds / 1000);
}
