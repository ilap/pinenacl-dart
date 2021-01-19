import 'dart:typed_data';

import 'package:pinenacl/ed25519.dart';

/*
Original JIT - order is important for stopwatch.
2000 iterations of ED25519 Signing took 3.955 sec(s)
2000 iterations of ED25519 Verifying took 11.645 sec(s)
500 iterations of ED25519 Signing took 1.074 sec(s)
500 iterations of ED25519 Verifying took 3.165 sec(s)

Original AOT
2000 iterations of ED25519 Signing took 40.471 sec(s)
2000 iterations of ED25519 Verifying took 120.152 sec(s)
500 iterations of ED25519 Signing took 10.407 sec(s)
500 iterations of ED25519 Verifying took 31.304 sec(s)
*/

void _printMessage(String alg, int iter, double sec) =>
    print('$iter iterations of $alg took $sec sec(s)');
void main() {
  final sw = Stopwatch();

  final signingKey = SigningKey.generate();
  final verifyKey = signingKey.verifyKey;

  final message =
      Uint8List.fromList('People see the things they want to see...'.codeUnits);
  var i = 0;
  final iteration = 500;

  late SignedMessage signed;
  sw.start();
  for (i = 0; i < iteration; i++) {
    signed = signingKey.sign(message);
  }
  sw.stop();
  _printMessage('ED25519 Signing', iteration, sw.elapsedMilliseconds / 1000);

  sw.start();
  for (i = 0; i < iteration; i++) {
    verifyKey.verifySignedMessage(signedMessage: signed);
  }
  sw.stop();
  _printMessage('ED25519 Verifying', iteration, sw.elapsedMilliseconds / 1000);
}
