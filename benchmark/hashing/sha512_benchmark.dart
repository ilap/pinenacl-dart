import 'dart:typed_data';

import 'package:pinenacl/hashing.dart';

/*
DartVM doc: https://mrale.ph/dartvm/

Original: JiT on macOS Big Sur
262144 iterations of SHA-512 took 5.455 sec(s)
262144 iterations of SHA-512 took 5.486 sec(s)
262144 iterations of SHA-512 took 5.464 sec(s)
262144 iterations of SHA-512 took 5.347 sec(s)
262144 iterations of SHA-512 took 2.57 sec(s)  // After refactored tweetnacl a littlebit. 18/01/2021


Original: AoT on macOS Big Sur
262144 iterations of SHA-512 took 21.078 sec(s)
262144 iterations of SHA-512 took 21.035 sec(s)
262144 iterations of SHA-512 took 20.911 sec(s)
262144 iterations of SHA-512 took 21.060 sec(s)
262144 iterations of SHA-512 took 4.54 sec(s) // After refactored tweetnacl a littlebit. 18/01/2021

*/

void _printMessage(String alg, int iter, double sec) =>
    print('$iter iterations of $alg took $sec sec(s)');
void main() {
  final sw = Stopwatch();
  final message = Uint8List.fromList(
      'People see what they want to see, and bla bla blad'.codeUnits);
  var i = 0;
  final iteration = 262144;

  sw.start();
  for (i = 0; i < iteration; i++) Hash.sha512(message);
  sw.stop();
  _printMessage('SHA-512', iteration, sw.elapsedMilliseconds / 1000);
}
