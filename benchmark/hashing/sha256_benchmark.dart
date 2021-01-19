import 'dart:typed_data';

import 'package:pinenacl/hashing.dart';

/*
DartVM doc: https://mrale.ph/dartvm/

JiT on macOS Big Sur
Original : 262144 iterations of SHA-256 took 3.118 sec(s)
Optimized: 262144 iterations of SHA-256 took 0.494 sec(s)

AoT on macOS Big Sur
Original : 262144 iterations of SHA-256 took 6.086 sec(s)
Optimised: 262144 iterations of SHA-256 took 1.721 sec(s)

Javascript
262144 iterations of SHA-256 took 1.078 sec(s) // 19/01/2021

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
  for (i = 0; i < iteration; i++) {
    Hash.sha256(message);
  }
  sw.stop();
  _printMessage('SHA-256', iteration, sw.elapsedMilliseconds / 1000);
}
