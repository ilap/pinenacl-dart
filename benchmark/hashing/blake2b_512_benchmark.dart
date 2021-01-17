import 'dart:typed_data';

import 'package:pinenacl/hashing.dart';

import 'package:pinenacl/hashing.dart';

/*
DartVM doc: https://mrale.ph/dartvm/
Original: JiT on macOS Big Sur
262144 iterations of BLAKE2B_512 took 1.008 sec(s)
262144 iterations of BLAKE2B_512 took 1.008 sec(s)
262144 iterations of BLAKE2B_512 took 1.048 sec(s)
262144 iterations of BLAKE2B_512 took 1.024 sec(s)

Original: AoT on macOS Big Sur
262144 iterations of BLAKE2B_512 took 0.969 sec(s)
262144 iterations of BLAKE2B_512 took 0.984 sec(s)
262144 iterations of BLAKE2B_512 took 0.973 sec(s)
262144 iterations of BLAKE2B_512 took 0.993 sec(s)
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
  for (i = 0; i < iteration; i++) Hash.blake2b(message);
  sw.stop();
  _printMessage('BLAKE2B_512', iteration, sw.elapsedMilliseconds / 1000);
}
