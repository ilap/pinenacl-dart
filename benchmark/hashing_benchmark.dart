import 'dart:typed_data';

import 'package:pinenacl/hashing.dart';

/*
Original JIT - order is important for stopwatch.
100000 of SHA-256 took: 0.228
100000 of BLAKE2B took: 0.626
100000 of SHA-512 took: 2.775
100000 iterations of SHA-256 took 0.23 sec(s)  // after tweaked tweetnacl a littlebit. 18/01/2021
100000 iterations of BLAKE2B took 0.623 sec(s) // after tweaked tweetnacl a littlebit. 18/01/2021
100000 iterations of SHA-512 took 1.686 sec(s) // after tweaked tweetnacl a littlebit. 18/01/2021

Original AOT
100000 of SHA-256 took: 2.511
100000 of SHA-512 took: 10.399
100000 of BLAKE2B took: 10.763
100000 iterations of SHA-256 took 0.716 sec(s) // after tweaked tweetnacl a littlebit. 18/01/2021
100000 iterations of BLAKE2B took 1.079 sec(s) // after tweaked tweetnacl a littlebit. 18/01/2021
100000 iterations of SHA-512 took 2.842 sec(s)  // after tweaked tweetnacl a littlebit. 18/01/2021

*/

void _printMessage(String alg, int iter, double sec) =>
    print('$iter iterations of $alg took $sec sec(s)');
void main() {
  final sw = Stopwatch();
  final message = Uint8List.fromList(
      'People see what they want to see, and bla bla blad'.codeUnits);
  var i = 0;
  final iteration = 100000;

  sw.start();
  for (i = 0; i < iteration; i++) Hash.sha256(message);
  sw.stop();
  _printMessage('SHA-256', iteration, sw.elapsedMilliseconds / 1000);

  sw.start();
  for (i = 0; i < iteration; i++) Hash.blake2b(message);
  sw.stop();
  _printMessage('BLAKE2B', iteration, sw.elapsedMilliseconds / 1000);
  // FIXME: Implement similar API

  sw.start();
  for (i = 0; i < iteration; i++) Hash.sha512(message);
  sw.stop();
  _printMessage('SHA-512', iteration, sw.elapsedMilliseconds / 1000);
}
