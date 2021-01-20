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
262144 iterations of SHA-256 took 0.483 sec(s)
262144 iterations of BLAKE2B took 1.72 sec(s)
262144 iterations of SHA-512 took 4.443 sec(s)

Original AOT
100000 of SHA-256 took: 2.511
100000 of SHA-512 took: 10.399
100000 of BLAKE2B took: 10.763
100000 iterations of SHA-256 took 0.716 sec(s) // after tweaked tweetnacl a littlebit. 18/01/2021
100000 iterations of BLAKE2B took 1.079 sec(s) // after tweaked tweetnacl a littlebit. 18/01/2021
100000 iterations of SHA-512 took 2.842 sec(s)  // after tweaked tweetnacl a littlebit. 18/01/2021
262144 iterations of SHA-256 took 2.874 sec(s)
262144 iterations of BLAKE2B took 4.032 sec(s)
262144 iterations of SHA-512 took 8.395 sec(s)



Javascript on 19/01/2021
262144 iterations of SHA-256 took 1.054 sec(s)
262144 iterations of BLAKE2B took 2.872 sec(s)
262144 iterations of SHA-512 took 21.278 sec(s)
262144 iterations of SHA-256 took 1.133 sec(s)
262144 iterations of BLAKE2B took 3.021 sec(s)
262144 iterations of SHA-512 took 30.663 sec(s)



Wind ia32
262144 iterations of SHA-256 took 1.12 sec(s)
262144 iterations of BLAKE2B took 5.485 sec(s)
262144 iterations of SHA-512 took 378.649 sec(s)
262144 iterations of SHA-256 took 1.166 sec(s)
262144 iterations of BLAKE2B took 5.592 sec(s)
262144 iterations of SHA-512 took 370.525 sec(s)

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

  sw.start();
  for (i = 0; i < iteration; i++) {
    Hash.blake2b(message);
  }
  sw.stop();
  _printMessage('BLAKE2B', iteration, sw.elapsedMilliseconds / 1000);

  sw.start();
  for (i = 0; i < iteration; i++) {
    Hash.sha512(message);
  }
  sw.stop();
  _printMessage('SHA-512', iteration, sw.elapsedMilliseconds / 1000);
}
