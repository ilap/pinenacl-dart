import 'dart:typed_data';

import 'package:pinenacl/hashing.dart';

/*
Original JIT - order is important for stopwatch.
100000 of SHA-256 took: 0.228
100000 of BLAKE2B took: 0.626
100000 of SHA-512 took: 2.775

Original AOT
100000 of SHA-256 took: 2.511
100000 of SHA-512 took: 10.399
100000 of BLAKE2B took: 10.763
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
