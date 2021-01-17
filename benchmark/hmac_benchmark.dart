import 'dart:typed_data';
import 'package:pinenacl/key_derivation.dart';
import 'package:pinenacl/hashing.dart';
import 'package:pinenacl/tweetnacl.dart';

void pbkdf2(Uint8List message, Uint8List salt) {}

void _printMessage(String alg, int iter, double sec) =>
    print('$iter iterations of $alg took $sec sec(s)');

void main() {
  final sw = Stopwatch();
  final message = Uint8List.fromList(
      'People see what they want to see, and bla bla blad'.codeUnits);
  var i = 0;
  final iteration = 10000;
  final salt = TweetNaCl.randombytes(32);

  var alg = 'BPKDF-HMAC-SHA256 4096 96';

  sw.start();
  PBKDF2.hmac_sha256(message, salt, 4096, 96);
  sw.stop();
  _printMessage(alg, iteration, sw.elapsedMilliseconds / 1000);

  alg = 'BPKDF-HMAC-SHA512 4096 96';

  sw.start();
  PBKDF2.hmac_sha512(message, salt, 4096, 96);
  sw.stop();
  _printMessage(alg, iteration, sw.elapsedMilliseconds / 1000);
}
