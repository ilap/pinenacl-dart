import '../helpers/signature_benchmark.dart';

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

Javascript
500 iterations of ED25519 Signing took 6.009 sec(s) // 19/01/2021
500 iterations of ED25519 Verifying took 17.237 sec(s) // 19/01/2021
*/

void main() {
  SignatureBenchmark('Ed25519', true).report();
  SignatureBenchmark('Ed25519', false).report();
}
