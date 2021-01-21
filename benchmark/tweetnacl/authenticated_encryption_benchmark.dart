import 'package:pinenacl/x25519.dart';

import '../helpers/authenticated_encryption_benchmark.dart';

void main() {
  EncryptionBenchmark(
          SecretBox(PineNaClUtils.randombytes(32)), 'SecretBox', true)
      .report();
  EncryptionBenchmark(
          SecretBox(PineNaClUtils.randombytes(32)), 'SecretBox', false)
      .report();

  // FIXME: decode should be used pk string only such as x25519_pk1.....
  EncryptionBenchmark(Box.decode(PineNaClUtils.randombytes(32)), 'Box', true)
      .report();
  EncryptionBenchmark(Box.decode(PineNaClUtils.randombytes(32)), 'Box', false)
      .report();
}
