import 'package:pinenacl/digests.dart';

import '../helpers/digest_benchmark.dart';

void main() {
  DigestBenchmark('BLAKE2B', Hash.blake2b).report();
}
