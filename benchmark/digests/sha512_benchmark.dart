import 'package:pinenacl/digests.dart';

import '../helpers/digest_benchmark.dart';

void main() {
  DigestBenchmark('SHA-512', Hash.sha512).report();
}
