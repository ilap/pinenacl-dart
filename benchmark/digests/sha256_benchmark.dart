import 'package:pinenacl/digests.dart';

import '../helpers/digest_benchmark.dart';

void main() {
  DigestBenchmark('SHA-256', Hash.sha256).report();
}
