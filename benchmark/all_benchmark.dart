import 'digests/sha256_benchmark.dart' as sha256_benchmark;
import 'digests/sha512_benchmark.dart' as sha512_benchmark;
import 'digests/blake2b_benchmark.dart' as blake2b_benchmark;

void main() {
  // Digest algorythms
  blake2b_benchmark.main();
  sha256_benchmark.main();
  sha512_benchmark.main();
}
