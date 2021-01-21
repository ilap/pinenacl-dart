import 'digests/sha256_benchmark.dart' as sha256_benchmark;
import 'digests/sha512_benchmark.dart' as sha512_benchmark;
import 'digests/blake2b_benchmark.dart' as blake2b_benchmark;
import 'tweetnacl/ed25519_benchmark.dart' as ed25519_benchmark;
import 'tweetnacl/authenticated_encryption_benchmark.dart'
    as authenticated_encryption_benchmark;
import 'tweetnacl/tweetnacl_benchmark.dart' as tweetnacl_benchmark;

void main() {
  // Digest algorythms
  blake2b_benchmark.main();
  sha256_benchmark.main();
  sha512_benchmark.main();

  // Ed25519
  ed25519_benchmark.main();

  // HMAC
  authenticated_encryption_benchmark.main();

  // TweetNaCl and TweeetNaClExt
  tweetnacl_benchmark.main();
}
