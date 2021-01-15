import 'package:benchmark_harness/benchmark_harness.dart';

//import 'package:pinenacl/encoding.dart';
import 'package:pinenacl/ed25519.dart';

void main() {
  // Run TemplateBenchmark
  DigitalSignatures.main();
}

// Create a new benchmark by extending BenchmarkBase
class DigitalSignatures extends BenchmarkBase {
  DigitalSignatures() : super('DigitalSignatures #1 - Sign and Verify');
  static const hex = HexCoder.instance;

  static const priv =
      '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c';
  static const pub =
      '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c';
  static const mesg = '72';
  static const sigd =
      '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c0072';

  final messageBytes = hex.decode(mesg);
  final signatureBytes = hex.decode(sigd);

  // Seed is the first 32 bytes of an 64-byte-long ed25519 private/secret key.
  final signingKey = SigningKey(seed: hex.decode(priv).sublist(0, 32));
  final verifyKey = VerifyKey(hex.decode(pub));
  static void main() {
    DigitalSignatures().report();
  }

  // Not measured setup code executed prior to the benchmark runs.
  @override
  void setup() {}

  // Not measured teardown code executed after the benchmark runs.
  @override
  void teardown() {}

  // Run /w or without --checked
  // pub run benchmark/all_benchmark.dart
  @override
  void run() {
    final signedMessage = signingKey.sign(messageBytes);
    verifyKey.verifySignedMessage(signedMessage: signedMessage);
  }
}
