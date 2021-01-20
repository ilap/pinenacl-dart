import 'dart:typed_data';

import 'rate_benchmark.dart';

typedef DigestAlg = Uint8List Function(dynamic message);

class DigestBenchmark extends RateBenchmark {
  DigestBenchmark(String digestName, DigestAlg digest,
      [int dataLength = 1024 * 1024])
      : _digest = digest,
        _data = Uint8List(dataLength),
        super('Digest | $digestName');

  final Uint8List _data;
  final DigestAlg _digest;

  @override
  void setup() {}

  @override
  void run() {
    _digest(_data);
    addSample(_data.length);
  }
}
