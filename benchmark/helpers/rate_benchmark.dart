// See file LICENSE for more information.

library pointycastle.benchmark.benchmark.rate_benchmark;

import 'package:benchmark_harness/benchmark_harness.dart';

abstract class RateBenchmark extends BenchmarkBase {
  RateBenchmark(String name) : super(name, emitter: RateEmitter()) {
    (emitter as RateEmitter).benchmark = this;
  }

  // ignore: constant_identifier_names
  static const _RUN_LENGTH_MILLIS = 5000;

  int _totalData = 0;
  int _iterations = 0;

  @override
  ScoreEmitter get emitter => super.emitter;

  void addSample(int processedData) {
    _totalData += processedData;
  }

  @override
  void exercise() {
    _totalData = 0;
    _iterations = 0;

    var watch = Stopwatch()..start();
    while (watch.elapsedMilliseconds < _RUN_LENGTH_MILLIS) {
      run();
      _iterations++;
    }
  }
}

class RateEmitter implements ScoreEmitter {
  late RateBenchmark benchmark;

  int get totalData => benchmark._totalData;
  int get iterations => benchmark._iterations;

  @override
  void emit(String testName, double value) {
    var ms = value / 1000;
    var s = ms / 1000;
    print('| $testName | '
        '${_formatDataLength(totalData / s)}/s | '
        '$iterations iterations | '
        '${ms.toInt()} ms | '
        '${_formatDataLength(totalData)} |');
  }

  String _formatDataLength(num dataLen) {
    if (dataLen < 1024) {
      return '${dataLen.toStringAsFixed(2)} B';
    } else if (dataLen < (1024 * 1024)) {
      return '${(dataLen / 1024).toStringAsFixed(2)} KB';
    } else if (dataLen < (1024 * 1024 * 1024)) {
      return '${(dataLen / (1024 * 1024)).toStringAsFixed(2)} MB';
    } else {
      return '${(dataLen / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
    }
  }
}
