import 'rate_benchmark.dart';

class TweetNaClBenchmark extends RateBenchmark {
  TweetNaClBenchmark(this._tweetNaCl, String funcName, this._dataLength)
      : super('TweetNaCl | $funcName');

  final Function _tweetNaCl;
  final int _dataLength;

  @override
  void setup() {}

  @override
  void run() {
    _tweetNaCl();
    addSample(_dataLength);
  }
}
