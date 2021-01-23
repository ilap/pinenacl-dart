import 'package:pinenacl/x25519.dart';

import 'rate_benchmark.dart';

class EncryptionBenchmark extends RateBenchmark {
  EncryptionBenchmark(this._cryptor, String cryptorName, bool forEncryption,
      [int dataLength = 1024 * 1024])
      : _forEncryption = forEncryption,
        _data = Uint8List(dataLength),
        super(
            'Authenticated Encryption | $cryptorName - ${forEncryption ? 'encrypt' : 'decrypt'}');

  final Uint8List _data;
  final bool _forEncryption;
  final BoxBase _cryptor;

  EncryptedMessage? encrypted;

  @override
  void setup() {
    encrypted = _forEncryption ? null : _cryptor.encrypt(_data);
  }

  @override
  void run() {
    if (_forEncryption) {
      _cryptor.encrypt(_data);
    } else {
      _cryptor.decrypt(encrypted!);
    }
    addSample(_data.length);
  }
}
