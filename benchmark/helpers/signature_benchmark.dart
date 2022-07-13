import 'package:pinenacl/ed25519.dart';
import 'package:pinenacl/src/tweetnacl/tweetnacl.dart';

import 'rate_benchmark.dart';

class SignatureBenchmark extends RateBenchmark {
  SignatureBenchmark(String signerName, bool forSigning,
      [int dataLength = 1024 * 1024])
      : _forSigning = forSigning,
        _data = PineNaClUtils.randombytes(dataLength),
        super('Signatures (${dataLength / 1024 / 1024 }MB) | $signerName - ${forSigning ? 'sign' : 'verify'}');

  final Uint8List _data;
  final bool _forSigning;
  late final SigningKey _signer;
  SignedMessage? _signature;

  @override
  void setup() {
    _signer = SigningKey.generate();
    _signature = _signer.sign(_data);
  }

  @override
  void run() {
    if (_forSigning) {
      _signer.sign(_data);
    } else if (_signature != null) {
      _signer.verifyKey.verifySignedMessage(signedMessage: _signature!);
    }
    addSample(_data.length);
  }
}
