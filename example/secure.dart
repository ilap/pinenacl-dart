import 'dart:math';
import 'dart:typed_data';

/// Add to js
/// var self = global;
/// var crypto = require('crypto');
/// self.crypto = crypto;
/// self.crypto.getRandomBytes = crypto.randomBytes;
/// self.crypto.getRandomValues = crypto.randomBytes;
///
void main() {
  print(1 << 32);
  print(0x100000000);
  print('${randombytes(10)}');
}

final _krandom = Random.secure();

Uint8List _randombytes_array(Uint8List x) {
  var rnd = 0;

  for (var i = 0; i < x.length; i++) {
    var iter = i % 4;

    if (iter == 0) {
      // rnd is always a 32-bit positive integer.
      rnd = _krandom.nextInt(0x100000000);
    }

    x[i] = (rnd >> (8 * iter)) & 0xFF;
  }

  return x;
}

Uint8List randombytes(int len) {
  return _randombytes_array(Uint8List(len));
}
