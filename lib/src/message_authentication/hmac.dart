import 'dart:typed_data';

import 'package:pinenacl/src/message_authentication/hmac_sha512.dart';

class Hmac {
  static void sha512(Uint8List out, Uint8List text, Uint8List k) {
    HmacSha512.mac(out, text, k);
  }
}
