import 'dart:typed_data';

import 'package:pinenacl/api.dart';
import 'package:pinenacl/tweetnacl.dart';

void main() {
  final key = List<int>.generate(20, (index) => 0xb).toUint8List();
  final data = Uint8List.fromList('Hi There'.codeUnits);
  final hex = HexCoder.instance;
  // Test case 1 fro https://www.rfc-editor.org/rfc/rfc4231.txt

  /*final hmac_sha_224 =
      hex.decode('896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22');
  final hmac_sha_256 = hex.decode(
      'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
  final hmac_sha_384 = hex.decode(
      'afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6');
  final hmac_sha_512 = hex.decode(
      '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854');
*/

  //final out224 = Uint8List(28);
  final out256 = ByteList(Uint8List(32));
  //final out384 = Uint8List(48);
  final out512 = ByteList(Uint8List(64));

  TweetNaClExt.crypto_auth_hmacsha512(out512.asTypedList, data, key);
  TweetNaClExt.crypto_auth_hmacsha256(out256.asTypedList, data, key);

  print(hex.encode(out512));
  print(hex.encode(out256));
}
