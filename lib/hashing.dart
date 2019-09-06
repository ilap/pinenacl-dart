import "dart:core";
import "dart:convert";
import 'dart:typed_data';

import 'package:pinenacl/src/crypto/tweetnacl.dart';
import 'package:pinenacl/src/crypto/blake2b.dart';

///
///  Hash algorithm, Implements SHA-512.
///
class Hash {
  //Length of hash in bytes.
  static final int hashLength = 64;

  ///
  ///  Returns SHA-512 hash of the message.
  //
  static Uint8List sha512(dynamic message) {
    if (message is String) {
      message = Uint8List.fromList(utf8.encode(message));
    } else if (message is! Uint8List) {
      throw Exception('The message must be either of string or Uint8List');
    }
    Uint8List out = Uint8List(hashLength);
    TweetNaCl.crypto_hash(out, message);
    return out;
  }


  ///Returns a Blake2b hash of the message.
  static Uint8List blake2b(dynamic message, {int digestSize, Uint8List key, Uint8List salt, Uint8List personalisation }) {
    if (message is String) {
      message = Uint8List.fromList(utf8.encode(message));
    } else if (message is! Uint8List) {
      throw Exception('The message must be either of string or Uint8List');
    }

    return Blake2b.digest(message, 
    digestSize: digestSize ?? hashLength, 
    key: key, 
    salt: salt, 
    personal: personalisation);
  }
}
