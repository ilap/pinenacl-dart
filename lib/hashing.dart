library pinenacl.api.hash;

import 'dart:core';
import 'dart:convert';
import 'dart:typed_data';

import 'package:pinenacl/api.dart';

///  Hash algorithm, Implements SHA-512.
/// Cryptographic secure hash functions are irreversible transforms of input data to a fixed length digest.
/// The standard properties of a cryptographic hash make these functions useful both for standalone usage as data integrity checkers, as well as black-box building blocks of other kind of algorithms and data structures.
///
/// All of the hash functions exposed in `pinenacl.hash` can be used as data integrity checkers.
class Hash {
  //Length of hash in bytes.
  static final int hashLength = 64;

  ///  Returns SHA-256 hash of the message.
  static Uint8List sha256(dynamic message) {
    if (message is String) {
      message = Uint8List.fromList(utf8.encode(message));
    } else if (message is! Uint8List) {
      throw Exception('The message must be either of string or Uint8List');
    }
    Uint8List out = Uint8List(32);
    Sha256.crypto_hash_sha256(out, message);
    return out;
  }

  ///  Returns SHA-512 hash of the message.
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

  /// Returns a Blake2b hash of the message.
  static Uint8List blake2b(dynamic message,
      {int digestSize,
      Uint8List key,
      Uint8List salt,
      Uint8List personalisation}) {
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
