library pinenacl.utils;

import 'dart:typed_data';

import 'api.dart';

/// Utils class, provides secure randomnes and basic
/// list functions.
//class Utils2 {
/// Add a global extension for converting List<int> to Uint8List.
extension Utils on List<int> {
  static Uint8List randombytes(int len) {
    return TweetNaCl.randombytes(len);
  }

  static void listCopy(List from, int fromLength, List to, [int toOffset = 0]) {
    for (var i = 0; i < fromLength; i++) {
      to[i + toOffset] = from[i];
    }
  }

  static void listZero(List list) {
    for (var i = 0; i < list.length; i++) {
      list[i] = 0;
    }
  }

  /// Add a global extension for converting List<int> to Uint8List.
  Uint8List toUint8List() {
    return Uint8List.fromList(this);
  }
}
