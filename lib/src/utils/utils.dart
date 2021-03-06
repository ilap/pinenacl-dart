library pinenacl.utils;

import 'dart:typed_data';

import 'package:pinenacl/src/tweetnacl/tweetnacl.dart';

/// Utils class, provides basic list functions.
class PineNaClUtils {
  static Uint8List randombytes(int len) {
    return TweetNaCl.randombytes(len);
  }

  static void listCopy(List from, int fromLength, List to, [int toOffset = 0]) {
    for (var i = 0; i < fromLength; i++) {
      to[i + toOffset] = from[i];
    }
  }

  static void listZero(List<int> list, [int l = -1]) {
    final length = l >= 0 ? l : list.length;
    for (var i = 0; i < length; i++) {
      list[i] = 0;
    }
  }
}
