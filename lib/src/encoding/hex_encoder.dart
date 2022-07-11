part of pinenacl.encoding;

class HexCoder implements Encoder {
  const HexCoder._singleton();
  static const HexCoder instance = HexCoder._singleton();

  static const _alphabet = '0123456789abcdef';
  static const _hexMap = <String, int>{
    '0': 0x0, '1': 0x1, '2': 0x2, '3': 0x3, // 4-5
    '4': 0x4, '5': 0x5, '6': 0x6, '7': 0x7,
    '8': 0x8, '9': 0x9, 'a': 0xa, 'b': 0xb,
    'c': 0xc, 'd': 0xd, 'e': 0xe, 'f': 0xf,
    'A': 0xa, 'B': 0xb, 'C': 0xc, 'D': 0xd,
    'E': 0xe, 'F': 0xf,
  };

  static List<int> _decode(String hexString) {
    if (hexString.length % 2 != 0) {
      throw Exception(
          'Invalid `length`. Expected even number got `${hexString.length}`');
    }

    var startsWithHexStart = hexString.startsWith('0x');
    if (startsWithHexStart && hexString.length == 2) {
      throw Exception('There is no any character in the hexadecimal string');
    }

    final startIndex = startsWithHexStart ? 2 : 0;
    var result = List<int>.filled((hexString.length - startIndex) ~/ 2, 0);

    for (var x = 0, i = startIndex; i < hexString.length; i += 2, x++) {
      final left = _hexMap[hexString[i]] ?? -1;
      final right = _hexMap[hexString[i + 1]] ?? -1;

      if (left < 0 || right < 0) {
        final invalidChar = left < 0 ? hexString[i] : hexString[i + 1];
        throw Exception('The `$invalidChar` character is undefined in hex');
      }

      result[x] = (left << 4) | right;
    }

    return result;
  }

  static String _encode(List<int> hexArray, {bool withHexString = false}) {
    if (hexArray.isEmpty) {
      return '';
    }

    var result = withHexString ? '0x' : '';

    for (var element in hexArray) {
      result += _alphabet[(element & 0xff) >> 4] + _alphabet[element & 0x0f];
    }

    return result;
  }

  @override
  String encode(List<int> data) {
    return _encode(data);
  }

  @override
  Uint8List decode(String data) {
    return Uint8List.fromList(_decode(data));
  }
}
