part of '../../encoding.dart';

const _alphabet = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
final _alphabetMap =
    _alphabet.codeUnits.asMap().map((idx, value) => MapEntry(value, idx));

class Base32Encoder implements Encoder {
  const Base32Encoder._singleton();
  static const Base32Encoder instance = Base32Encoder._singleton();

  @override
  String encode(List<int> data) {
    final result =
        _convertBits(data, 8, 5, true).fold<String>('', (prev, item) {
      prev += _alphabet[item];
      return prev;
    });
    return result;
  }

  @override
  Uint8List decode(String data) {
    final result = _convertBits(
        data.codeUnits.fold([], (prev, item) {
          return prev..add(_alphabetMap[item]!);
        }),
        5,
        8,
        false);
    return Uint8List.fromList(result);
  }

  static List<int> _convertBits(List<int> data, int from, int to, bool pad) {
    var acc = 0;
    var bits = 0;
    var result = <int>[];
    var maxv = (1 << to) - 1;

    for (var v in data) {
      if (v < 0 || (v >> from) != 0) {
        throw Exception('Bit conversion error - Invalid input value');
      }
      acc = (acc << from) | v;
      bits += from;
      while (bits >= to) {
        bits -= to;
        result.add((acc >> bits) & maxv);
      }
    }

    if (pad) {
      if (bits > 0) {
        result.add((acc << (to - bits)) & maxv);
      }
    } else if (bits >= from) {
      throw Exception('Bit conversion error - Illegal zero padding');
    } else if (((acc << (to - bits)) & maxv) != 0) {
      throw Exception('Bit conversion error - non zero');
    }

    return result;
  }
}
