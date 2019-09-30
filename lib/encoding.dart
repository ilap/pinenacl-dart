import 'package:pinenacl/api.dart';
import 'package:convert/convert.dart';

import 'package:bech32/bech32.dart' hide Bech32Encoder;

const hexEncoder = HexEncoder();
const base32Encoder = Base32Encoder();

abstract class Encoder {
  String encode(ByteList data);
  ByteList decode(String data);
}

class HexEncoder implements Encoder {
  const HexEncoder();

  @override
  String encode(ByteList data) {
    return hex.encode(data);
  }

  @override
  ByteList decode(String data) {
    return ByteList(hex.decode(data));
  }
}

class Bech32Encoder implements Encoder {
  const Bech32Encoder({this.hrp});
  final String hrp;

  @override
  String encode(ByteList data) {
    var be = Base32Encoder._convertBits(data, 8, 5, true);
    return Bech32Codec().encode(Bech32(hrp, be));
  }

  @override
  ByteList decode(String data) {
    final be32 = Bech32Codec().decode(data);
    if (be32.hrp != this.hrp) {
      throw Exception('Invalid `hrp`. Expected $hrp got ${be32.hrp}');
    }
    return ByteList(Base32Encoder._convertBits(be32.data, 5, 8, false));
  }
}

const _alphabet = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
final _alphabetMap =
    _alphabet.codeUnits.asMap().map((idx, value) => MapEntry(value, idx));

class Base32Encoder implements Encoder {
  const Base32Encoder();

  @override
  String encode(ByteList data) {
    var result = _convertBits(data, 8, 5, true).fold('', (prev, item) {
      prev += _alphabet[item];
      return prev;
    });
    return result;
  }

  @override
  ByteList decode(String data) {
    final result = _convertBits(
        data.codeUnits.fold([], (prev, item) {
          return prev..add(_alphabetMap[item]);
        }),
        5,
        8,
        false);
    return ByteList(result);
  }

  static List<int> _convertBits(List<int> data, int from, int to, bool pad) {
    var acc = 0;
    var bits = 0;
    List<int> result = [];
    var maxv = (1 << to) - 1;

    data.forEach((v) {
      if (v < 0 || (v >> from) != 0) {
        throw Exception('Bit conversion error - Invalid input value');
      }
      acc = (acc << from) | v;
      bits += from;
      while (bits >= to) {
        bits -= to;
        result.add((acc >> bits) & maxv);
      }
    });

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

abstract class Encodable<T extends AsymmetricKey> {
  //static const Encoder encoder = hexEncoder;
  Encoder get encoder;
  String encode([dynamic enc]) {
    enc = enc ?? encoder;
    return enc.encode(this);
  }
}
