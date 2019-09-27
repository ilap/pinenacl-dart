import 'dart:typed_data';
import 'package:pinenacl/api.dart';
import 'package:convert/convert.dart';

import 'package:bech32/bech32.dart' hide Bech32Encoder;

abstract class EncoderBase {
  String encode(ByteList data);
  ByteList decode(String data);
}

class HexEncoder implements EncoderBase {
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

class Bech32Encoder implements EncoderBase {
  const Bech32Encoder({this.hrp});
  final String hrp;

  @override
  String encode(ByteList data) {
    var b = Base32Encoder._convertBits(data, 8, 5, true);
    return Bech32Codec().encode(Bech32(hrp, b));
  }

  @override
  ByteList decode(String data) {
    final be32 = Bech32Codec().decode(data);
    return ByteList(be32.data);
  }
}

class Base32Encoder implements EncoderBase {
  const Base32Encoder();

  @override
  String encode(ByteList data) {
    var result = _convertBits(data, 8, 5, true).fold('', (prev, item) {
      prev += alphabet[item];
      return prev;
    });
    return result;
  }

  @override
  ByteList decode(String data) {
    final result = _convertBits(data.codeUnits, 8, 5, false);
    return ByteList(result);
  }

  static const alphabet = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

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

abstract class Decodable {
  Decodable();
  factory Decodable.decode(String data,
      [EncoderBase decoder = const HexEncoder()]) {

    throw Exception('Decodable - Unreachable');
  }
}

abstract class Encodable {
  String encode([dynamic encoder]) {
    if (encoder == null) {
      encoder = HexEncoder();
    }
    return encoder.encode(this);
  }
}
