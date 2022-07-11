part of pinenacl.encoding;

class Bech32Coder implements Encoder {
  const Bech32Coder({required this.hrp});
  final String hrp;

  static const maxHrpLength = 83;
  static const checksumLength = 6;
  // 100 character long i.e. 100 * 8 / 5
  static const maxLength = maxHrpLength + 160 + checksumLength;

  @override
  String encode(List<int> data) {
    var be = Base32Encoder._convertBits(data, 8, 5, true);
    return Bech32Codec().encode(Bech32(hrp, be), maxLength);
  }

  @override
  Uint8List decode(String data) {
    final be32 = Bech32Codec().decode(data, maxLength);
    if (be32.hrp != hrp) {
      throw Exception('Invalid `hrp`. Expected $hrp got ${be32.hrp}');
    }
    return Uint8List.fromList(
        Base32Encoder._convertBits(be32.data, 5, 8, false));
  }
}

// ignore: slash_for_doc_comments
/**
 * The below part is copied from `bech32` dart package under the MIT license for
 * `pre-release` null safety migration of this package.
 * 
 * Copyright 2020 Harm Aarts
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to 
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is 
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in 
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY,  * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
class Bech32 {
  Bech32(this.hrp, this.data);

  final String hrp;
  final List<int> data;
}

const Bech32Codec bech32 = Bech32Codec();

class Bech32Codec extends Codec<Bech32, String> {
  const Bech32Codec();

  @override
  Bech32Decoder get decoder => Bech32Decoder();
  @override
  Bech32Encoder get encoder => Bech32Encoder();

  @override
  String encode(Bech32 input,
      [int maxLength = Bech32Validations.maxInputLength]) {
    return Bech32Encoder().convert(input, maxLength);
  }

  @override
  Bech32 decode(String encoded,
      [int maxLength = Bech32Validations.maxInputLength]) {
    return Bech32Decoder().convert(encoded, maxLength);
  }
}

// This class converts a Bech32 class instance to a String.
class Bech32Encoder extends Converter<Bech32, String> with Bech32Validations {
  @override
  String convert(Bech32 input,
      [int maxLength = Bech32Validations.maxInputLength]) {
    var hrp = input.hrp;
    var data = input.data;

    if (hrp.length +
            data.length +
            separator.length +
            Bech32Validations.checksumLength >
        maxLength) {
      throw TooLong(
          hrp.length + data.length + 1 + Bech32Validations.checksumLength);
    }

    if (hrp.isEmpty) {
      throw TooShortHrp();
    }

    if (hasOutOfRangeHrpCharacters(hrp)) {
      throw OutOfRangeHrpCharacters(hrp);
    }

    if (isMixedCase(hrp)) {
      throw MixedCase(hrp);
    }

    hrp = hrp.toLowerCase();

    var checksummed = data + _createChecksum(hrp, data);

    if (hasOutOfBoundsChars(checksummed)) {
      // TODO this could be more informative
      throw OutOfBoundChars('<unknown>');
    }

    return hrp + separator + checksummed.map((i) => charset[i]).join();
  }
}

// This class converts a String to a Bech32 class instance.
class Bech32Decoder extends Converter<String, Bech32> with Bech32Validations {
  @override
  Bech32 convert(String input,
      [int maxLength = Bech32Validations.maxInputLength]) {
    if (input.length > maxLength) {
      throw TooLong(input.length);
    }

    if (isMixedCase(input)) {
      throw MixedCase(input);
    }

    if (hasInvalidSeparator(input)) {
      throw InvalidSeparator(input.lastIndexOf(separator));
    }

    var separatorPosition = input.lastIndexOf(separator);

    if (isChecksumTooShort(separatorPosition, input)) {
      throw TooShortChecksum();
    }

    if (isHrpTooShort(separatorPosition)) {
      throw TooShortHrp();
    }

    input = input.toLowerCase();

    var hrp = input.substring(0, separatorPosition);
    var data = input.substring(
        separatorPosition + 1, input.length - Bech32Validations.checksumLength);
    var checksum =
        input.substring(input.length - Bech32Validations.checksumLength);

    if (hasOutOfRangeHrpCharacters(hrp)) {
      throw OutOfRangeHrpCharacters(hrp);
    }

    var dataBytes = data.split('').map((c) {
      return charset.indexOf(c);
    }).toList();

    if (hasOutOfBoundsChars(dataBytes)) {
      throw OutOfBoundChars(data[dataBytes.indexOf(-1)]);
    }

    var checksumBytes = checksum.split('').map((c) {
      return charset.indexOf(c);
    }).toList();

    if (hasOutOfBoundsChars(checksumBytes)) {
      throw OutOfBoundChars(checksum[checksumBytes.indexOf(-1)]);
    }

    if (isInvalidChecksum(hrp, dataBytes, checksumBytes)) {
      throw InvalidChecksum();
    }

    return Bech32(hrp, dataBytes);
  }
}

/// Generic validations for Bech32 standard.
class Bech32Validations {
  static const int maxInputLength = 90;
  static const checksumLength = 6;

  // From the entire input subtract the hrp length, the separator and the required checksum length
  bool isChecksumTooShort(int separatorPosition, String input) {
    return (input.length - separatorPosition - 1 - checksumLength) < 0;
  }

  bool hasOutOfBoundsChars(List<int> data) {
    return data.any((c) => c == -1);
  }

  bool isHrpTooShort(int separatorPosition) {
    return separatorPosition == 0;
  }

  bool isInvalidChecksum(String hrp, List<int> data, List<int> checksum) {
    return !_verifyChecksum(hrp, data + checksum);
  }

  bool isMixedCase(String input) {
    return input.toLowerCase() != input && input.toUpperCase() != input;
  }

  bool hasInvalidSeparator(String bech32) {
    return bech32.lastIndexOf(separator) == -1;
  }

  bool hasOutOfRangeHrpCharacters(String hrp) {
    return hrp.codeUnits.any((c) => c < 33 || c > 126);
  }
}

const String separator = '1';

const List<String> charset = [
  'q',
  'p',
  'z',
  'r',
  'y',
  '9',
  'x',
  '8',
  'g',
  'f',
  '2',
  't',
  'v',
  'd',
  'w',
  '0',
  's',
  '3',
  'j',
  'n',
  '5',
  '4',
  'k',
  'h',
  'c',
  'e',
  '6',
  'm',
  'u',
  'a',
  '7',
  'l',
];

const List<int> generator = [
  0x3b6a57b2,
  0x26508e6d,
  0x1ea119fa,
  0x3d4233dd,
  0x2a1462b3,
];

int _polymod(List<int> values) {
  var chk = 1;
  for (var v in values) {
    var top = chk >> 25;
    chk = (chk & 0x1ffffff) << 5 ^ v;
    for (var i = 0; i < generator.length; i++) {
      if ((top >> i) & 1 == 1) {
        chk ^= generator[i];
      }
    }
  }

  return chk;
}

List<int> _hrpExpand(String hrp) {
  var result = hrp.codeUnits.map((c) => c >> 5).toList();
  result = result + [0];

  result = result + hrp.codeUnits.map((c) => c & 31).toList();

  return result;
}

bool _verifyChecksum(String hrp, List<int> dataIncludingChecksum) {
  return _polymod(_hrpExpand(hrp) + dataIncludingChecksum) == 1;
}

List<int> _createChecksum(String hrp, List<int> data) {
  var values = _hrpExpand(hrp) + data + [0, 0, 0, 0, 0, 0];
  var polymod = _polymod(values) ^ 1;

  var result = <int>[0, 0, 0, 0, 0, 0];

  for (var i = 0; i < result.length; i++) {
    result[i] = (polymod >> (5 * (5 - i))) & 31;
  }
  return result;
}

class TooShortHrp implements Exception {
  @override
  String toString() => 'The human readable part should have non zero length.';
}

class TooLong implements Exception {
  TooLong(this.length);

  final int length;

  @override
  String toString() => 'The bech32 string is too long: $length (>90)';
}

class OutOfRangeHrpCharacters implements Exception {
  OutOfRangeHrpCharacters(this.hpr);

  final String hpr;

  @override
  String toString() =>
      'The human readable part contains invalid characters: $hpr';
}

class MixedCase implements Exception {
  MixedCase(this.hpr);

  final String hpr;

  @override
  String toString() =>
      'The human readable part is mixed case, should either be all lower or all upper case: $hpr';
}

class OutOfBoundChars implements Exception {
  OutOfBoundChars(this.char);

  final String char;

  @override
  String toString() => 'A character is undefined in bech32: $char';
}

class InvalidSeparator implements Exception {
  InvalidSeparator(this.pos);

  final int pos;

  @override
  String toString() => "separator '1' at invalid position: $pos";
}

class InvalidAddress implements Exception {
  @override
  String toString() => '';
}

class InvalidChecksum implements Exception {
  @override
  String toString() => 'Checksum verification failed';
}

class TooShortChecksum implements Exception {
  @override
  String toString() => 'Checksum is shorter than 6 characters';
}

class InvalidHrp implements Exception {
  @override
  String toString() => "Human readable part should be 'bc' or 'tb'.";
}

class InvalidProgramLength implements Exception {
  InvalidProgramLength(this.reason);

  final String reason;

  @override
  String toString() => 'Program length is invalid: $reason';
}

class InvalidWitnessVersion implements Exception {
  InvalidWitnessVersion(this.version);

  final int version;

  @override
  String toString() => 'Witness version $version > 16';
}

class InvalidPadding implements Exception {
  InvalidPadding(this.reason);

  final String reason;

  @override
  String toString() => 'Invalid padding: $reason';
}
