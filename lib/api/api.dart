// ignore_for_file: hash_and_equals

part of pinenacl.api;

abstract class AsymmetricKey extends ByteList with Encodable {
  AsymmetricKey(Uint8List data, [int? keyLength]) : super(data, keyLength);
  AsymmetricKey.fromList(Uint8List data) : super.fromList(data);
  AsymmetricPublicKey get publicKey;
}

abstract class AsymmetricPublicKey extends AsymmetricKey {
  AsymmetricPublicKey(Uint8List data, [int? bytesLength])
      : super(data, bytesLength);
  AsymmetricPublicKey.fromList(Uint8List data) : super.fromList(data);
}

abstract class AsymmetricPrivateKey extends AsymmetricKey {
  AsymmetricPrivateKey(Uint8List data, [int? keyLength])
      : super(data, keyLength);
}

/// `ByteList` is the base of the PineNaCl cryptographic library,
/// which is based on the unmodifiable Uin8List class
class ByteList with ListMixin<int>, Encodable {
  ByteList(Iterable<int> bytes, [int? bytesLength])
      : _u8l = _constructList(
            bytes, bytesLength ?? bytes.length, bytesLength ?? bytes.length);

  ByteList.fromList(Uint8List list,
      [int minLength = _minLength, int maxLength = _maxLength])
      : _u8l = _constructList(list, minLength, maxLength);

  ByteList.decode(String data, {Encoder defaultDecoder = decoder, int? bytesLength})
      : this(defaultDecoder.decode(data), bytesLength);

  static const _minLength = 0;

  // Maximum message/bytes' length
  static const _maxLength = 16384;

  final Uint8List _u8l;

  static Uint8List _constructList(
      Iterable<int> list, int minLength, int maxLength) {
    if (list.length < minLength || list.length > maxLength) {
      throw Exception(
          'The list length (${list.length}) is invalid (min: $minLength, max: $maxLength)');
    }
    return UnmodifiableUint8ListView(Uint8List.fromList(list.toList()));
  }

  // Default encoder/decoder is the HexCoder()
  static const decoder = HexCoder.instance;

  @override
  Encoder get encoder => decoder;

  // Original getters/setters
  @override
  set length(int newLength) => _u8l.length = newLength;

  @override
  int get length => _u8l.length;

  @override
  int operator [](int index) => _u8l[index];

  @override
  operator []=(int index, value) {
    _u8l[index] = value;
  }

  @override
  bool operator ==(Object other) {
    var isEqual = identical(this, other) ||
        other is ByteList &&
            runtimeType == other.runtimeType &&
            length == other.length;

    if (!isEqual) return false;

    for (var i = 0; i < length; i++) {
      if (this[i] != (other as List)[i]) return false;
    }
    return true;
  }

  @override
  ByteList sublist(int start, [int? end]) {
    final sublist = _u8l.sublist(start, end ?? _u8l.length);
    return ByteList(sublist, sublist.length);
  }
}

mixin Suffix on ByteList {
  int get prefixLength;
  ByteList get prefix => ByteList(take(prefixLength), prefixLength);
  ByteList get suffix => ByteList(skip(prefixLength), length - prefixLength);
}

extension ByteListExtension on ByteList {
  Uint8List get asTypedList => _u8l;
}

/// Add a global extension for converting List<int> to Uint8List.
extension IntListExtension on List<int> {
  Uint8List toUint8List() {
    return Uint8List.fromList(this);
  }
}
