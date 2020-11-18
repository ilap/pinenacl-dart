part of pinenacl.api;

abstract class AsymmetricKey extends ByteList with Encodable {
  AsymmetricKey([List<int> data]) : super(data);
  AsymmetricKey.fromList(List<int> data) : super.fromList(data);
}

abstract class AsymmetricPublicKey extends AsymmetricKey {
  AsymmetricPublicKey([List<int> data]) : super(data);
  AsymmetricPublicKey.fromList(List<int> data) : super.fromList(data);
}

abstract class AsymmetricPrivateKey extends AsymmetricKey {
  factory AsymmetricPrivateKey.generate() {
    throw Exception('AsymmetricPrivateKey - unreachable');
  }
  final AsymmetricPublicKey publicKey;
}

/// `ByteList` is the base of the PineNaCl cryptographic library,
/// which is based on the unmodifiable Uin8List class
class ByteList with ListMixin<int>, Encodable implements Uint8List {
  ByteList([Iterable<int> bytes, int bytesLength])
      : this._u8l = _constructList(
            bytes, bytesLength ?? _minLength, bytesLength ?? _maxLength);

  ByteList.fromList(List<int> list, [int minLength, int maxLength])
      : this._u8l = _constructList(
            list, minLength ?? _minLength, maxLength ?? _maxLength);

  factory ByteList.decode(String data, [Encoder defaultDecoder = decoder]) {
    return defaultDecoder.decode(data);
  }

  static const _minLength = 0;

  // Maximum message/bytes' length
  static const _maxLength = 16384;

  final Uint8List _u8l;

  static Uint8List _constructList(
      Iterable<int> list, int minLength, int maxLength) {
    if (list == null || list.length < minLength || list.length > maxLength) {
      throw Exception(
          'The list length (${list == null ? 'N/A' : list.length}) is invalid (min: $minLength, max: $maxLength)');
    }
    return UnmodifiableUint8ListView(Uint8List.fromList(list.toList()));
  }

  // Default encoder/decoder is the HexEncoder()
  static const decoder = hexEncoder;

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
  ByteBuffer get buffer => _u8l.buffer;

  @override
  int get elementSizeInBytes => _u8l.elementSizeInBytes;

  @override
  int get lengthInBytes => _u8l.lengthInBytes;

  @override
  int get offsetInBytes => _u8l.offsetInBytes;

  @override
  bool operator ==(Object other) {
    var isEqual = identical(this, other) ||
        other != null &&
            other is ByteList &&
            runtimeType == other.runtimeType &&
            length == other.length;

    if (!isEqual) return false;

    for (int i = 0; i < length; i++) {
      if (this[i] != (other as List)[i]) return false;
    }
    return true;
  }

  @override
  ByteList sublist(int start, [int end]) {
    final sublist = _u8l.sublist(start, end ?? _u8l.length);
    return ByteList(sublist, sublist.length);
  }
}

abstract class Encoder {
  String encode(ByteList data);
  ByteList decode(String data);
}

mixin Encodable {
  Encoder get encoder;
  String encode([Encoder encoder]) {
    encoder = encoder ?? this.encoder;
    return encoder.encode(this);
  }
}

mixin Suffix on ByteList {
  int prefixLength;
  ByteList get prefix => ByteList(take(prefixLength), prefixLength);
  ByteList get suffix => ByteList(skip(prefixLength), length - prefixLength);
}
