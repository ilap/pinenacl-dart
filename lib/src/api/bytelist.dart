part of pinenacl.api;

/// `ByteList` is the base of the PineNaCl cryptographic library,
/// which is based on the unmodifiable Uin8List class
class ByteList with ListMixin<int> implements Uint8List {
  ByteList([Iterable<int> bytes, int bytesLength])
      : this._u8l = _constructList(bytes, bytesLength, bytesLength);

  ByteList.fromList(List<int> list, [int minLength, int maxLength])
      : this._u8l = _constructList(
            list, minLength ?? _minLength, maxLength ?? _maxLength);

  ByteList.fromHexString(String s, {int minLength, int maxLength})
      : this._u8l = _constructList(Uint8List.fromList(hex.decode(s)),
            minLength ?? _minLength, maxLength ?? _maxLength);

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
    final sublist = _u8l.sublist(start, end);
    return ByteList(sublist, sublist.length);
  }
}
