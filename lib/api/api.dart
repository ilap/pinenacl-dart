// ignore_for_file: hash_and_equals

part of pinenacl.api;

abstract class AsymmetricKey extends ByteList with Encodable {
  AsymmetricKey(Uint8List bytes, {required int keyLength})
      : super.withConstraint(bytes, constraintLength: keyLength);
  AsymmetricPublicKey get publicKey;
}

abstract class AsymmetricPublicKey extends AsymmetricKey {
  AsymmetricPublicKey(Uint8List bytes, {required int keyLength})
      : super(bytes, keyLength: keyLength);
}

abstract class AsymmetricPrivateKey extends AsymmetricKey {
  AsymmetricPrivateKey(Uint8List bytes, {required int keyLength})
      : super(bytes, keyLength: keyLength);
}

///
/// `ByteList` is the base of the PineNaCl cryptographic library,
/// which is based on the unmodifiable Uin8List class
/// The bytelist can be created either from
/// - hex string (with or without '0x' prefix) or
/// - List of int's
///
/// ByteList can have a `min` and `max` length specified.
/// - `minLength` means the length of the constructable ByteList must be equal
/// of bigger.
/// - `maxLength` means the ByteList length must be less (till `minLength`) or
/// equal.
///
/// Theses two options can be used for creating a class with fixed-length ByteList or
/// a class which has some constraints e.g., a class that can only create a ByteList
/// that is longer or equal than 16 and shorter or equal than 32.
///
class ByteList with ListMixin<int>, Encodable {
  /// It creates an data's length ByteList
  ByteList(Iterable<int> data)
      : _u8l = _constructList(data, data.length, data.length);

  /// It creates a ByteList and checks wheter the data's length is equal with
  /// the specified constraint (min and max length equal).

  ByteList.withConstraint(Iterable<int> data, {required int constraintLength})
      : _u8l = _constructList(data, constraintLength, constraintLength);

  /// It creates a ByteList and checks wheter the data's length is equal with
  /// the specified constraints (allowed range i.e., min and max length)
  ///
  /// e.g. data.length >= min and data.length <= max.
  ByteList.withConstraintRange(Iterable<int> data,
      {int min = _minLength, int max = _maxLength})
      : _u8l = _constructList(data, min, max);

  /// Decoding encoded String to a ByteList. There is no size constraints for the
  /// decoded bytes.
  /// TODO: create unit tests for decoding constructors.
  ByteList.decode(String encodedString, {Encoder coder = decoder})
      : this(coder.decode(encodedString));

  /// Decoding encoded string to a ByteList with the expected length of the
  /// encoded bytes.
  ByteList.decodeWithConstraint(String encodedString,
      {Encoder coder = decoder, required int constraintLength})
      : this.withConstraint(coder.decode(encodedString),
            constraintLength: constraintLength);

  /// Decoding encoded string to a ByteList with the expected min and max lengths of the
  /// encoded bytes.
  ByteList.decodeWithConstraintRange(String encodedString,
      {Encoder coder = decoder, int min = _minLength, int max = _maxLength})
      : this.withConstraintRange(coder.decode(encodedString),
            min: min, max: max);

  static const _minLength = 0;

  // Maximum message/bytes' length is 1MB currently
  static const _maxLength = 1048576;

  final Uint8List _u8l;

  static Uint8List _constructList(
      Iterable<int> data, int minLength, int maxLength) {
    if (data.length < minLength || data.length > maxLength) {
      throw Exception(
          'The list length (${data.length}) is invalid (min: $minLength, max: $maxLength)');
    }
    return UnmodifiableUint8ListView(Uint8List.fromList(data.toList()));
  }

  // Default encoder/decoder is the HexCoder()
  static const decoder = Base16Encoder.instance;

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
    return ByteList.withConstraint(sublist, constraintLength: sublist.length);
  }
}

mixin Suffix on ByteList {
  int get prefixLength;
  ByteList get prefix => ByteList.withConstraint(take(prefixLength),
      constraintLength: prefixLength);
  ByteList get suffix => ByteList.withConstraint(skip(prefixLength),
      constraintLength: length - prefixLength);
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
