part of pinenacl.api;

abstract class ByteListBase with ListMixin<int> implements Uint8List {
  ByteListBase([int length]) : this._u8l = Uint8List(length ?? _minLength);

  ByteListBase.fromList(List<int> list, {int minLength, int maxLength})
      : this._u8l = _constructList(
            list, minLength ?? _minLength, maxLength ?? _maxLength);

  ByteListBase.fromHexString(String s, {int minLength, int maxLength})
      : this._u8l = _constructList(Uint8List.fromList(hex.decode(s)),
            minLength ?? _minLength, maxLength ?? _maxLength);

  static const _minLength = 0;

  // MAximum message/bytes' length
  static const _maxLength = 16384;

  final Uint8List _u8l;

  static Uint8List _constructList(
      List<int> list, int minLength, int maxLength) {
    if (list.length < minLength || list.length > maxLength) {
      throw Exception(
          'The list length (${list.length}) is invalid (min: $minLength, max: $maxLength)');
    }
    return Uint8List.fromList(list);
  }

  // Original getters/setters
  @override
  set length(int newLength) =>
      throw '`ByteList` length ($length) cannot be modified';
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
  int get lengthInBytes => _u8l.length;

  @override
  int get offsetInBytes => _u8l.offsetInBytes;

  @override
  bool operator ==(Object other) {
    var isEqual = identical(this, other) ||
        other is ByteListBase &&
            runtimeType == other.runtimeType &&
            length == other.length;

    if (!isEqual) return false;

    for (int i = 0; i < length; i++) {
      if (this[i] != (other as List)[i]) return false;
    }
    return true;
  }

  @override
  Uint8List sublist(int start, [int end]) => _u8l.sublist(start, end);
}

class ByteList extends ByteListBase {
  ByteList([int length]) : super(length);
}

class AsymmetricKey extends ByteListBase {
  AsymmetricKey([int length]) : super(length ?? keyLength);
  AsymmetricKey.fromList(List<int> list, [int minLength, int maxLength])
      : super.fromList(list ?? [],
            minLength: minLength ?? keyLength,
            maxLength: maxLength ?? keyLength);
  AsymmetricKey.fromHexString(String hexaString, [int minLength, int maxLength])
      : super.fromHexString(hexaString,
            minLength: minLength ?? keyLength,
            maxLength: maxLength ?? keyLength);
  static const keyLength = TweetNaCl.keyLength;
}

///
/// Classes for messages
///
class EncryptionMessage extends ByteListBase {
  EncryptionMessage.fromList(List<int> list) : super.fromList(list);
}

class EncryptedMessage extends EncryptionMessage {
  EncryptedMessage.fromList(List<int> list) : super.fromList(list);
  Uint8List get nonce =>
      Uint8List.fromList(sublist(0, TweetNaCl.nonceLength));
  Uint8List get ciphertext =>
      Uint8List.fromList(sublist(TweetNaCl.nonceLength));
}

class DecryptedMessage extends EncryptionMessage {
  DecryptedMessage.fromList(List<int> list) : super.fromList(list);
  Uint8List get nonce =>
      Uint8List.fromList(sublist(0, TweetNaCl.nonceLength));
  Uint8List get plaintext =>
      Uint8List.fromList(sublist(TweetNaCl.nonceLength));
}

abstract class BaseBox extends AsymmetricKey {
  BaseBox.fromList(List<int> list) : super.fromList(list);
  BaseBox.fromHexString(String hexaString) : super.fromHexString(hexaString);

  Uint8List doEncrypt(Uint8List ciphertext, Uint8List plaintext, int pLen,
      Uint8List nonce, Uint8List k);
  Uint8List doDecrypt(Uint8List plaintext, Uint8List ciphertext, int cLen,
      Uint8List nonce, Uint8List k);
  AsymmetricKey get key;

  DecryptedMessage decrypt(Uint8List encryptedMessage, {Uint8List nonce}) {
    var ciphertext;
    if (encryptedMessage is EncryptedMessage) {
      nonce = encryptedMessage.nonce;
      ciphertext = encryptedMessage.ciphertext;
    } else if (nonce != null) {
      ciphertext = encryptedMessage;
    } else {
      throw Exception('Nonce is required for a message');
    }

    final c = Uint8List(TweetNaCl.boxzerobytesLength) + ciphertext;
    final m = Uint8List(c.length);
    final plaintext = doDecrypt(m, Uint8List.fromList(c), c.length, nonce, key);
    return DecryptedMessage.fromList(nonce + plaintext);
  }

  EncryptedMessage encrypt(List<int> plainText, {List<int> nonce}) {
    nonce = nonce ?? TweetNaCl.randombytes(TweetNaCl.nonceLength);

    final m = Uint8List(TweetNaCl.zerobytesLength) + plainText;
    final c = Uint8List(m.length);
    final cipherText =
        doEncrypt(c, Uint8List.fromList(m), m.length, nonce, key);
    return EncryptedMessage.fromList(nonce + cipherText);
  }
}
