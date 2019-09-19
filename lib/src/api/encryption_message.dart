part of pinenacl.api;

abstract class Sign {
  Verify get verifyKey;
  SignedMessage sign(List<int> message);
}

abstract class Verify extends ByteList {
  bool verify({Signature signature, ByteList message});
  bool verifySignedMessage({SignedMessage signedMessage});
}

class _EncryptionMessage extends ByteList {
  _EncryptionMessage._(List<int> message, int prefixLength)
      : this._prefixLength = prefixLength,
        super(message, message.length);

  _EncryptionMessage(List<int> prefix, List<int> suffix, int prefixLength)
      : this._prefixLength = prefixLength,
        super((prefix ?? []) + (suffix ?? []), prefixLength + suffix.length);
  final int _prefixLength;
  ByteList get prefix => ByteList(take(_prefixLength), _prefixLength);
  ByteList get suffix => ByteList(skip(_prefixLength), length - _prefixLength);
}

class EncryptedMessage extends _EncryptionMessage {
  EncryptedMessage({List<int> nonce, List<int> cipherText})
      : super(nonce, cipherText, nonceLength);

  static const nonceLength = 24;
  Uint8List get nonce => prefix;
  Uint8List get cipherText => suffix;
}

class SealedMessage extends _EncryptionMessage {
  SealedMessage({List<int> public, List<int> cipherText})
      : super(public, cipherText, publicLength);

  static const publicLength = 32;
  Uint8List get public => prefix;
  Uint8List get cipherText => suffix;
}

class SignedMessage extends _EncryptionMessage {
  SignedMessage({Signature signature, List<int> message})
      : super(signature, message, signatureLength);
  SignedMessage.fromList({List<int> signedMessage})
      : super._(signedMessage, signatureLength);

  static const signatureLength = 64;
  Signature get signature => Signature(prefix);
  Uint8List get message => suffix;
}
