part of pinenacl.api;

abstract class Sign {
  Verify get verifyKey;
  SignedMessage sign(List<int> message);
}

abstract class Verify extends ByteList {
  bool verify({Signature signature, ByteList message});
  bool verifySignedMessage({SignedMessage signedMessage});
}

class EncryptedMessage extends ByteList with Suffix {
  EncryptedMessage({List<int> nonce, List<int> cipherText})
      : super(nonce + cipherText);

  static const nonceLength = 24;

  @override
  int _prefixLength = nonceLength;

  Uint8List get nonce => prefix;
  Uint8List get cipherText => suffix;
}

class SealedMessage extends ByteList with Suffix {
  SealedMessage({List<int> public, List<int> cipherText})
      : super(public + cipherText);

  @override
  int _prefixLength = publicLength;

  static const publicLength = 32;
  Uint8List get public => prefix;
  Uint8List get cipherText => suffix;
}

class SignedMessage extends ByteList with Suffix {
  SignedMessage({Signature signature, List<int> message})
      : super(signature + message, signatureLength);
  SignedMessage.fromList({List<int> signedMessage})
      : super(signedMessage);

  @override
  int _prefixLength = signatureLength;

  static const signatureLength = 64;
  Signature get signature => Signature(prefix);
  Uint8List get message => suffix;
}
