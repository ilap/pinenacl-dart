part of pinenacl.api;

abstract class Sign {
  Verify get verifyKey;
  SignedMessage sign(List<int> message);
}

abstract class Verify extends ByteList {
  bool verify({Signature signature, ByteList message});
  bool verifySignedMessage({SignedMessage signedMessage});
}

class EncryptedMessage extends SuffixByteList {
  EncryptedMessage({List<int> nonce, List<int> cipherText})
      : super(nonce, cipherText, nonceLength);

  static const nonceLength = 24;
  Uint8List get nonce => prefix;
  Uint8List get cipherText => suffix;
}

class SealedMessage extends SuffixByteList {
  SealedMessage({List<int> public, List<int> cipherText})
      : super(public, cipherText, publicLength);

  static const publicLength = 32;
  Uint8List get public => prefix;
  Uint8List get cipherText => suffix;
}

class SignedMessage extends SuffixByteList {
  SignedMessage({Signature signature, List<int> message})
      : super(signature, message, signatureLength);
  SignedMessage.fromList({List<int> signedMessage})
      : super._(signedMessage, signatureLength);

  static const signatureLength = 64;
  Signature get signature => Signature(prefix);
  Uint8List get message => suffix;
}
