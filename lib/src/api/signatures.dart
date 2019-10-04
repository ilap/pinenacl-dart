part of pinenacl.api;

abstract class Sign {
  Verify get verifyKey;
  EncryptionMessage sign(List<int> message);
}

abstract class Verify extends ByteList {
  bool verify({SignatureBase signature, List<int> message});
  bool verifySignedMessage({EncryptionMessage signedMessage});
}

abstract class SignatureBase extends ByteList {}

abstract class EncryptionMessage {
  SignatureBase get signature;
  ByteList get message;
}
