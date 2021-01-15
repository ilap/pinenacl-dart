import 'package:pinenacl/api.dart';

abstract class Sign {
  Verify get verifyKey;
  EncryptionMessage sign(List<int> message);
}

abstract class Verify implements ByteList {
  bool verify({required SignatureBase signature, required List<int> message});
  bool verifySignedMessage({required EncryptionMessage signedMessage});
}

abstract class SignatureBase implements ByteList {}

abstract class EncryptionMessage {
  SignatureBase get signature;
  ByteList get message;
}
