import 'package:pinenacl/api.dart';

abstract class Sign {
  Verify get verifyKey;
  EncryptionMessage sign(Uint8List message);
}

abstract class Verify implements ByteList {
  bool verify({required SignatureBase signature, required Uint8List message});
  bool verifySignedMessage({required EncryptionMessage signedMessage});
}

abstract class SignatureBase implements ByteList {}

abstract class EncryptionMessage {
  SignatureBase get signature;
  ByteList get message;
}
