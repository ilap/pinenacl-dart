part of pinenacl.api;

typedef Crypting = Uint8List Function(
    Uint8List out, Uint8List text, int textLen, Uint8List nonce, Uint8List k);

abstract class BoxBase extends ByteList implements AsymmetricKey {
  BoxBase.fromList(List<int> list) : super.fromList(list);
  BoxBase.fromHexString(String hexaString) : super.fromHexString(hexaString);

  Crypting doEncrypt;
  Crypting doDecrypt;
  ByteList get key;

  Uint8List decrypt(Uint8List encryptedMessage, {Uint8List nonce}) {
    var ciphertext;
    if (encryptedMessage is EncryptedMessage) {
      nonce = encryptedMessage.nonce;
      ciphertext = encryptedMessage.cipherText;
    } else if (nonce != null) {
      ciphertext = encryptedMessage;
    } else {
      throw Exception('Nonce is required for a message');
    }

    final c = Uint8List(TweetNaCl.boxzerobytesLength) + ciphertext;
    final m = Uint8List(c.length);
    final plaintext =
        doDecrypt(m, Uint8List.fromList(c), c.length, nonce, this.key);
    return Uint8List.fromList(plaintext);
  }

  EncryptedMessage encrypt(List<int> plainText, {List<int> nonce}) {
    nonce = nonce ?? TweetNaCl.randombytes(TweetNaCl.nonceLength);

    final m = Uint8List(TweetNaCl.zerobytesLength) + plainText;
    final c = Uint8List(m.length);
    final cipherText =
        doEncrypt(c, Uint8List.fromList(m), m.length, nonce, this.key);

    return EncryptedMessage(nonce: nonce, cipherText: cipherText);
  }
}
