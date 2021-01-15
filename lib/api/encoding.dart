part of pinenacl.api;

abstract class Encoder {
  String encode(Uint8List data);
  ByteList decode(String data);
}

mixin Encodable {
  Encoder get encoder;
  String encode([Encoder? encoder]) {
    encoder = encoder ?? this.encoder;
    return encoder.encode(this as ByteList);
  }
}
