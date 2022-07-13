part of pinenacl.api;

/// The Encoder interface for classes that are capable for encoding data,
/// therefore they need decoding function too.
abstract class Encoder {
  String encode(ByteList data);
  Uint8List decode(String data);
}

mixin Encodable {
  Encoder get encoder;
  String encode([Encoder? encoder]) {
    encoder = encoder ?? this.encoder;
    return encoder.encode(this as ByteList);
  }
}
