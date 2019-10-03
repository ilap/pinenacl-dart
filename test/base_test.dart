import 'package:test/test.dart';

import 'package:pinenacl/public.dart'
    show GenericPrivateKey, ByteList, Curve25519;

void main() {
  group('Base Classes Test', () {
    group('ByteList', () {
      test('Immutability', () {
        final _l32 = List<int>.generate(32, (i) => 0xb);
        final byteList = ByteList(_l32, 32);
        final sk = GenericPrivateKey<Curve25519>(_l32);

        expect(() {
          sk[0] += 1;
        }, throwsUnsupportedError);
        expect(() {
          sk.sublist(0, 5)[0] += 1;
        }, throwsUnsupportedError);

        expect(() {
          byteList[0] += 1;
        }, throwsUnsupportedError);
        expect(() {
          byteList.sublist(0, 5)[0] += 1;
        }, throwsUnsupportedError);
      });

      test('Growing', () {
        final _l32 = List<int>.generate(32, (i) => 0xb);
        final byteList = ByteList(_l32, 32);
        final sk = GenericPrivateKey<Curve25519>(_l32);

        expect(() {
          sk.length += 1;
        }, throwsUnsupportedError);
        expect(() {
          byteList.length += 1;
        }, throwsUnsupportedError);
      });
    });
  });
}
