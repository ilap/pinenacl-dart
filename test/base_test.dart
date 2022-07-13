import 'package:test/test.dart';

import 'package:pinenacl/api.dart';

void main() {
  group('Base Classes Test', () {
    group('ByteList', () {
      test('Immutability', () {
        final l32 = List<int>.generate(32, (i) => 0xb).toUint8List();
        final byteList = ByteList(l32);
        final sk = PrivateKey(l32);

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
        final l32 = List<int>.generate(32, (i) => 0xb).toUint8List();
        final byteList = ByteList(l32);
        final sk = PrivateKey(l32);

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
