// ignore_for_file: constant_identifier_names, non_constant_identifier_names
library pinenacl.tweetnacl;

import 'dart:math';

import 'package:pinenacl/api.dart';
import 'package:pinenacl/src/tweetnacl/poly1305.dart';

part 'tweetnacl_ext.dart';

class TweetNaCl {
  static const int keyLength = 32;
  static const int macBytes = 16;
  static const int seedSize = 32;

  // Length of public key in bytes.
  static const int publicKeyLength = 32;
  // Default length of the secret key in bytes.
  static const int secretKeyLength = 32;
  // Length of precomputed shared key in bytes.
  static const int sharedKeyLength = 32;
  // Length of nonce in bytes.
  static const int nonceLength = 24;
  // zero bytes in case box
  static const int zerobytesLength = 32;
  // zero bytes in case open box
  static const int boxzerobytesLength = 16;
  // Length of overhead added to box compared to original message.
  static const int overheadLength = 16;

  // Default length of the ed25519 signing key in bytes.
  static const int signingKeyLength = 64;
  // Signature length
  static const int signatureLength = 64;

  static final _0 =
      Uint8List.fromList([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

  static final _9 = Uint8List.fromList([
    9, 0, 0, 0, 0, 0, 0, 0, // 0-7
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
  ]);

  static final _gf0 =
      Int32List.fromList([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); //16

  static final _gf1 =
      Int32List.fromList([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); //16

  static final _121665 = Int32List.fromList([
    0xDB41, 1, 0, 0, // 0-3
    0, 0, 0, 0,
    0, 0, 0, 0,
    0, 0, 0, 0
  ]);

  static final _D = Int32List.fromList([
    0x78a3, 0x1359, 0x4dca, 0x75eb, // 0-3
    0xd8ab, 0x4141, 0x0a4d, 0x0070,
    0xe898, 0x7779, 0x4079, 0x8cc7,
    0xfe73, 0x2b6f, 0x6cee, 0x5203
  ]);

  static final _D2 = Int32List.fromList([
    0xf159, 0x26b2, 0x9b94, 0xebd6, // 0-3
    0xb156, 0x8283, 0x149a, 0x00e0,
    0xd130, 0xeef3, 0x80f2, 0x198e,
    0xfce7, 0x56df, 0xd9dc, 0x2406
  ]);

  static final _X = Int32List.fromList([
    0xd51a, 0x8f25, 0x2d60, 0xc956, // 0-3
    0xa7b2, 0x9525, 0xc760, 0x692c,
    0xdc5c, 0xfdd6, 0xe231, 0xc0a4,
    0x53fe, 0xcd6e, 0x36d3, 0x2169
  ]);

  static final _Y = Int32List.fromList([
    0x6658, 0x6666, 0x6666, 0x6666, // 0-3
    0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666
  ]);

  static final _I = Int32List.fromList([
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, // 0-3
    0xe478, 0xad2f, 0x1806, 0x2f43,
    0xd7a7, 0x3dfb, 0x0099, 0x2b4d,
    0xdf0b, 0x4fc1, 0x2480, 0x2b83
  ]);

  static void _ts64(Uint8List x, final int i, final int uh, final int ul) {
    x[i + 0] = (uh >> 24) & 0xff;
    x[i + 1] = (uh >> 16) & 0xff;
    x[i + 2] = (uh >> 8) & 0xff;
    x[i + 3] = uh & 0xff;
    x[i + 4] = (ul >> 24) & 0xff;
    x[i + 5] = (ul >> 16) & 0xff;
    x[i + 6] = (ul >> 8) & 0xff;
    x[i + 7] = ul & 0xff;
  }

  static int _vn(
      Uint8List x, final int xoff, Uint8List y, final int yoff, final int n) {
    int i, d = 0;
    for (i = 0; i < n; i++) {
      d |= (x[i + xoff] ^ y[i + yoff]) & 0xff;
    }
    return (1 & ((d - 1) >> 8)) - 1;
  }

  static int _crypto_verify_16(
      Uint8List x, final int xoff, Uint8List y, final int yoff) {
    return _vn(x, xoff, y, yoff, 16);
  }

  static int crypto_verify_16(Uint8List x, Uint8List y) {
    return _crypto_verify_16(x, 0, y, 0);
  }

  static int _crypto_verify_32(
      Uint8List x, final int xoff, Uint8List y, final int yoff) {
    return _vn(x, xoff, y, yoff, 32);
  }

  static int crypto_verify_32(Uint8List x, Uint8List y) {
    return _crypto_verify_32(x, 0, y, 0);
  }

  static void _core_salsa20(
      Uint8List o, Uint8List p, Uint8List k, Uint8List c) {
    final j0 = c[0] | c[1] << 8 | c[2] << 16 | c[3] << 24,
        j1 = k[0] | k[1] << 8 | k[2] << 16 | k[3] << 24,
        j2 = k[4] | k[5] << 8 | k[6] << 16 | k[7] << 24,
        j3 = k[8] | k[9] << 8 | k[10] << 16 | k[11] << 24,
        j4 = k[12] | k[13] << 8 | k[14] << 16 | k[15] << 24,
        j5 = c[4] | c[5] << 8 | c[6] << 16 | c[7] << 24,
        j6 = p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24,
        j7 = p[4] | p[5] << 8 | p[6] << 16 | p[7] << 24,
        j8 = p[8] | p[9] << 8 | p[10] << 16 | p[11] << 24,
        j9 = p[12] | p[13] << 8 | p[14] << 16 | p[15] << 24,
        j10 = c[8] | c[9] << 8 | c[10] << 16 | c[11] << 24,
        j11 = k[16] | k[17] << 8 | k[18] << 16 | k[19] << 24,
        j12 = k[20] | k[21] << 8 | k[22] << 16 | k[23] << 24,
        j13 = k[24] | k[25] << 8 | k[26] << 16 | k[27] << 24,
        j14 = k[28] | k[29] << 8 | k[30] << 16 | k[31] << 24,
        j15 = c[12] | c[13] << 8 | c[14] << 16 | c[15] << 24;

    final x = Int32List.fromList(
        [j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15]);

    int u;

    for (var i = 0; i < 20; i += 2) {
      u = x[0] + x[12];
      x[4] ^= u << 7 | _shr32(u, 32 - 7);
      u = x[4] + x[0];
      x[8] ^= u << 9 | _shr32(u, 32 - 9);
      u = x[8] + x[4];
      x[12] ^= u << 13 | _shr32(u, 32 - 13);
      u = x[12] + x[8];
      x[0] ^= u << 18 | _shr32(u, 32 - 18);

      u = x[5] + x[1];
      x[9] ^= u << 7 | _shr32(u, 32 - 7);
      u = x[9] + x[5];
      x[13] ^= u << 9 | _shr32(u, 32 - 9);
      u = x[13] + x[9];
      x[1] ^= u << 13 | _shr32(u, 32 - 13);
      u = x[1] + x[13];
      x[5] ^= u << 18 | _shr32(u, 32 - 18);

      u = x[10] + x[6];
      x[14] ^= u << 7 | _shr32(u, 32 - 7);
      u = x[14] + x[10];
      x[2] ^= u << 9 | _shr32(u, 32 - 9);
      u = x[2] + x[14];
      x[6] ^= u << 13 | _shr32(u, 32 - 13);
      u = x[6] + x[2];
      x[10] ^= u << 18 | _shr32(u, 32 - 18);

      u = x[15] + x[11];
      x[3] ^= u << 7 | _shr32(u, 32 - 7);
      u = x[3] + x[15];
      x[7] ^= u << 9 | _shr32(u, 32 - 9);
      u = x[7] + x[3];
      x[11] ^= u << 13 | _shr32(u, 32 - 13);
      u = x[11] + x[7];
      x[15] ^= u << 18 | _shr32(u, 32 - 18);

      u = x[0] + x[3];
      x[1] ^= u << 7 | _shr32(u, 32 - 7);
      u = x[1] + x[0];
      x[2] ^= u << 9 | _shr32(u, 32 - 9);
      u = x[2] + x[1];
      x[3] ^= u << 13 | _shr32(u, 32 - 13);
      u = x[3] + x[2];
      x[0] ^= u << 18 | _shr32(u, 32 - 18);

      u = x[5] + x[4];
      x[6] ^= u << 7 | _shr32(u, 32 - 7);
      u = x[6] + x[5];
      x[7] ^= u << 9 | _shr32(u, 32 - 9);
      u = x[7] + x[6];
      x[4] ^= u << 13 | _shr32(u, 32 - 13);
      u = x[4] + x[7];
      x[5] ^= u << 18 | _shr32(u, 32 - 18);

      u = x[10] + x[9];
      x[11] ^= u << 7 | _shr32(u, 32 - 7);
      u = x[11] + x[10];
      x[8] ^= u << 9 | _shr32(u, 32 - 9);
      u = x[8] + x[11];
      x[9] ^= u << 13 | _shr32(u, 32 - 13);
      u = x[9] + x[8];
      x[10] ^= u << 18 | _shr32(u, 32 - 18);

      u = x[15] + x[14];
      x[12] ^= u << 7 | _shr32(u, 32 - 7);
      u = x[12] + x[15];
      x[13] ^= u << 9 | _shr32(u, 32 - 9);
      u = x[13] + x[12];
      x[14] ^= u << 13 | _shr32(u, 32 - 13);
      u = x[14] + x[13];
      x[15] ^= u << 18 | _shr32(u, 32 - 18);
    }

    x[0] = x[0] + j0;
    x[1] = x[1] + j1;
    x[2] = x[2] + j2;
    x[3] = x[3] + j3;
    x[4] = x[4] + j4;
    x[5] = x[5] + j5;
    x[6] = x[6] + j6;
    x[7] = x[7] + j7;
    x[8] = x[8] + j8;
    x[9] = x[9] + j9;
    x[10] = x[10] + j10;
    x[11] = x[11] + j11;
    x[12] = x[12] + j12;
    x[13] = x[13] + j13;
    x[14] = x[14] + j14;
    x[15] = x[15] + j15;

    o[0] = x[0] >> 0;
    o[1] = x[0] >> 8;
    o[2] = x[0] >> 16;
    o[3] = x[0] >> 24;

    o[4] = x[1] >> 0;
    o[5] = x[1] >> 8;
    o[6] = x[1] >> 16;
    o[7] = x[1] >> 24;

    o[8] = x[2] >> 0;
    o[9] = x[2] >> 8;
    o[10] = x[2] >> 16;
    o[11] = x[2] >> 24;

    o[12] = x[3] >> 0;
    o[13] = x[3] >> 8;
    o[14] = x[3] >> 16;
    o[15] = x[3] >> 24;

    o[16] = x[4] >> 0;
    o[17] = x[4] >> 8;
    o[18] = x[4] >> 16;
    o[19] = x[4] >> 24;

    o[20] = x[5] >> 0;
    o[21] = x[5] >> 8;
    o[22] = x[5] >> 16;
    o[23] = x[5] >> 24;

    o[24] = x[6] >> 0;
    o[25] = x[6] >> 8;
    o[26] = x[6] >> 16;
    o[27] = x[6] >> 24;

    o[28] = x[7] >> 0;
    o[29] = x[7] >> 8;
    o[30] = x[7] >> 16;
    o[31] = x[7] >> 24;

    o[32] = x[8] >> 0;
    o[33] = x[8] >> 8;
    o[34] = x[8] >> 16;
    o[35] = x[8] >> 24;

    o[36] = x[9] >> 0;
    o[37] = x[9] >> 8;
    o[38] = x[9] >> 16;
    o[39] = x[9] >> 24;

    o[40] = x[10] >> 0;
    o[41] = x[10] >> 8;
    o[42] = x[10] >> 16;
    o[43] = x[10] >> 24;

    o[44] = x[11] >> 0;
    o[45] = x[11] >> 8;
    o[46] = x[11] >> 16;
    o[47] = x[11] >> 24;

    o[48] = x[12] >> 0;
    o[49] = x[12] >> 8;
    o[50] = x[12] >> 16;
    o[51] = x[12] >> 24;

    o[52] = x[13] >> 0;
    o[53] = x[13] >> 8;
    o[54] = x[13] >> 16;
    o[55] = x[13] >> 24;

    o[56] = x[14] >> 0;
    o[57] = x[14] >> 8;
    o[58] = x[14] >> 16;
    o[59] = x[14] >> 24;

    o[60] = x[15] >> 0;
    o[61] = x[15] >> 8;
    o[62] = x[15] >> 16;
    o[63] = x[15] >> 24;
  }

  static void _core_hsalsa20(
      Uint8List o, Uint8List p, Uint8List k, Uint8List c) {
    final j0 = c[0] | c[1] << 8 | c[2] << 16 | c[3] << 24,
        j1 = k[0] | k[1] << 8 | k[2] << 16 | k[3] << 24,
        j2 = k[4] | k[5] << 8 | k[6] << 16 | k[7] << 24,
        j3 = k[8] | k[9] << 8 | k[10] << 16 | k[11] << 24,
        j4 = k[12] | k[13] << 8 | k[14] << 16 | k[15] << 24,
        j5 = c[4] | c[5] << 8 | c[6] << 16 | c[7] << 24,
        j6 = p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24,
        j7 = p[4] | p[5] << 8 | p[6] << 16 | p[7] << 24,
        j8 = p[8] | p[9] << 8 | p[10] << 16 | p[11] << 24,
        j9 = p[12] | p[13] << 8 | p[14] << 16 | p[15] << 24,
        j10 = c[8] | c[9] << 8 | c[10] << 16 | c[11] << 24,
        j11 = k[16] | k[17] << 8 | k[18] << 16 | k[19] << 24,
        j12 = k[20] | k[21] << 8 | k[22] << 16 | k[23] << 24,
        j13 = k[24] | k[25] << 8 | k[26] << 16 | k[27] << 24,
        j14 = k[28] | k[29] << 8 | k[30] << 16 | k[31] << 24,
        j15 = c[12] | c[13] << 8 | c[14] << 16 | c[15] << 24;

    final x = Int32List.fromList(
        [j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15]);

    int u;

    for (var i = 0; i < 20; i += 2) {
      u = x[0] + x[12];
      x[4] ^= u << 7 | _shr32(u, 32 - 7);
      u = x[4] + x[0];
      x[8] ^= u << 9 | _shr32(u, 32 - 9);
      u = x[8] + x[4];
      x[12] ^= u << 13 | _shr32(u, 32 - 13);
      u = x[12] + x[8];
      x[0] ^= u << 18 | _shr32(u, 32 - 18);

      u = x[5] + x[1];
      x[9] ^= u << 7 | _shr32(u, 32 - 7);
      u = x[9] + x[5];
      x[13] ^= u << 9 | _shr32(u, 32 - 9);
      u = x[13] + x[9];
      x[1] ^= u << 13 | _shr32(u, 32 - 13);
      u = x[1] + x[13];
      x[5] ^= u << 18 | _shr32(u, 32 - 18);

      u = x[10] + x[6];
      x[14] ^= u << 7 | _shr32(u, 32 - 7);
      u = x[14] + x[10];
      x[2] ^= u << 9 | _shr32(u, 32 - 9);
      u = x[2] + x[14];
      x[6] ^= u << 13 | _shr32(u, 32 - 13);
      u = x[6] + x[2];
      x[10] ^= u << 18 | _shr32(u, 32 - 18);

      u = x[15] + x[11];
      x[3] ^= u << 7 | _shr32(u, 32 - 7);
      u = x[3] + x[15];
      x[7] ^= u << 9 | _shr32(u, 32 - 9);
      u = x[7] + x[3];
      x[11] ^= u << 13 | _shr32(u, 32 - 13);
      u = x[11] + x[7];
      x[15] ^= u << 18 | _shr32(u, 32 - 18);

      u = x[0] + x[3];
      x[1] ^= u << 7 | _shr32(u, 32 - 7);
      u = x[1] + x[0];
      x[2] ^= u << 9 | _shr32(u, 32 - 9);
      u = x[2] + x[1];
      x[3] ^= u << 13 | _shr32(u, 32 - 13);
      u = x[3] + x[2];
      x[0] ^= u << 18 | _shr32(u, 32 - 18);

      u = x[5] + x[4];
      x[6] ^= u << 7 | _shr32(u, 32 - 7);
      u = x[6] + x[5];
      x[7] ^= u << 9 | _shr32(u, 32 - 9);
      u = x[7] + x[6];
      x[4] ^= u << 13 | _shr32(u, 32 - 13);
      u = x[4] + x[7];
      x[5] ^= u << 18 | _shr32(u, 32 - 18);

      u = x[10] + x[9];
      x[11] ^= u << 7 | _shr32(u, 32 - 7);
      u = x[11] + x[10];
      x[8] ^= u << 9 | _shr32(u, 32 - 9);
      u = x[8] + x[11];
      x[9] ^= u << 13 | _shr32(u, 32 - 13);
      u = x[9] + x[8];
      x[10] ^= u << 18 | _shr32(u, 32 - 18);

      u = x[15] + x[14];
      x[12] ^= u << 7 | _shr32(u, 32 - 7);
      u = x[12] + x[15];
      x[13] ^= u << 9 | _shr32(u, 32 - 9);
      u = x[13] + x[12];
      x[14] ^= u << 13 | _shr32(u, 32 - 13);
      u = x[14] + x[13];
      x[15] ^= u << 18 | _shr32(u, 32 - 18);
    }

    // The & 0xff masking is not required as it's an Uint8List
    // which will do the mask anyway.
    o[0] = x[0] >> 0;
    o[1] = x[0] >> 8;
    o[2] = x[0] >> 16;
    o[3] = x[0] >> 24;

    o[4] = x[5] >> 0;
    o[5] = x[5] >> 8;
    o[6] = x[5] >> 16;
    o[7] = x[5] >> 24;

    o[8] = x[10] >> 0;
    o[9] = x[10] >> 8;
    o[10] = x[10] >> 16;
    o[11] = x[10] >> 24;

    o[12] = x[15] >> 0;
    o[13] = x[15] >> 8;
    o[14] = x[15] >> 16;
    o[15] = x[15] >> 24;

    o[16] = x[6] >> 0;
    o[17] = x[6] >> 8;
    o[18] = x[6] >> 16;
    o[19] = x[6] >> 24;

    o[20] = x[7] >> 0;
    o[21] = x[7] >> 8;
    o[22] = x[7] >> 16;
    o[23] = x[7] >> 24;

    o[24] = x[8] >> 0;
    o[25] = x[8] >> 8;
    o[26] = x[8] >> 16;
    o[27] = x[8] >> 24;

    o[28] = x[9] >> 0;
    o[29] = x[9] >> 8;
    o[30] = x[9] >> 16;
    o[31] = x[9] >> 24;
  }

  static int crypto_core_salsa20(
      Uint8List out, Uint8List input, Uint8List k, Uint8List c) {
    _core_salsa20(out, input, k, c);
    return 0;
  }

  static Uint8List crypto_core_hsalsa20(
      Uint8List out, Uint8List input, Uint8List k, Uint8List c) {
    _core_hsalsa20(out, input, k, c);
    return out;
  }

// "expand 32-byte k"
  static final _sigma = Uint8List.fromList([
    101, 120, 112, 97, //0-7
    110, 100, 32, 51,
    50, 45, 98, 121,
    116, 101, 32, 107
  ]);

  static int crypto_stream_salsa20_xor(Uint8List c, int cpos, Uint8List m,
      int mpos, int b, Uint8List n, Uint8List k,
      [int ic = 0]) {
    final z = Uint8List(16), x = Uint8List(64);
    int i;
    int u;

    for (i = 0; i < 16; i++) {
      z[i] = 0;
    }

    for (i = 0; i < 8; i++) {
      z[i] = n[i];
    }

    for (i = 8; i < 16; i++) {
      z[i] = ic & 0xff;
      ic >>= 8;
    }

    while (b >= 64) {
      crypto_core_salsa20(x, z, k, _sigma);
      for (i = 0; i < 64; i++) {
        c[cpos + i] = m[mpos + i] ^ x[i];
      }
      u = 1;
      for (i = 8; i < 16; i++) {
        u = u + z[i];
        z[i] = u;
        u = _shr32(u, 8);
      }
      b -= 64;
      cpos += 64;
      mpos += 64;
    }
    if (b > 0) {
      crypto_core_salsa20(x, z, k, _sigma);
      for (i = 0; i < b; i++) {
        c[cpos + i] = m[mpos + i] ^ x[i];
      }
    }

    return 0;
  }

  static int crypto_stream_salsa20(
      Uint8List c, int cpos, int b, Uint8List n, Uint8List k) {
    final z = Uint8List(16), x = Uint8List(64);
    int i;
    int u;

    for (i = 0; i < 16; i++) {
      z[i] = 0;
    }

    for (i = 0; i < 8; i++) {
      z[i] = n[i];
    }

    while (b >= 64) {
      crypto_core_salsa20(x, z, k, _sigma);
      for (i = 0; i < 64; i++) {
        c[cpos + i] = x[i];
      }

      u = 1;

      for (i = 8; i < 16; i++) {
        u = u + z[i];
        z[i] = u;
        u = _shr32(u, 8);
      }

      b -= 64;
      cpos += 64;
    }

    if (b > 0) {
      crypto_core_salsa20(x, z, k, _sigma);
      for (i = 0; i < b; i++) {
        c[cpos + i] = x[i];
      }
    }

    return 0;
  }

  static int crypto_stream(
      Uint8List c, int cpos, int d, Uint8List n, Uint8List k) {
    final s = Uint8List(32);

    crypto_core_hsalsa20(s, n, k, _sigma);
    final sn = Uint8List(8);

    for (var i = 0; i < 8; i++) {
      sn[i] = n[i + 16];
    }

    return crypto_stream_salsa20(c, cpos, d, sn, s);
  }

  static int crypto_stream_xor(Uint8List c, int cpos, Uint8List m, int mpos,
      int d, Uint8List n, Uint8List k) {
    final s = Uint8List(32);

    crypto_core_hsalsa20(s, n, k, _sigma);
    final sn = Uint8List(8);

    for (var i = 0; i < 8; i++) {
      sn[i] = n[i + 16];
    }

    return crypto_stream_salsa20_xor(c, cpos, m, mpos, d, sn, s);
  }

  static int _crypto_onetimeauth(Uint8List out, final int outpos, Uint8List m,
      final int mpos, int n, Uint8List k) {
    final s = Poly1305(k);

    s.update(m, mpos, n);
    s.finish(out, outpos);

    return 0;
  }

  static int crypto_onetimeauth(
      Uint8List out, Uint8List m, final int n, Uint8List k) {
    return _crypto_onetimeauth(out, 0, m, 0, n, k);
  }

  static int _crypto_onetimeauth_verify(Uint8List h, final int hoff,
      Uint8List m, final int moff, int /*long*/ n, Uint8List k) {
    final x = Uint8List(16);

    _crypto_onetimeauth(x, 0, m, moff, n, k);

    return _crypto_verify_16(h, hoff, x, 0);
  }

  static int _crypto_onetimeauth_verify_len(
      Uint8List h, Uint8List m, final int n, Uint8List k) {
    return _crypto_onetimeauth_verify(h, 0, m, 0, n, k);
  }

  static int crypto_onetimeauth_verify(Uint8List h, Uint8List m, Uint8List k) {
    return _crypto_onetimeauth_verify_len(h, m, m.length, k);
  }

  static Uint8List crypto_secretbox(
      Uint8List c, Uint8List m, final int d, Uint8List n, Uint8List k) {
    if (d < 32) {
      throw 'SecretBox is invalid';
    }

    crypto_stream_xor(c, 0, m, 0, d, n, k);
    _crypto_onetimeauth(c, 16, c, 32, d - 32, c);

    // FIXME: Check in tweetnacl where these 16 bytes disappear?
    //for (i = 0; i < 16; i++) c[i] = 0;
    return c.sublist(16);
  }

  static Uint8List crypto_secretbox_open(
      Uint8List m, Uint8List c, final int d, Uint8List n, Uint8List k) {
    final x = Uint8List(32);
    if (d < 32) {
      throw 'The encrypted message must be at least 32-byte long';
    }

    crypto_stream(x, 0, 32, n, k);

    // NOTE: the hash offset is zero instead of 16
    if (_crypto_onetimeauth_verify(c, 16, c, 32, d - 32, x) != 0) {
      throw 'The message is forged or malformed or the shared secret is invalid';
      //return -1;
    }
    crypto_stream_xor(m, 0, c, 0, d, n, k);

    ///for (i = 0; i < 32; i++) m[i] = 0;
    // FIXME: Check in tweetnacl where these 32 bytes disappear?
    return m.sublist(32);
  }

  static void _set25519(Int32List r, Int32List a) {
    int i;

    for (i = 0; i < 16; i++) {
      r[i] = a[i];
    }
  }

// FIXME: no carry required
  static void _car25519(Int32List o) {
    int i;
    int v, c = 1;

    for (i = 0; i < 16; i++) {
      v = o[i] + c + 0xffff;
      c = v ~/ 0x10000;
      o[i] = v - c * 0x10000;
    }

    o[0] += c - 1 + 37 * (c - 1);
  }

  static void _sel25519(Int32List p, Int32List q, int b) {
    _sel25519_off(p, 0, q, 0, b);
  }

  static void _sel25519_off(
      Int32List p, final int poff, Int32List q, final int qoff, final int b) {
    int t, c = ~(b - 1);

    for (var i = 0; i < 16; i++) {
      t = c & (p[i + poff] ^ q[i + qoff]);
      p[i + poff] = p[i + poff] ^ t;
      q[i + qoff] = q[i + qoff] ^ t;
    }
  }

  static void _pack25519(Uint8List o, Int32List n, final int noff) {
    final m = Int32List(16), t = Int32List(16);

    for (var i = 0; i < 16; i++) {
      t[i] = n[i + noff];
    }

    _car25519(t);
    _car25519(t);
    _car25519(t);

    for (var j = 0; j < 2; j++) {
      m[0] = t[0] - 0xffed;

      for (var i = 1; i < 15; i++) {
        m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
        m[i - 1] &= 0xffff;
      }

      m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);

      final b = ((m[15] >> 16) & 1);
      m[14] &= 0xffff;
      _sel25519_off(t, 0, m, 0, 1 - b);
    }

    for (var i = 0; i < 16; i++) {
      o[2 * i] = t[i] & 0xff;
      o[2 * i + 1] = (t[i] >> 8);
    }
  }

  static int _neq25519(Int32List a, Int32List b) {
    return _neq25519_off(a, 0, b, 0);
  }

  static int _neq25519_off(
      Int32List a, final int aoff, Int32List b, final int boff) {
    final c = Uint8List(32), d = Uint8List(32);

    _pack25519(c, a, aoff);
    _pack25519(d, b, boff);

    return _crypto_verify_32(c, 0, d, 0);
  }

  static int _par25519(Int32List a) {
    return _par25519_off(a, 0);
  }

  static int _par25519_off(Int32List a, final int aoff) {
    final d = Uint8List(32);

    _pack25519(d, a, aoff);

    return (d[0] & 1);
  }

  static void _unpack25519(Int32List o, Uint8List n) {
    int i;

    for (i = 0; i < 16; i++) {
      o[i] = (n[2 * i] & 0xff) + (((n[2 * i + 1] << 8) & 0xffff));
    }

    o[15] &= 0x7fff;
  }

  static void _A(Int32List o, Int32List a, Int32List b) {
    _A_off(o, 0, a, 0, b, 0);
  }

  static void _A_off(Int32List o, final int ooff, Int32List a, final int aoff,
      Int32List b, final int boff) {
    int i;

    for (i = 0; i < 16; i++) {
      o[i + ooff] = a[i + aoff] + b[i + boff];
    }
  }

  static void _Z(Int32List o, Int32List a, Int32List b) {
    _Z_off(o, 0, a, 0, b, 0);
  }

  static void _Z_off(Int32List o, final int ooff, Int32List a, final int aoff,
      Int32List b, final int boff) {
    int i;
    for (i = 0; i < 16; i++) {
      o[i + ooff] = a[i + aoff] - b[i + boff];
    }
  }

  static void _M(Int32List o, Int32List a, Int32List b) {
    _M_off(o, 0, a, 0, b, 0);
  }

  ///
  /// It Calculates the `(a * b) mod (2^256 - 38)` instead of the `2^255-19`.
  /// The reason is explained in the following paper

  /// Reference:
  /// High-speed Curve25519 on 8-bit, 16-bit, and 32-bit microcontrollers
  /// https://link.springer.com/article/10.1007/s10623-015-0087-1
  static void _M_off(Int32List o, final int ooff, Int32List a, final int aoff,
      Int32List b, final int boff) {
    var t0 = 0,
        t1 = 0,
        t2 = 0,
        t3 = 0,
        t4 = 0,
        t5 = 0,
        t6 = 0,
        t7 = 0,
        t8 = 0,
        t9 = 0,
        t10 = 0,
        t11 = 0,
        t12 = 0,
        t13 = 0,
        t14 = 0,
        t15 = 0,
        t16 = 0,
        t17 = 0,
        t18 = 0,
        t19 = 0,
        t20 = 0,
        t21 = 0,
        t22 = 0,
        t23 = 0,
        t24 = 0,
        t25 = 0,
        t26 = 0,
        t27 = 0,
        t28 = 0,
        t29 = 0,
        t30 = 0,
        b0 = b[0 + boff],
        b1 = b[1 + boff],
        b2 = b[2 + boff],
        b3 = b[3 + boff],
        b4 = b[4 + boff],
        b5 = b[5 + boff],
        b6 = b[6 + boff],
        b7 = b[7 + boff],
        b8 = b[8 + boff],
        b9 = b[9 + boff],
        b10 = b[10 + boff],
        b11 = b[11 + boff],
        b12 = b[12 + boff],
        b13 = b[13 + boff],
        b14 = b[14 + boff],
        b15 = b[15 + boff];

    var v = a[0 + aoff];

    t0 += v * b0;
    t1 += v * b1;
    t2 += v * b2;
    t3 += v * b3;
    t4 += v * b4;
    t5 += v * b5;
    t6 += v * b6;
    t7 += v * b7;
    t8 += v * b8;
    t9 += v * b9;
    t10 += v * b10;
    t11 += v * b11;
    t12 += v * b12;
    t13 += v * b13;
    t14 += v * b14;
    t15 += v * b15;

    v = a[1 + aoff];

    t1 += v * b0;
    t2 += v * b1;
    t3 += v * b2;
    t4 += v * b3;
    t5 += v * b4;
    t6 += v * b5;
    t7 += v * b6;
    t8 += v * b7;
    t9 += v * b8;
    t10 += v * b9;
    t11 += v * b10;
    t12 += v * b11;
    t13 += v * b12;
    t14 += v * b13;
    t15 += v * b14;
    t16 += v * b15;

    v = a[2 + aoff];

    t2 += v * b0;
    t3 += v * b1;
    t4 += v * b2;
    t5 += v * b3;
    t6 += v * b4;
    t7 += v * b5;
    t8 += v * b6;
    t9 += v * b7;
    t10 += v * b8;
    t11 += v * b9;
    t12 += v * b10;
    t13 += v * b11;
    t14 += v * b12;
    t15 += v * b13;
    t16 += v * b14;
    t17 += v * b15;

    v = a[3 + aoff];

    t3 += v * b0;
    t4 += v * b1;
    t5 += v * b2;
    t6 += v * b3;
    t7 += v * b4;
    t8 += v * b5;
    t9 += v * b6;
    t10 += v * b7;
    t11 += v * b8;
    t12 += v * b9;
    t13 += v * b10;
    t14 += v * b11;
    t15 += v * b12;
    t16 += v * b13;
    t17 += v * b14;
    t18 += v * b15;

    v = a[4 + aoff];

    t4 += v * b0;
    t5 += v * b1;
    t6 += v * b2;
    t7 += v * b3;
    t8 += v * b4;
    t9 += v * b5;
    t10 += v * b6;
    t11 += v * b7;
    t12 += v * b8;
    t13 += v * b9;
    t14 += v * b10;
    t15 += v * b11;
    t16 += v * b12;
    t17 += v * b13;
    t18 += v * b14;
    t19 += v * b15;

    v = a[5 + aoff];

    t5 += v * b0;
    t6 += v * b1;
    t7 += v * b2;
    t8 += v * b3;
    t9 += v * b4;
    t10 += v * b5;
    t11 += v * b6;
    t12 += v * b7;
    t13 += v * b8;
    t14 += v * b9;
    t15 += v * b10;
    t16 += v * b11;
    t17 += v * b12;
    t18 += v * b13;
    t19 += v * b14;
    t20 += v * b15;

    v = a[6 + aoff];

    t6 += v * b0;
    t7 += v * b1;
    t8 += v * b2;
    t9 += v * b3;
    t10 += v * b4;
    t11 += v * b5;
    t12 += v * b6;
    t13 += v * b7;
    t14 += v * b8;
    t15 += v * b9;
    t16 += v * b10;
    t17 += v * b11;
    t18 += v * b12;
    t19 += v * b13;
    t20 += v * b14;
    t21 += v * b15;

    v = a[7 + aoff];

    t7 += v * b0;
    t8 += v * b1;
    t9 += v * b2;
    t10 += v * b3;
    t11 += v * b4;
    t12 += v * b5;
    t13 += v * b6;
    t14 += v * b7;
    t15 += v * b8;
    t16 += v * b9;
    t17 += v * b10;
    t18 += v * b11;
    t19 += v * b12;
    t20 += v * b13;
    t21 += v * b14;
    t22 += v * b15;

    v = a[8 + aoff];

    t8 += v * b0;
    t9 += v * b1;
    t10 += v * b2;
    t11 += v * b3;
    t12 += v * b4;
    t13 += v * b5;
    t14 += v * b6;
    t15 += v * b7;
    t16 += v * b8;
    t17 += v * b9;
    t18 += v * b10;
    t19 += v * b11;
    t20 += v * b12;
    t21 += v * b13;
    t22 += v * b14;
    t23 += v * b15;

    v = a[9 + aoff];

    t9 += v * b0;
    t10 += v * b1;
    t11 += v * b2;
    t12 += v * b3;
    t13 += v * b4;
    t14 += v * b5;
    t15 += v * b6;
    t16 += v * b7;
    t17 += v * b8;
    t18 += v * b9;
    t19 += v * b10;
    t20 += v * b11;
    t21 += v * b12;
    t22 += v * b13;
    t23 += v * b14;
    t24 += v * b15;

    v = a[10 + aoff];

    t10 += v * b0;
    t11 += v * b1;
    t12 += v * b2;
    t13 += v * b3;
    t14 += v * b4;
    t15 += v * b5;
    t16 += v * b6;
    t17 += v * b7;
    t18 += v * b8;
    t19 += v * b9;
    t20 += v * b10;
    t21 += v * b11;
    t22 += v * b12;
    t23 += v * b13;
    t24 += v * b14;
    t25 += v * b15;

    v = a[11 + aoff];

    t11 += v * b0;
    t12 += v * b1;
    t13 += v * b2;
    t14 += v * b3;
    t15 += v * b4;
    t16 += v * b5;
    t17 += v * b6;
    t18 += v * b7;
    t19 += v * b8;
    t20 += v * b9;
    t21 += v * b10;
    t22 += v * b11;
    t23 += v * b12;
    t24 += v * b13;
    t25 += v * b14;
    t26 += v * b15;

    v = a[12 + aoff];

    t12 += v * b0;
    t13 += v * b1;
    t14 += v * b2;
    t15 += v * b3;
    t16 += v * b4;
    t17 += v * b5;
    t18 += v * b6;
    t19 += v * b7;
    t20 += v * b8;
    t21 += v * b9;
    t22 += v * b10;
    t23 += v * b11;
    t24 += v * b12;
    t25 += v * b13;
    t26 += v * b14;
    t27 += v * b15;

    v = a[13 + aoff];

    t13 += v * b0;
    t14 += v * b1;
    t15 += v * b2;
    t16 += v * b3;
    t17 += v * b4;
    t18 += v * b5;
    t19 += v * b6;
    t20 += v * b7;
    t21 += v * b8;
    t22 += v * b9;
    t23 += v * b10;
    t24 += v * b11;
    t25 += v * b12;
    t26 += v * b13;
    t27 += v * b14;
    t28 += v * b15;

    v = a[14 + aoff];

    t14 += v * b0;
    t15 += v * b1;
    t16 += v * b2;
    t17 += v * b3;
    t18 += v * b4;
    t19 += v * b5;
    t20 += v * b6;
    t21 += v * b7;
    t22 += v * b8;
    t23 += v * b9;
    t24 += v * b10;
    t25 += v * b11;
    t26 += v * b12;
    t27 += v * b13;
    t28 += v * b14;
    t29 += v * b15;

    v = a[15 + aoff];

    t15 += v * b0;
    t16 += v * b1;
    t17 += v * b2;
    t18 += v * b3;
    t19 += v * b4;
    t20 += v * b5;
    t21 += v * b6;
    t22 += v * b7;
    t23 += v * b8;
    t24 += v * b9;
    t25 += v * b10;
    t26 += v * b11;
    t27 += v * b12;
    t28 += v * b13;
    t29 += v * b14;
    t30 += v * b15;

    t0 += 38 * t16;
    t1 += 38 * t17;
    t2 += 38 * t18;
    t3 += 38 * t19;
    t4 += 38 * t20;
    t5 += 38 * t21;
    t6 += 38 * t22;
    t7 += 38 * t23;
    t8 += 38 * t24;
    t9 += 38 * t25;
    t10 += 38 * t26;
    t11 += 38 * t27;
    t12 += 38 * t28;
    t13 += 38 * t29;
    t14 += 38 * t30;

    var c = 1;
    v = t0 + c + 0xffff;
    c = v ~/ 0x10000;
    t0 = v - c * 0x10000;
    v = t1 + c + 0xffff;
    c = v ~/ 0x10000;
    t1 = v - c * 0x10000;
    v = t2 + c + 0xffff;
    c = v ~/ 0x10000;
    t2 = v - c * 0x10000;
    v = t3 + c + 0xffff;
    c = v ~/ 0x10000;
    t3 = v - c * 0x10000;
    v = t4 + c + 0xffff;
    c = v ~/ 0x10000;
    t4 = v - c * 0x10000;
    v = t5 + c + 0xffff;
    c = v ~/ 0x10000;
    t5 = v - c * 0x10000;
    v = t6 + c + 0xffff;
    c = v ~/ 0x10000;
    t6 = v - c * 0x10000;
    v = t7 + c + 0xffff;
    c = v ~/ 0x10000;
    t7 = v - c * 0x10000;
    v = t8 + c + 0xffff;
    c = v ~/ 0x10000;
    t8 = v - c * 0x10000;
    v = t9 + c + 0xffff;
    c = v ~/ 0x10000;
    t9 = v - c * 0x10000;
    v = t10 + c + 0xffff;
    c = v ~/ 0x10000;
    t10 = v - c * 0x10000;
    v = t11 + c + 0xffff;
    c = v ~/ 0x10000;
    t11 = v - c * 0x10000;
    v = t12 + c + 0xffff;
    c = v ~/ 0x10000;
    t12 = v - c * 0x10000;
    v = t13 + c + 0xffff;
    c = v ~/ 0x10000;
    t13 = v - c * 0x10000;
    v = t14 + c + 0xffff;
    c = v ~/ 0x10000;
    t14 = v - c * 0x10000;
    v = t15 + c + 0xffff;
    c = v ~/ 0x10000;
    t15 = v - c * 0x10000;
    t0 += 38 * (c - 1);

    c = 1;
    v = t0 + c + 0xffff;
    c = v ~/ 0x10000;
    t0 = v - c * 0x10000;
    v = t1 + c + 0xffff;
    c = v ~/ 0x10000;
    t1 = v - c * 0x10000;
    v = t2 + c + 0xffff;
    c = v ~/ 0x10000;
    t2 = v - c * 0x10000;
    v = t3 + c + 0xffff;
    c = v ~/ 0x10000;
    t3 = v - c * 0x10000;
    v = t4 + c + 0xffff;
    c = v ~/ 0x10000;
    t4 = v - c * 0x10000;
    v = t5 + c + 0xffff;
    c = v ~/ 0x10000;
    t5 = v - c * 0x10000;
    v = t6 + c + 0xffff;
    c = v ~/ 0x10000;
    t6 = v - c * 0x10000;
    v = t7 + c + 0xffff;
    c = v ~/ 0x10000;
    t7 = v - c * 0x10000;
    v = t8 + c + 0xffff;
    c = v ~/ 0x10000;
    t8 = v - c * 0x10000;
    v = t9 + c + 0xffff;
    c = v ~/ 0x10000;
    t9 = v - c * 0x10000;
    v = t10 + c + 0xffff;
    c = v ~/ 0x10000;
    t10 = v - c * 0x10000;
    v = t11 + c + 0xffff;
    c = v ~/ 0x10000;
    t11 = v - c * 0x10000;
    v = t12 + c + 0xffff;
    c = v ~/ 0x10000;
    t12 = v - c * 0x10000;
    v = t13 + c + 0xffff;
    c = v ~/ 0x10000;
    t13 = v - c * 0x10000;
    v = t14 + c + 0xffff;
    c = v ~/ 0x10000;
    t14 = v - c * 0x10000;
    v = t15 + c + 0xffff;
    c = v ~/ 0x10000;
    t15 = v - c * 0x10000;
    t0 += 38 * (c - 1);

    o[0 + ooff] = t0;
    o[1 + ooff] = t1;
    o[2 + ooff] = t2;
    o[3 + ooff] = t3;
    o[4 + ooff] = t4;
    o[5 + ooff] = t5;
    o[6 + ooff] = t6;
    o[7 + ooff] = t7;
    o[8 + ooff] = t8;
    o[9 + ooff] = t9;
    o[10 + ooff] = t10;
    o[11 + ooff] = t11;
    o[12 + ooff] = t12;
    o[13 + ooff] = t13;
    o[14 + ooff] = t14;
    o[15 + ooff] = t15;
  }

  static void _S(Int32List o, Int32List a) {
    _S_off(o, 0, a, 0);
  }

  static void _S_off(Int32List o, final int ooff, Int32List a, final int aoff) {
    _M_off(o, ooff, a, aoff, a, aoff);
  }

  static void _inv25519(
      Int32List o, final int ooff, Int32List i, final int ioff) {
    final c = Int32List(16);

    int a;
    for (a = 0; a < 16; a++) {
      c[a] = i[a + ioff];
    }
    for (a = 253; a >= 0; a--) {
      _S_off(c, 0, c, 0);
      if (a != 2 && a != 4) _M_off(c, 0, c, 0, i, ioff);
    }
    for (a = 0; a < 16; a++) {
      o[a + ooff] = c[a];
    }
  }

  static void _pow2523(Int32List o, Int32List i) {
    final c = Int32List(16);

    int a;

    for (a = 0; a < 16; a++) {
      c[a] = i[a];
    }

    for (a = 250; a >= 0; a--) {
      _S_off(c, 0, c, 0);
      if (a != 1) _M_off(c, 0, c, 0, i, 0);
    }

    for (a = 0; a < 16; a++) {
      o[a] = c[a];
    }
  }

  static Uint8List crypto_scalarmult(Uint8List q, Uint8List n, Uint8List p) {
    final z = Int8List(32);
    final x = Int32List(80);
    int r, i;
    final a = Int32List(16),
        b = Int32List(16),
        c = Int32List(16),
        d = Int32List(16),
        e = Int32List(16),
        f = Int32List(16);

    for (i = 0; i < 31; i++) {
      z[i] = n[i];
    }

    z[31] = (n[31] & 127) | 64;
    z[0] &= 248;

    _unpack25519(x, Uint8List.fromList(p));

    for (i = 0; i < 16; i++) {
      b[i] = x[i];
      d[i] = a[i] = c[i] = 0;
    }

    a[0] = d[0] = 1;

    for (i = 254; i >= 0; --i) {
      r = (z[i >> 3] >> (i & 7)) & 1;

      _sel25519(a, b, r);
      _sel25519(c, d, r);
      _A(e, a, c);
      _Z(a, a, c);
      _A(c, b, d);
      _Z(b, b, d);
      _S(d, e);
      _S(f, a);
      _M(a, c, a);
      _M(c, b, e);
      _A(e, a, c);
      _Z(a, a, c);
      _S(b, a);
      _Z(c, d, f);
      _M(a, c, _121665);
      _A(a, a, d);
      _M(c, c, a);
      _M(a, d, f);
      _M(d, b, x);
      _S(b, e);
      _sel25519(a, b, r);
      _sel25519(c, d, r);
    }

    for (i = 0; i < 16; i++) {
      x[i + 16] = a[i];
      x[i + 32] = c[i];
      x[i + 48] = b[i];
      x[i + 64] = d[i];
    }

    _inv25519(x, 32, x, 32);
    _M_off(x, 16, x, 16, x, 32);
    _pack25519(q, x, 16);

    return q;
  }

  static Uint8List crypto_scalarmult_base(Uint8List q, Uint8List n) {
    return crypto_scalarmult(q, n, _9);
  }

  static Uint8List crypto_box_keypair(Uint8List y, Uint8List x) {
    x = _randombytes_array(x);
    return crypto_scalarmult_base(y, x);
  }

  static Uint8List crypto_box_beforenm(Uint8List k, Uint8List y, Uint8List x) {
    final s = Uint8List(32);
    crypto_scalarmult(s, x, y);

    final res = crypto_core_hsalsa20(k, _0, s, _sigma);
    return res;
  }

  static Uint8List crypto_box_afternm(
      Uint8List c, Uint8List m, int /*long*/ d, Uint8List n, Uint8List k) {
    return crypto_secretbox(c, m, d, n, k);
  }

  static Uint8List crypto_box_open_afternm(
      Uint8List m, Uint8List c, int /*long*/ d, Uint8List n, Uint8List k) {
    return crypto_secretbox_open(m, c, d, n, k);
  }

  static Uint8List crypto_box(Uint8List c, Uint8List m, int /*long*/ d,
      Uint8List n, Uint8List y, Uint8List x) {
    final k = Uint8List(32);

    crypto_box_beforenm(k, y, x);

    return crypto_box_afternm(c, m, d, n, k);
  }

  static Uint8List crypto_box_open(Uint8List m, Uint8List c, int /*long*/ d,
      Uint8List n, Uint8List y, Uint8List x) {
    final k = Uint8List(32);

    crypto_box_beforenm(k, y, x);

    return crypto_box_open_afternm(m, c, d, n, k);
  }

  static const _K = <int>[
    0x428a2f98, 0xd728ae22, // 0-2
    0x71374491, 0x23ef65cd,
    0xb5c0fbcf, 0xec4d3b2f,
    0xe9b5dba5, 0x8189dbbc,
    0x3956c25b, 0xf348b538,
    0x59f111f1, 0xb605d019,
    0x923f82a4, 0xaf194f9b,
    0xab1c5ed5, 0xda6d8118,
    0xd807aa98, 0xa3030242,
    0x12835b01, 0x45706fbe,
    0x243185be, 0x4ee4b28c,
    0x550c7dc3, 0xd5ffb4e2,
    0x72be5d74, 0xf27b896f,
    0x80deb1fe, 0x3b1696b1,
    0x9bdc06a7, 0x25c71235,
    0xc19bf174, 0xcf692694,
    0xe49b69c1, 0x9ef14ad2,
    0xefbe4786, 0x384f25e3,
    0x0fc19dc6, 0x8b8cd5b5,
    0x240ca1cc, 0x77ac9c65,
    0x2de92c6f, 0x592b0275,
    0x4a7484aa, 0x6ea6e483,
    0x5cb0a9dc, 0xbd41fbd4,
    0x76f988da, 0x831153b5,
    0x983e5152, 0xee66dfab,
    0xa831c66d, 0x2db43210,
    0xb00327c8, 0x98fb213f,
    0xbf597fc7, 0xbeef0ee4,
    0xc6e00bf3, 0x3da88fc2,
    0xd5a79147, 0x930aa725,
    0x06ca6351, 0xe003826f,
    0x14292967, 0x0a0e6e70,
    0x27b70a85, 0x46d22ffc,
    0x2e1b2138, 0x5c26c926,
    0x4d2c6dfc, 0x5ac42aed,
    0x53380d13, 0x9d95b3df,
    0x650a7354, 0x8baf63de,
    0x766a0abb, 0x3c77b2a8,
    0x81c2c92e, 0x47edaee6,
    0x92722c85, 0x1482353b,
    0xa2bfe8a1, 0x4cf10364,
    0xa81a664b, 0xbc423001,
    0xc24b8b70, 0xd0f89791,
    0xc76c51a3, 0x0654be30,
    0xd192e819, 0xd6ef5218,
    0xd6990624, 0x5565a910,
    0xf40e3585, 0x5771202a,
    0x106aa070, 0x32bbd1b8,
    0x19a4c116, 0xb8d2d0c8,
    0x1e376c08, 0x5141ab53,
    0x2748774c, 0xdf8eeb99,
    0x34b0bcb5, 0xe19b48a8,
    0x391c0cb3, 0xc5c95a63,
    0x4ed8aa4a, 0xe3418acb,
    0x5b9cca4f, 0x7763e373,
    0x682e6ff3, 0xd6b2b8a3,
    0x748f82ee, 0x5defb2fc,
    0x78a5636f, 0x43172f60,
    0x84c87814, 0xa1f0ab72,
    0x8cc70208, 0x1a6439ec,
    0x90befffa, 0x23631e28,
    0xa4506ceb, 0xde82bde9,
    0xbef9a3f7, 0xb2c67915,
    0xc67178f2, 0xe372532b,
    0xca273ece, 0xea26619c,
    0xd186b8c7, 0x21c0c207,
    0xeada7dd6, 0xcde0eb1e,
    0xf57d4f7f, 0xee6ed178,
    0x06f067aa, 0x72176fba,
    0x0a637dc5, 0xa2c898a6,
    0x113f9804, 0xbef90dae,
    0x1b710b35, 0x131c471b,
    0x28db77f5, 0x23047d84,
    0x32caab7b, 0x40c72493,
    0x3c9ebe0a, 0x15c9bebc,
    0x431d67c4, 0x9c100d4c,
    0x4cc5d4be, 0xcb3e42b6,
    0x597f299c, 0xfc657e2a,
    0x5fcb6fab, 0x3ad6faec,
    0x6c44198c, 0x4a475817
  ];

  static int _rotr32(int x, int y, int n) => _shr32(x, n) | y << (32 - n);
  static int _shr32(int x, int n) => (x & 0xffffffff) >> n;
  static int _ch32(int x, int y, int z) => (x & y) ^ (~x & z);
  static int _maj32(int x, int y, int z) => (x & y) ^ (x & z) ^ (y & z);
  static int _sigma0(int h, int l) =>
      (_rotr32(h, l, 28) ^ _rotr32(l, h, 34 - 32) ^ _rotr32(l, h, 39 - 32));
  static int _sigma1(int h, int l) =>
      (_rotr32(h, l, 14) ^ _rotr32(h, l, 18) ^ _rotr32(l, h, 41 - 32));
  static int _gamma0h(int h, int l) =>
      (_rotr32(h, l, 1) ^ _rotr32(h, l, 8) ^ _shr32(h, 7));
  static int _gamma0l(int h, int l) =>
      (_rotr32(h, l, 1) ^ _rotr32(h, l, 8) ^ _rotr32(h, l, 7));
  static int _gamma1h(int h, int l) =>
      (_rotr32(h, l, 19) ^ _rotr32(l, h, 61 - 32) ^ _shr32(h, 6));
  static int _gamma1l(int h, int l) =>
      (_rotr32(h, l, 19) ^ _rotr32(l, h, 61 - 32) ^ _rotr32(h, l, 6));

  static void _initAdd64(Uint32List out, Uint32List a, int aoff) {
    out[0] = a[aoff + 1] & 0xffff;
    out[1] = a[aoff + 1] >> 16;
    out[2] = a[aoff] & 0xffff;
    out[3] = a[aoff] >> 16;
  }

  static void _updateAdd64(Uint32List out, int h, int l) {
    out[0] += l & 0xffff;
    out[1] += (l & 0xffffffff) >> 16;
    out[2] += h & 0xffff;
    out[3] += (h & 0xffffffff) >> 16;
  }

  static void _finalizeAdd64(Uint32List out, int ooff, Uint32List ins) {
    ins[1] += ins[0] >> 16;
    ins[2] += ins[1] >> 16;
    ins[3] += ins[2] >> 16;
    out[ooff] = ins[2] & 0xffff | ins[3] << 16;
    out[ooff + 1] = ins[0] & 0xffff | ins[1] << 16;
  }

  /// Though the maximum SHA-512 message length is 2^128,
  ///  we set it to
  /// the maximum 2^53-1 for javascript compatibility.
  ///
  /// TODO: It should be tested whether it works or not.
  static void crypto_hashblocks_hl(
      Uint32List iv, Uint8List m, final int moff, int n) {
    const iteration = 80;

    final w = Uint32List(iteration * 2);

    final a = Uint32List(2),
        b = Uint32List(2),
        c = Uint32List(2),
        d = Uint32List(2),
        e = Uint32List(2),
        f = Uint32List(2),
        g = Uint32List(2),
        h = Uint32List(2),
        T1 = Uint32List(2),
        T2 = Uint32List(2),
        partial = Uint32List(4);

    var i = 0, j = 0, s0h = 0, s0l = 0, s1h = 0, s1l = 0, pos = 0;

    while (n >= 128) {
      a[0] = iv[0];
      b[0] = iv[2];
      c[0] = iv[4];
      d[0] = iv[6];
      e[0] = iv[8];
      f[0] = iv[10];
      g[0] = iv[12];
      h[0] = iv[14];
      a[1] = iv[1];
      b[1] = iv[3];
      c[1] = iv[5];
      d[1] = iv[7];
      e[1] = iv[9];
      f[1] = iv[11];
      g[1] = iv[13];
      h[1] = iv[15];

      for (j = 0; j < iteration; j++) {
        if (j < 16) {
          i = (j << 3) + pos + moff;

          w[j * 2] =
              (m[i + 0] << 24) | (m[i + 1] << 16) | (m[i + 2] << 8) | m[i + 3];
          w[j * 2 + 1] =
              (m[i + 4] << 24) | (m[i + 5] << 16) | (m[i + 6] << 8) | m[i + 7];
        } else {
          s0h = _gamma0h(w[(j - 15) * 2], w[(j - 15) * 2 + 1]);
          s0l = _gamma0l(w[(j - 15) * 2 + 1], w[(j - 15) * 2]);
          s1h = _gamma1h(w[(j - 2) * 2], w[(j - 2) * 2 + 1]);
          s1l = _gamma1l(w[(j - 2) * 2 + 1], w[(j - 2) * 2]);

          _initAdd64(partial, w, (j - 16) * 2);
          _updateAdd64(partial, s0h, s0l);
          _updateAdd64(partial, s1h, s1l);
          _updateAdd64(partial, w[(j - 7) * 2], w[(j - 7) * 2 + 1]);
          _finalizeAdd64(w, j * 2, partial);
        }

        _initAdd64(partial, h, 0);
        _updateAdd64(partial, _sigma1(e[0], e[1]), _sigma1(e[1], e[0]));
        _updateAdd64(partial, _ch32(e[0], f[0], g[0]), _ch32(e[1], f[1], g[1]));
        _updateAdd64(partial, _K[j * 2], _K[j * 2 + 1]);
        _updateAdd64(partial, w[j * 2], w[j * 2 + 1]);
        _finalizeAdd64(T1, 0, partial);

        _initAdd64(partial, T1, 0);
        _updateAdd64(partial, _sigma0(a[0], a[1]), _sigma0(a[1], a[0]));
        _updateAdd64(
            partial, _maj32(a[0], b[0], c[0]), _maj32(a[1], b[1], c[1]));
        _finalizeAdd64(T2, 0, partial);

        h[0] = g[0];
        h[1] = g[1];
        g[0] = f[0];
        g[1] = f[1];
        f[0] = e[0];
        f[1] = e[1];

        _initAdd64(partial, d, 0);
        _updateAdd64(partial, T1[0], T1[1]);
        _finalizeAdd64(e, 0, partial);

        d[0] = c[0];
        d[1] = c[1];
        c[0] = b[0];
        c[1] = b[1];
        b[0] = a[0];
        b[1] = a[1];
        a[0] = T2[0];
        a[1] = T2[1];
      }
      _initAdd64(partial, iv, 0);
      _updateAdd64(partial, a[0], a[1]);
      _finalizeAdd64(iv, 0, partial);

      _initAdd64(partial, iv, 2);
      _updateAdd64(partial, b[0], b[1]);
      _finalizeAdd64(iv, 2, partial);

      _initAdd64(partial, iv, 4);
      _updateAdd64(partial, c[0], c[1]);
      _finalizeAdd64(iv, 4, partial);

      _initAdd64(partial, iv, 6);
      _updateAdd64(partial, d[0], d[1]);
      _finalizeAdd64(iv, 6, partial);

      _initAdd64(partial, iv, 8);
      _updateAdd64(partial, e[0], e[1]);
      _finalizeAdd64(iv, 8, partial);

      _initAdd64(partial, iv, 10);
      _updateAdd64(partial, f[0], f[1]);
      _finalizeAdd64(iv, 10, partial);

      _initAdd64(partial, iv, 12);
      _updateAdd64(partial, g[0], g[1]);
      _finalizeAdd64(iv, 12, partial);

      _initAdd64(partial, iv, 14);
      _updateAdd64(partial, h[0], h[1]);
      _finalizeAdd64(iv, 14, partial);

      pos += 128;
      n -= 128;
    }
  }

  static int _crypto_hash_off(Uint8List out, Uint8List m, int moff, int n) {
    final x = Uint8List(256);
    int i;
    final b = n;

    final iv = Uint32List.fromList([
      0x6a09e667, 0xf3bcc908, // 0-2
      0xbb67ae85, 0x84caa73b,
      0x3c6ef372, 0xfe94f82b,
      0xa54ff53a, 0x5f1d36f1,
      0x510e527f, 0xade682d1,
      0x9b05688c, 0x2b3e6c1f,
      0x1f83d9ab, 0xfb41bd6b,
      0x5be0cd19, 0x137e2179
    ]);

    if (n >= 128) {
      crypto_hashblocks_hl(iv, m, moff, n);
      n %= 128;
    }

    for (i = 0; i < n; i++) {
      x[i] = m[b - n + i + moff];
    }
    x[n] = 128;

    n = 256 - 128 * (n < 112 ? 1 : 0);
    x[n - 9] = 0;

    _ts64(x, n - 8, b ~/ 0x20000000, b << 3);

    crypto_hashblocks_hl(iv, x, 0, n);

    for (i = 0; i < 8; i++) {
      _ts64(out, 8 * i, iv[i * 2], iv[i * 2 + 1]);
    }

    return 0;
  }

  static int crypto_hash(Uint8List out, Uint8List m) {
    return _crypto_hash_off(out, m, 0, m.length);
  }

  static void _add(List<Int32List> p, List<Int32List> q) {
    final a = Int32List(16);
    final b = Int32List(16);
    final c = Int32List(16);
    final d = Int32List(16);
    final t = Int32List(16);
    final e = Int32List(16);
    final f = Int32List(16);
    final g = Int32List(16);
    final h = Int32List(16);

    final p0 = p[0];
    final p1 = p[1];
    final p2 = p[2];
    final p3 = p[3];

    final q0 = q[0];
    final q1 = q[1];
    final q2 = q[2];
    final q3 = q[3];

    _Z_off(a, 0, p1, 0, p0, 0);
    _Z_off(t, 0, q1, 0, q0, 0);
    _M_off(a, 0, a, 0, t, 0);
    _A_off(b, 0, p0, 0, p1, 0);
    _A_off(t, 0, q0, 0, q1, 0);
    _M_off(b, 0, b, 0, t, 0);
    _M_off(c, 0, p3, 0, q3, 0);
    _M_off(c, 0, c, 0, _D2, 0);
    _M_off(d, 0, p2, 0, q2, 0);

    _A_off(d, 0, d, 0, d, 0);
    _Z_off(e, 0, b, 0, a, 0);
    _Z_off(f, 0, d, 0, c, 0);
    _A_off(g, 0, d, 0, c, 0);
    _A_off(h, 0, b, 0, a, 0);

    _M_off(p0, 0, e, 0, f, 0);
    _M_off(p1, 0, h, 0, g, 0);
    _M_off(p2, 0, g, 0, f, 0);
    _M_off(p3, 0, e, 0, h, 0);
  }

  static void _cswap(List<Int32List> p, List<Int32List> q, int b) {
    for (var i = 0; i < 4; i++) {
      _sel25519_off(p[i], 0, q[i], 0, b);
    }
  }

  static void _pack(Uint8List r, List<Int32List> p) {
    final tx = Int32List(16);
    final ty = Int32List(16);
    final zi = Int32List(16);

    _inv25519(zi, 0, p[2], 0);

    _M_off(tx, 0, p[0], 0, zi, 0);
    _M_off(ty, 0, p[1], 0, zi, 0);

    _pack25519(r, ty, 0);

    r[31] ^= _par25519_off(tx, 0) << 7;
  }

  static void _scalarmult(
      List<Int32List> p, List<Int32List> q, Uint8List s, final int soff) {
    int i;

    _set25519(p[0], _gf0);
    _set25519(p[1], _gf1);
    _set25519(p[2], _gf1);
    _set25519(p[3], _gf0);

    for (i = 255; i >= 0; --i) {
      final b = _shr32(s[(i >> 3) + soff], i & 7) & 1;

      _cswap(p, q, b);
      _add(q, p);
      _add(p, p);
      _cswap(p, q, b);
    }
  }

  static void _scalarbase(List<Int32List> p, Uint8List s, final int soff) {
    final q = List<Int32List>.generate(4, (_) => Int32List(16));

    _set25519(q[0], _X);
    _set25519(q[1], _Y);
    _set25519(q[2], _gf1);
    _M_off(q[3], 0, _X, 0, _Y, 0);
    _scalarmult(p, q, s, soff);
  }

  ///
  /// The `crypto_sign_keypair` function randomly generates a secret key and a corresponding public key.
  /// It puts the secret key into `sk` and public key into `pk`.
  /// It returns 0 on success.
  ///
  static int crypto_sign_keypair(Uint8List pk, Uint8List sk, Uint8List seed) {
    final k = Uint8List(64);
    final p = List<Int32List>.generate(4, (_) => Int32List(16));

    _crypto_hash_off(k, seed, 0, 32);
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    _scalarbase(p, k, 0);
    _pack(pk, p);

    for (var i = 0; i < 32; i++) {
      sk[i] = seed[i];
    }
    for (var i = 0; i < 32; i++) {
      sk[i + 32] = pk[i];
    }

    for (var i = 0; i < 64; i++) {
      k[i] = 0;
    }
    return 0;
  }

  static const _L = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, //0-7
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0x10
  ];
  static void _modL(Uint8List r, final int roff, Int32List x) {
    int carry;
    int i, j;

    for (i = 63; i >= 32; --i) {
      carry = 0;
      for (j = i - 32; j < i - 12; ++j) {
        x[j] += carry - 16 * x[i] * _L[j - (i - 32)];
        carry = (x[j] + 128) >> 8;
        x[j] -= carry << 8;
      }
      x[j] += carry;
      x[i] = 0;
    }
    carry = 0;

    for (j = 0; j < 32; j++) {
      x[j] += carry - (x[31] >> 4) * _L[j];
      carry = x[j] >> 8;
      x[j] &= 255;
    }

    for (j = 0; j < 32; j++) {
      x[j] -= carry * _L[j];
    }

    for (i = 0; i < 32; i++) {
      x[i + 1] += x[i] >> 8;
      r[i + roff] = (x[i] & 255);
    }
  }

  static void _reduce(Uint8List r) {
    final x = Int32List(64);

    int i;

    for (i = 0; i < 64; i++) {
      x[i] = r[i];
    }

    for (i = 0; i < 64; i++) {
      r[i] = 0;
    }

    _modL(r, 0, x);
  }

  // TODO: 64-bit of `n`
  /// The crypto_sign interface expecting either
  /// - a standard Ed25519 seed
  /// - or an extended Ed25519 secret key (meaning already hashed and bits are/cleared and set).
  ///
  /// Note: Extended interface simply means that the corresponding 64-byte long private key is
  /// already hashed and its bits are cleared/set.
  ///
  /// The `crypto_sign` function signs a message `m` using the signer's secret
  /// key `sk`.
  ///
  /// The `crypto_sign` function returns the resulting signed message `sm`.
  ///
  /// The function raises an exception if
  ///  - sk (sk || pk) size is not 64 or
  ///  - sk (esk || pk) size is not 96 (extended).
  ///
  static int crypto_sign(Uint8List sm, int dummy /* *smlen not used*/,
      Uint8List m, final int moff, int n, Uint8List sk,
      {bool extended = false}) {
    final d = Uint8List(64), h = Uint8List(64), r = Uint8List(64);

    int i, j;

    final x = Int32List(64);
    final p = List<Int32List>.generate(4, (_) => Int32List(16));

    final pk_offset = extended ? 64 : 32;

    /// Added support for extended private keys (96 bytes long))
    /// Assuming 64 byte-length secret keys
    /// bits have already cleared and set
    if (extended) {
      for (i = 0; i < pk_offset; i++) {
        d[i] = sk[i];
      }
    } else {
      _crypto_hash_off(d, sk, 0, 32);
    }

    // when it's extended then we leave clear/set bit below only for safeness.
    // As we can assume that the 64-byte length
    // extended private key's bits have been already cleared and set.
    // TODO: throw exception if the above assumption is not met.
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    //*smlen = n+64;

    for (i = 0; i < n; i++) {
      sm[64 + i] = m[i + moff];
    }

    for (i = 0; i < 32; i++) {
      sm[32 + i] = d[32 + i];
    }

    _crypto_hash_off(r, sm, 32, n + 32);
    _reduce(r);
    _scalarbase(p, r, 0);
    _pack(sm, p);

    for (i = 0; i < 32; i++) {
      sm[i + 32] = sk[i + pk_offset];
    }
    _crypto_hash_off(h, sm, 0, n + 64);
    _reduce(h);

    for (i = 0; i < 64; i++) {
      x[i] = 0;
    }

    for (i = 0; i < 32; i++) {
      x[i] = r[i];
    }

    for (i = 0; i < 32; i++) {
      for (j = 0; j < 32; j++) {
        x[i + j] += h[i] * d[j];
      }
    }

    _modL(sm, 32, x);

    return 0;
  }

  static int _unpackneg(List<Int32List> r, Uint8List p) {
    final t = Int32List(16);
    final chk = Int32List(16);
    final inum = Int32List(16);
    final den = Int32List(16);
    final den2 = Int32List(16);
    final den4 = Int32List(16);
    final den6 = Int32List(16);

    _set25519(r[2], _gf1);
    _unpack25519(r[1], p);
    _S(inum, r[1]);
    _M(den, inum, Int32List.fromList(_D));
    _Z(inum, inum, r[2]);
    _A(den, r[2], den);

    _S(den2, den);
    _S(den4, den2);
    _M(den6, den4, den2);
    _M(t, den6, inum);
    _M(t, t, den);

    _pow2523(t, t);
    _M(t, t, inum);
    _M(t, t, den);
    _M(t, t, den);
    _M(r[0], t, den);

    _S(chk, r[0]);
    _M(chk, chk, den);
    if (_neq25519(chk, inum) != 0) _M(r[0], r[0], _I);

    _S(chk, r[0]);
    _M(chk, chk, den);
    if (_neq25519(chk, inum) != 0) return -1;

    if (_par25519(r[0]) == _shr32(p[31], 7)) {
      _Z(r[0], _gf0, r[0]);
    }

    _M(r[3], r[0], r[1]);

    return 0;
  }

  // TODO: fix 64-bit length mlen
  static int crypto_sign_open(Uint8List m, int dummy /* *mlen not used*/,
      Uint8List sm, final int smoff, int /*long*/ n, Uint8List pk) {
    int i;
    final t = Uint8List(32), h = Uint8List(64);
    final p = List<Int32List>.generate(4, (_) => Int32List(16));

    final q = List<Int32List>.generate(4, (_) => Int32List(16));

    ///*mlen = -1;

    if (n < 64) return -1;

    if (_unpackneg(q, pk) != 0) return -1;

    for (i = 0; i < n; i++) {
      m[i] = sm[i + smoff];
    }

    for (i = 0; i < 32; i++) {
      m[i + 32] = pk[i];
    }

    _crypto_hash_off(h, m, 0, n);

    _reduce(h);
    _scalarmult(p, q, h, 0);

    _scalarbase(q, sm, 32 + smoff);
    _add(p, q);
    _pack(t, p);

    n -= 64;
    if (_crypto_verify_32(sm, smoff, t, 0) != 0) {
      ///for (i = 0; i < n; i ++) m[i] = 0;
      return -1;
    }

    ///for (i = 0; i < n; i ++) m[i] = sm[i + 64 + smoff];
    ///*mlen = n;

    return 0;
  }

  // Generates a cryptographically secure random number and throws
  // error otherwise.
  static final _krandom = Random.secure();

  static Uint8List randombytes(int len) {
    return _randombytes_array(Uint8List(len));
  }

  static Uint8List _randombytes_array(Uint8List x) {
    var rnd = 0;

    for (var i = 0; i < x.length; i++) {
      final iter = i % 4;

      if (iter == 0) {
        // rnd is always a 32-bit positive integer.
        // from 1 to max 0x100000000 i.e. (1<<32).
        // replaced from (1 << 32) as when it compiled to js
        // it forces the bitwise operations only to 32-bits
        rnd = _krandom.nextInt(0x100000000);
      }

      x[i] = rnd >> (iter << 3);
    }

    return x;
  }
}
