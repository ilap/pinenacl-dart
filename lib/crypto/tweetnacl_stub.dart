library pinenacl.api.crypto.tweetnacl_stub;

import 'dart:core';
import 'dart:typed_data';

import 'package:fixnum/fixnum.dart';

part 'tweetnacl_stub_ext.dart';

class TweetNaCl {
  static const int keyLength = 32;

  static const int macBytes = 16;

  // Constants
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

  // Signature length
  static const int signatureLength = 64;

  static int crypto_verify_16(Uint8List x, Uint8List y) => 0;
  static int crypto_verify_32(Uint8List x, Uint8List y) => 0;

  static int crypto_core_salsa20(
          Uint8List out, List<int> input, Uint8List k, List<int> c) =>
      0;

  static Uint8List crypto_core_hsalsa20(
          Uint8List out, List<int> input, Uint8List k, List<int> c) =>
      Uint8List(0);

  static int crypto_stream_salsa20_xor(Uint8List c, int cpos, Uint8List m,
          int mpos, int b, Uint8List n, Uint8List k,
          [int ic = 0]) =>
      0;

  static int crypto_stream_salsa20(
          Uint8List c, int cpos, int b, Uint8List n, Uint8List k) =>
      0;

  static int crypto_stream(
          Uint8List c, int cpos, int d, Uint8List n, Uint8List k) =>
      0;

  static int crypto_stream_xor(Uint8List c, int cpos, Uint8List m, int mpos,
          int d, Uint8List n, Uint8List k) =>
      0;

  static int crypto_onetimeauth(
          Uint8List out, Uint8List m, int n, Uint8List k) =>
      0;

  static int crypto_onetimeauth_verify(Uint8List h, Uint8List m, Uint8List k) =>
      0;

  static Uint8List crypto_secretbox(
          Uint8List c, Uint8List m, int d, Uint8List n, Uint8List k) =>
      Uint8List(0);

  static Uint8List crypto_secretbox_open(
          Uint8List m, Uint8List c, int d, Uint8List n, Uint8List k) =>
      Uint8List(0);

  static Uint8List crypto_scalarmult(Uint8List q, Uint8List n, List<int> p) =>
      Uint8List(0);

  static Uint8List crypto_scalarmult_base(Uint8List q, Uint8List n) =>
      Uint8List(0);

  static Uint8List crypto_box_keypair(Uint8List y, Uint8List x) => Uint8List(0);

  static Uint8List crypto_box_beforenm(Uint8List k, Uint8List y, Uint8List x) =>
      Uint8List(0);

  static Uint8List crypto_box_afternm(
          Uint8List c, Uint8List m, int /*long*/ d, Uint8List n, Uint8List k) =>
      Uint8List(0);

  static Uint8List crypto_box_open_afternm(
          Uint8List m, Uint8List c, int /*long*/ d, Uint8List n, Uint8List k) =>
      Uint8List(0);

  Uint8List crypto_box(Uint8List c, Uint8List m, int /*long*/ d, Uint8List n,
          Uint8List y, Uint8List x) =>
      Uint8List(0);

  Uint8List crypto_box_open(Uint8List m, Uint8List c, int /*long*/ d,
          Uint8List n, Uint8List y, Uint8List x) =>
      Uint8List(0);

  static int crypto_hashblocks_hl(
          List<Int32> hh, List<Int32> hl, Uint8List m, final int moff, int n) =>
      0;

  static int crypto_hash(Uint8List out, Uint8List m) => 0;

  static int crypto_sign_keypair(Uint8List pk, Uint8List sk, Uint8List seed) =>
      0;

  static int crypto_sign(Uint8List sm, int dummy /* *smlen not used*/,
          Uint8List m, final int moff, int /*long*/ n, Uint8List sk,
          [bool extended = false]) =>
      0;

  static int crypto_sign_open(Uint8List m, int dummy /* *mlen not used*/,
          Uint8List sm, final int smoff, int /*long*/ n, Uint8List pk) =>
      0;

  static Uint8List randombytes(int len) => Uint8List(0);
}
