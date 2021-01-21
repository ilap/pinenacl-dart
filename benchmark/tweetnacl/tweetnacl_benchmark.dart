import 'package:pinenacl/api.dart';
import 'package:pinenacl/tweetnacl.dart';

import '../helpers/tweetnacl_benchmark.dart';

// TODO: Implement the following too.
// crypto_onetimeauth(Uint8List out, Uint8List m, final int n, Uint8List k)
// crypto_onetimeauth_verify(Uint8List h, Uint8List m, Uint8List k)
// crypto_stream_salsa20(Uint8List c, int cpos, int b, Uint8List n, Uint8List k)
// crypto_stream_salsa20_xor(Uint8List c, int cpos, Uint8List m, int mpos, int b, Uint8List n, Uint8List k, [int ic = 0])
// crypto_secretbox(outData, data, dataLength, nonce, sk),
// crypto_secretbox_open(data, outData, outDataLength, nonce, sk),

void main() {
  const dataLength = 1024 * 1024;
  const outDataLength = dataLength;

  final data = Uint8List(dataLength);

  final sk = PineNaClUtils.randombytes(32);
  final pk = Uint8List(32);

  final sharedKey = Uint8List(32);
  final nonce = PineNaClUtils.randombytes(24);

  final randOut16 = PineNaClUtils.randombytes(16);
  final out32 = Uint8List(32);
  final out64 = Uint8List(64);
  final outData = Uint8List(outDataLength);
  const outSignatureLength = outDataLength + TweetNaCl.signatureLength;

  final outSignature = Uint8List(outSignatureLength);

  final funcMap = <String, Function>{
    // SHA-256 SHA-512
    'crypto_hash_sha256': () => TweetNaClExt.crypto_hash_sha256(out32, data),
    'crypto_hash_sha512': () => TweetNaCl.crypto_hash(out64, data),

    // HMAC
    'crypto_auth_hmacsha256': () =>
        TweetNaClExt.crypto_auth_hmacsha256(out32, data, sk),
    'crypto_auth_hmacsha512': () =>
        TweetNaClExt.crypto_auth_hmacsha512(out64, data, sk),

    // Public - Authenticated Encryption
    'crypto_box_keypair': () => TweetNaCl.crypto_box_keypair(pk, sk),
    'crypto_box_curve25519xsalsa20poly1305': () =>
        TweetNaCl.crypto_box(outData, data, dataLength, nonce, pk, sk),
    'crypto_box_beforenm': () =>
        TweetNaCl.crypto_box_beforenm(sharedKey, pk, sk),
    'crypto_box_afternm': () => TweetNaCl.crypto_box_afternm(
        outData, data, dataLength, nonce, sharedKey),
    'crypto_box_open_afternm': () => TweetNaCl.crypto_box_open_afternm(
        data, outData, outDataLength, nonce, sharedKey),

    // Secret-key cryptography - Stream Encryption
    'crypto_stream': () => TweetNaCl.crypto_stream(out32, 0, 32, nonce, sk),
    'crypto_stream_xor': () =>
        TweetNaCl.crypto_stream_xor(outData, 0, data, 0, dataLength, nonce, sk),

    'crypto_core_salsa20': () =>
        TweetNaCl.crypto_core_salsa20(outData, data, sharedKey, nonce),
    'crypto_core_hsalsa20': () =>
        TweetNaCl.crypto_core_hsalsa20(outData, data, sharedKey, nonce),

    // TweetNaCl Extension.
    'crypto_point_add': () => TweetNaClExt.crypto_point_add(out32, pk, pk),
    'crypto_scalar_base': () => TweetNaClExt.crypto_scalar_base(out32, sk),

    'crypto_scalarmult_base': () => TweetNaCl.crypto_scalarmult_base(out32, sk),
    'crypto_scalarmult': () =>
        TweetNaCl.crypto_scalarmult(out32, sk, Uint8List(32)),

    'crypto_sign_ed25519_pk_to_x25519_pk': () =>
        TweetNaClExt.crypto_sign_ed25519_pk_to_x25519_pk(out32, pk),
    'crypto_sign_ed25519_sk_to_x25519_sk': () =>
        TweetNaClExt.crypto_sign_ed25519_sk_to_x25519_sk(out64, sk),
    'crypto_sign_keypair': () =>
        TweetNaCl.crypto_sign_keypair(pk, out64, out32),
    'crypto_sign': () =>
        TweetNaCl.crypto_sign(outSignature, 0, data, 0, dataLength, out64),
    'crypto_sign_open': () => TweetNaCl.crypto_sign_open(
        data, 0, outSignature.sublist(64), 0, dataLength, pk),

    'crypto_verify_16': () => TweetNaCl.crypto_verify_16(randOut16, randOut16),
    'crypto_verify_32': () => TweetNaCl.crypto_verify_32(pk, pk),
    'crypto_verify_64': () => TweetNaClExt.crypto_verify_64(out64, out64),
  };

  funcMap.forEach((funcName, func) {
    TweetNaClBenchmark(func, funcName, data.length).report();
  });
}
