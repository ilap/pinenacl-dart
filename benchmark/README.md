# Benchmark

There are 3 type of executables in dart:
- JiT: runs the program in the Dart VM by `dart` or `pub run`
- AoT: compiled native binary for the target OS (iOS, Android, Linux macOS Windows),
- JavaScript: runs with `node` or in browser.

> Note: Keep in mind that there are `32` and `64` bit architectures, and it seems that the `armv7` compiled `dart-sdk` does not run under `QEMU` emulation.

**All benchmarks used a 1MB large message for hashing, en/decrypt and sign/verify.**

## JiT (Dart VM) Benhcmark

Just simply run the benchmarks in Dart VM.

```dart
$ pub get
$ pub run benchmark/all_benchmark.dart
| Digest | BLAKE2B | 22.67 MB/s | 114 iterations | 5029 ms | 114.00 MB |
| Digest | SHA-256 | 14.21 MB/s | 72 iterations | 5066 ms | 72.00 MB |
...
```

### Results

Converted to table
MacBook Pro (2016), macOS Big Sur, with 2.7GHz i7 /w 16GB 

20/01/2021

| Alg type | Alg     |    rate    | iterations    |   time  | data throughput |
|----------|---------|:----------:|---------------|:-------:|:---------------:|
| Digest                   | BLAKE2B                               | 22.67 MB/s   | 114 iterations      | 5029 ms | 114.00 MB       |
| Digest                   | SHA-256                               | 14.21 MB/s   | 72 iterations       | 5066 ms | 72.00 MB        |
| Digest                   | SHA-512                               | 7.27 MB/s    | 37 iterations       | 5089 ms | 37.00 MB        |
| Signatures               | Ed25519 - sign                        | 3.58 MB/s    | 18 iterations       | 5023 ms | 18.00 MB        |
| Signatures               | Ed25519 - verify                      | 5.76 MB/s    | 29 iterations       | 5033 ms | 29.00 MB        |
| Authenticated Encryption | SecretBox - encrypt                   | 9.56 MB/s    | 48 iterations       | 5022 ms | 48.00 MB        |
| Authenticated Encryption | SecretBox - decrypt                   | 10.78 MB/s   | 54 iterations       | 5007 ms | 54.00 MB        |
| Authenticated Encryption | Box - encrypt                         | 8.77 MB/s    | 44 iterations       | 5014 ms | 44.00 MB        |
| Authenticated Encryption | Box - decrypt                         | 9.88 MB/s    | 50 iterations       | 5058 ms | 50.00 MB        |
| TweetNaCl                | crypto_hash_sha256                    | 13.35 MB/s   | 67 iterations       | 5018 ms | 67.00 MB        |
| TweetNaCl                | crypto_hash_sha512                    | 7.60 MB/s    | 38 iterations       | 5002 ms | 38.00 MB        |
| TweetNaCl                | crypto_auth_hmacsha256                | 11.47 MB/s   | 58 iterations       | 5057 ms | 58.00 MB        |
| TweetNaCl                | crypto_auth_hmacsha512                | 6.50 MB/s    | 33 iterations       | 5079 ms | 33.00 MB        |
| TweetNaCl                | crypto_box_keypair                    | 623.14 MB/s  | 3116 iterations     | 5000 ms | 3.04 GB         |
| TweetNaCl                | crypto_box_curve25519xsalsa20poly1305 | 18.21 MB/s   | 92 iterations       | 5052 ms | 92.00 MB        |
| TweetNaCl                | crypto_box_beforenm                   | 954.37 MB/s  | 4772 iterations     | 5000 ms | 4.66 GB         |
| TweetNaCl                | crypto_box_afternm                    | 16.44 MB/s   | 83 iterations       | 5048 ms | 83.00 MB        |
| TweetNaCl                | crypto_box_open_afternm               | 17.77 MB/s   | 89 iterations       | 5007 ms | 89.00 MB        |
| TweetNaCl                | crypto_stream                         | 340.49 GB/s  | 1743291 iterations  | 5000 ms | 1702.43 GB      |
| TweetNaCl                | crypto_stream_xor                     | 20.88 MB/s   | 105 iterations      | 5029 ms | 105.00 MB       |
| TweetNaCl                | crypto_core_salsa20                   | 740.98 GB/s  | 3793818 iterations  | 5000 ms | 3704.90 GB      |
| TweetNaCl                | crypto_core_hsalsa20                  | 754.57 GB/s  | 3863415 iterations  | 5000 ms | 3772.87 GB      |
| TweetNaCl                | crypto_point_add                      | 2.01 GB/s    | 10294 iterations    | 5000 ms | 10.05 GB        |
| TweetNaCl                | crypto_scalar_base                    | 527.46 MB/s  | 2638 iterations     | 5001 ms | 2.58 GB         |
| TweetNaCl                | crypto_scalarmult_base                | 940.88 MB/s  | 4705 iterations     | 5000 ms | 4.59 GB         |
| TweetNaCl                | crypto_scalarmult                     | 911.16 MB/s  | 4556 iterations     | 5000 ms | 4.45 GB         |
| TweetNaCl                | crypto_sign_ed25519_pk_to_x25519_pk   | 3.04 GB/s    | 15552 iterations    | 5000 ms | 15.19 GB        |
| TweetNaCl                | crypto_sign_ed25519_sk_to_x25519_sk   | 99.41 GB/s   | 508972 iterations   | 5000 ms | 497.04 GB       |
| TweetNaCl                | crypto_sign_keypair                   | 520.30 MB/s  | 2602 iterations     | 5001 ms | 2.54 GB         |
| TweetNaCl                | crypto_sign                           | 3.78 MB/s    | 19 iterations       | 5029 ms | 19.00 MB        |
| TweetNaCl                | crypto_sign_open                      | 7.64 MB/s    | 39 iterations       | 5107 ms | 39.00 MB        |
| TweetNaCl                | crypto_verify_16                      | 4515.12 GB/s | 23117428 iterations | 5000 ms | 22575.61 GB     |
| TweetNaCl                | crypto_verify_32                      | 3963.50 GB/s | 20293152 iterations | 5000 ms | 19817.53 GB     |
| TweetNaCl                | crypto_verify_64                      | 4048.47 GB/s | 20728189 iterations | 5000 ms | 20242.37 GB     |

## AoT (native binary)

```dart
$ pub get
$ dart2native benchmark/all_benchmark.dart -o all_benchmark
$ ./all_benchmark
| Digest | BLAKE2B | 21.99 MB/s | 110 iterations | 5001 ms | 110.00 MB |
| Digest | SHA-256 | 7.44 MB/s | 38 iterations | 5108 ms | 38.00 MB |
...
```

### Results

| Alg type | Alg     |    rate    | iterations    |   time  | data throughput |
|----------|---------|:----------:|---------------|:-------:|:---------------:|
| Digest | BLAKE2B | 21.99 MB/s | 110 iterations | 5001 ms | 110.00 MB |
| Digest | SHA-256 | 7.44 MB/s | 38 iterations | 5108 ms | 38.00 MB |
| Digest | SHA-512 | 4.89 MB/s | 25 iterations | 5108 ms | 25.00 MB |
| Signatures | Ed25519 - sign | 2.46 MB/s | 13 iterations | 5290 ms | 13.00 MB |
| Signatures | Ed25519 - verify | 3.60 MB/s | 18 iterations | 5004 ms | 18.00 MB |
| Authenticated Encryption | SecretBox - encrypt | 7.14 MB/s | 36 iterations | 5040 ms | 36.00 MB |
| Authenticated Encryption | SecretBox - decrypt | 6.60 MB/s | 34 iterations | 5154 ms | 34.00 MB |
| Authenticated Encryption | Box - encrypt | 7.01 MB/s | 36 iterations | 5133 ms | 36.00 MB |
| Authenticated Encryption | Box - decrypt | 6.58 MB/s | 33 iterations | 5013 ms | 33.00 MB |
| TweetNaCl | crypto_hash_sha256 | 8.48 MB/s | 43 iterations | 5070 ms | 43.00 MB |
| TweetNaCl | crypto_hash_sha512 | 5.25 MB/s | 27 iterations | 5140 ms | 27.00 MB |
| TweetNaCl | crypto_auth_hmacsha256 | 7.07 MB/s | 36 iterations | 5093 ms | 36.00 MB |
| TweetNaCl | crypto_auth_hmacsha512 | 4.68 MB/s | 24 iterations | 5126 ms | 24.00 MB |
| TweetNaCl | crypto_box_keypair | 183.84 MB/s | 920 iterations | 5004 ms | 920.00 MB |
| TweetNaCl | crypto_box_curve25519xsalsa20poly1305 | 12.66 MB/s | 64 iterations | 5055 ms | 64.00 MB |
| TweetNaCl | crypto_box_beforenm | 219.73 MB/s | 1099 iterations | 5001 ms | 1.07 GB |
| TweetNaCl | crypto_box_afternm | 13.51 MB/s | 68 iterations | 5031 ms | 68.00 MB |
| TweetNaCl | crypto_box_open_afternm | 13.53 MB/s | 68 iterations | 5026 ms | 68.00 MB |
| TweetNaCl | crypto_stream | 253.90 GB/s | 1299990 iterations | 5000 ms | 1269.52 GB |
| TweetNaCl | crypto_stream_xor | 15.38 MB/s | 77 iterations | 5007 ms | 77.00 MB |
| TweetNaCl | crypto_core_salsa20 | 501.70 GB/s | 2568713 iterations | 5000 ms | 2508.51 GB |
| TweetNaCl | crypto_core_hsalsa20 | 542.12 GB/s | 2775633 iterations | 5000 ms | 2710.58 GB |
| TweetNaCl | crypto_point_add | 1.40 GB/s | 7151 iterations | 5000 ms | 6.98 GB |
| TweetNaCl | crypto_scalar_base | 119.08 MB/s | 596 iterations | 5005 ms | 596.00 MB |
| TweetNaCl | crypto_scalarmult_base | 222.95 MB/s | 1115 iterations | 5001 ms | 1.09 GB |
| TweetNaCl | crypto_scalarmult | 213.73 MB/s | 1069 iterations | 5001 ms | 1.04 GB |
| TweetNaCl | crypto_sign_ed25519_pk_to_x25519_pk | 1.26 GB/s | 6467 iterations | 5000 ms | 6.32 GB |
| TweetNaCl | crypto_sign_ed25519_sk_to_x25519_sk | 54.29 GB/s | 277969 iterations | 5000 ms | 271.45 GB |
| TweetNaCl | crypto_sign_keypair | 137.13 MB/s | 686 iterations | 5002 ms | 686.00 MB |
| TweetNaCl | crypto_sign | 2.67 MB/s | 14 iterations | 5235 ms | 14.00 MB |
| TweetNaCl | crypto_sign_open | 4.60 MB/s | 23 iterations | 5004 ms | 23.00 MB |
| TweetNaCl | crypto_verify_16 | 3872.89 GB/s | 19829184 iterations | 5000 ms | 19364.44 GB |
| TweetNaCl | crypto_verify_32 | 3581.01 GB/s | 18334757 iterations | 5000 ms | 17905.04 GB |
| TweetNaCl | crypto_verify_64 | 3682.11 GB/s | 18852390 iterations | 5000 ms | 18410.54 GB |


## Javascript 

In javascript converted code, the bitwise operations are handled as `32-bit` operations.

```dart
$ pub get
$ dart2js benchmark/all_benchmark.dart -o all_benchmark.js
$ node all_benchmark.js
| Digest | BLAKE2B | 14.67 MB/s | 74 iterations | 5044 ms | 74.00 MB |
| Digest | SHA-256 | 14.75 MB/s | 74 iterations | 5018 ms | 74.00 MB |
...
```

### Resultss

| Alg type | Alg     |    rate    | iterations    |   time  | data throughput |
|----------|---------|:----------:|---------------|:-------:|:---------------:|
| Digest | BLAKE2B | 14.67 MB/s | 74 iterations | 5044 ms | 74.00 MB |
| Digest | SHA-256 | 14.75 MB/s | 74 iterations | 5018 ms | 74.00 MB |
| Digest | SHA-512 | 1.69 MB/s | 9 iterations | 5324 ms | 9.00 MB |
| Signatures | Ed25519 - sign | 877.01 KB/s | 5 iterations | 5838 ms | 5.00 MB |
| Signatures | Ed25519 - verify | 1.52 MB/s | 8 iterations | 5267 ms | 8.00 MB |
| Authenticated Encryption | SecretBox - encrypt | 2.65 MB/s | 14 iterations | 5276 ms | 14.00 MB |
| Authenticated Encryption | SecretBox - decrypt | 3.67 MB/s | 19 iterations | 5175 ms | 19.00 MB |
| Authenticated Encryption | Box - encrypt | 2.75 MB/s | 14 iterations | 5099 ms | 14.00 MB |
| Authenticated Encryption | Box - decrypt | 3.69 MB/s | 19 iterations | 5144 ms | 19.00 MB |
| TweetNaCl | crypto_hash_sha256 | 11.24 MB/s | 57 iterations | 5072 ms | 57.00 MB |
| TweetNaCl | crypto_hash_sha512 | 1.91 MB/s | 10 iterations | 5237 ms | 10.00 MB |
| TweetNaCl | crypto_auth_hmacsha256 | 4.53 MB/s | 23 iterations | 5074 ms | 23.00 MB |
| TweetNaCl | crypto_auth_hmacsha512 | 1.53 MB/s | 8 iterations | 5235 ms | 8.00 MB |
| TweetNaCl | crypto_box_keypair | 499.60 MB/s | 2498 iterations | 5000 ms | 2.44 GB |
| TweetNaCl | crypto_box_curve25519xsalsa20poly1305 | 6.75 MB/s | 34 iterations | 5039 ms | 34.00 MB |
| TweetNaCl | crypto_box_beforenm | 544.29 MB/s | 2722 iterations | 5001 ms | 2.66 GB |
| TweetNaCl | crypto_box_afternm | 6.38 MB/s | 32 iterations | 5013 ms | 32.00 MB |
| TweetNaCl | crypto_box_open_afternm | 6.63 MB/s | 34 iterations | 5129 ms | 34.00 MB |
| TweetNaCl | crypto_stream | 92.58 GB/s | 473999 iterations | 5000 ms | 462.89 GB |
| TweetNaCl | crypto_stream_xor | 7.57 MB/s | 38 iterations | 5017 ms | 38.00 MB |
| TweetNaCl | crypto_core_salsa20 | 195.29 GB/s | 999893 iterations | 5000 ms | 976.46 GB |
| TweetNaCl | crypto_core_hsalsa20 | 196.11 GB/s | 1004089 iterations | 5000 ms | 980.56 GB |
| TweetNaCl | crypto_point_add | 3.55 GB/s | 18177 iterations | 5000 ms | 17.75 GB |
| TweetNaCl | crypto_scalar_base | 295.16 MB/s | 1477 iterations | 5004 ms | 1.44 GB |
| TweetNaCl | crypto_scalarmult_base | 529.09 MB/s | 2646 iterations | 5001 ms | 2.58 GB |
| TweetNaCl | crypto_scalarmult | 556.69 MB/s | 2784 iterations | 5001 ms | 2.72 GB |
| TweetNaCl | crypto_sign_ed25519_pk_to_x25519_pk | 3.62 GB/s | 18515 iterations | 5000 ms | 18.08 GB |
| TweetNaCl | crypto_sign_ed25519_sk_to_x25519_sk | 13.41 GB/s | 68635 iterations | 5000 ms | 67.03 GB |
| TweetNaCl | crypto_sign_keypair | 287.09 MB/s | 1436 iterations | 5002 ms | 1.40 GB |
| TweetNaCl | crypto_sign | 932.10 KB/s | 5 iterations | 5493 ms | 5.00 MB |
| TweetNaCl | crypto_sign_open | 1.78 MB/s | 9 iterations | 5066 ms | 9.00 MB |
| TweetNaCl | crypto_verify_16 | 3523.37 GB/s | 18039674 iterations | 5000 ms | 17616.87 GB |
| TweetNaCl | crypto_verify_32 | 2585.52 GB/s | 13237885 iterations | 5000 ms | 12927.62 GB |
| TweetNaCl | crypto_verify_64 | 2594.30 GB/s | 13282803 iterations | 5000 ms | 12971.49 GB |

# Conclusion

TBD
