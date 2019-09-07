import 'dart:typed_data';

import 'package:convert/convert.dart';

import 'package:pinenacl/api.dart';
import 'package:pinenacl/hashing.dart';

void main() {

  final hasher = Hash.blake2b;

  /// # Hashing
  print('Hash example\nH(\'\'): ${hex.encode(hasher(''))}');

  /// # Message authentication
  /// To authenticate a message, using a secret key, the blake2b function must be called as in the following example.
  print('\nMessage authentication');
  /// Message authentication example
  /// It can ganarate a MAC to be sure that the message is not forged.

  final msg = '256 BytesMessage' * 16;

  // the simplest way to get a cryptographic quality authKey
  // is to generate it with a cryptographic quality
  // random number generator
  final authKey = Utils.randombytes(64);
  final mac = hasher(msg, key: authKey);

  print('MAC(msg, authKey): ${hex.encode(mac)}.\n');

  /// # Key derivation example
  /// The blake2b algorithm can replace a key derivation function by following the lines of:
  print('Key derivation example');
  final masterKey = Utils.randombytes(64);
  final derivationSalt = Utils.randombytes(16);

  final personalisation = Uint8List.fromList('<DK usage>'.codeUnits);

  final subKey = hasher('', key: masterKey, salt: derivationSalt, personalisation: personalisation);
  print('KDF(\'\', masterKey, salt, personalisation): ${hex.encode(subKey)}');
  /// By repeating the key derivation procedure before encrypting our messages, 
  /// and sending the derivationSalt along with the encrypted message, we can expect to never reuse a key, 
  /// drastically reducing the risks which ensue from such a reuse.
}
