import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:pointycastle/export.dart';
import 'package:crypto/crypto.dart' as crypto_lib;

/// Provides ECDH key exchange, AES-256-GCM encryption, and HKDF key
/// derivation for secure BLE communication.
///
/// Flow:
///   1. Both parties generate ephemeral ECDH P-256 keypairs
///   2. Exchange public keys over BLE
///   3. Derive shared secret via ECDH
///   4. Derive AES-256 session key via HKDF-SHA256
///   5. Encrypt/decrypt payloads with AES-256-GCM (unique IV per message)
class CryptoService {
  static final CryptoService _instance = CryptoService._internal();
  factory CryptoService() => _instance;
  CryptoService._internal();

  static final _domain = ECCurve_secp256r1();

  // ── ECDH Key Exchange ──────────────────────────────────────────

  /// Generate an ephemeral ECDH keypair for a single BLE session.
  AsymmetricKeyPair<PublicKey, PrivateKey> generateEphemeralKeyPair() {
    final gen = ECKeyGenerator()
      ..init(ParametersWithRandom(
        ECKeyGeneratorParameters(_domain),
        _secureRandom(),
      ));
    return gen.generateKeyPair();
  }

  /// Encode an ephemeral public key to bytes for BLE transmission.
  Uint8List encodePublicKey(ECPublicKey key) {
    final q = key.Q!;
    final x = _bigIntToBytes(q.x!.toBigInteger()!, 32);
    final y = _bigIntToBytes(q.y!.toBigInteger()!, 32);
    return Uint8List.fromList([0x04, ...x, ...y]);
  }

  /// Decode a received ephemeral public key from bytes.
  ECPublicKey decodePublicKey(Uint8List bytes) {
    final point = _domain.curve.decodePoint(bytes);
    if (point == null) throw FormatException('Invalid EC point');
    return ECPublicKey(point, _domain);
  }

  /// Perform ECDH to derive a shared secret from our private key and
  /// the remote party's public key.
  Uint8List deriveSharedSecret(
    ECPrivateKey ourPrivate,
    ECPublicKey theirPublic,
  ) {
    final agreement = ECDHBasicAgreement()
      ..init(ourPrivate);
    final shared = agreement.calculateAgreement(theirPublic);
    return _bigIntToBytes(shared, 32);
  }

  // ── HKDF Key Derivation ────────────────────────────────────────

  /// Derive an AES-256 session key from the ECDH shared secret using
  /// HKDF-SHA256. The [info] parameter provides domain separation
  /// (e.g. "ble-session-key-v1").
  Uint8List deriveSessionKey(
    Uint8List sharedSecret, {
    Uint8List? salt,
    String info = 'offlinepay-ble-session-v1',
  }) {
    salt ??= Uint8List(32); // Zero salt per RFC 5869

    // HKDF-Extract
    final prk = _hmacSha256(salt, sharedSecret);

    // HKDF-Expand (single block for 32-byte key)
    final infoBytes = utf8.encode(info);
    final t = Uint8List.fromList([...infoBytes, 0x01]);
    final okm = _hmacSha256(prk, t);

    return Uint8List.fromList(okm.sublist(0, 32));
  }

  // ── AES-256-GCM Encryption ─────────────────────────────────────

  /// Encrypt [plaintext] with AES-256-GCM using [key].
  /// Returns: IV (12 bytes) || ciphertext || tag (16 bytes).
  Uint8List encryptAesGcm(Uint8List plaintext, Uint8List key) {
    final iv = _generateIv(12);
    final cipher = GCMBlockCipher(AESEngine())
      ..init(
        true,
        AEADParameters(
          KeyParameter(key),
          128, // 16-byte auth tag
          iv,
          Uint8List(0), // no AAD
        ),
      );

    final output = Uint8List(plaintext.length + 16); // ciphertext + tag
    var offset = 0;
    offset += cipher.processBytes(plaintext, 0, plaintext.length, output, 0);
    offset += cipher.doFinal(output, offset);

    // Prepend IV
    return Uint8List.fromList([...iv, ...output.sublist(0, offset)]);
  }

  /// Decrypt [cipherBlob] (IV || ciphertext || tag) with AES-256-GCM.
  Uint8List decryptAesGcm(Uint8List cipherBlob, Uint8List key) {
    if (cipherBlob.length < 28) {
      throw FormatException('Ciphertext too short');
    }

    final iv = cipherBlob.sublist(0, 12);
    final ciphertextAndTag = cipherBlob.sublist(12);

    final cipher = GCMBlockCipher(AESEngine())
      ..init(
        false,
        AEADParameters(
          KeyParameter(key),
          128,
          iv,
          Uint8List(0),
        ),
      );

    final output = Uint8List(ciphertextAndTag.length);
    var offset = 0;
    offset += cipher.processBytes(
      ciphertextAndTag, 0, ciphertextAndTag.length, output, 0,
    );
    offset += cipher.doFinal(output, offset);

    return output.sublist(0, offset);
  }

  /// Convenience: encrypt a JSON map to a base64 string.
  String encryptJson(Map<String, dynamic> json, Uint8List key) {
    final plaintext = Uint8List.fromList(utf8.encode(jsonEncode(json)));
    return base64Encode(encryptAesGcm(plaintext, key));
  }

  /// Convenience: decrypt a base64 string to a JSON map.
  Map<String, dynamic> decryptJson(String base64Cipher, Uint8List key) {
    final blob = base64Decode(base64Cipher);
    final plaintext = decryptAesGcm(blob, key);
    return jsonDecode(utf8.decode(plaintext)) as Map<String, dynamic>;
  }

  // ── Challenge-Response for Mutual Auth ─────────────────────────

  /// Generate a 32-byte cryptographic challenge.
  Uint8List generateChallenge() => _generateIv(32);

  /// Create a challenge response: HMAC-SHA256(sessionKey, challenge || identity).
  Uint8List respondToChallenge(
    Uint8List challenge,
    Uint8List sessionKey,
    String identity,
  ) {
    final data = Uint8List.fromList([
      ...challenge,
      ...utf8.encode(identity),
    ]);
    return Uint8List.fromList(_hmacSha256(sessionKey, data));
  }

  /// Verify a challenge response.
  bool verifyChallengeResponse(
    Uint8List challenge,
    Uint8List sessionKey,
    String identity,
    Uint8List response,
  ) {
    final expected = respondToChallenge(challenge, sessionKey, identity);
    return _constantTimeEquals(expected, response);
  }

  // ── Helpers ────────────────────────────────────────────────────

  static Uint8List _hmacSha256(Uint8List key, Uint8List data) {
    final hmac = crypto_lib.Hmac(crypto_lib.sha256, key);
    final digest = hmac.convert(data);
    return Uint8List.fromList(digest.bytes);
  }

  static Uint8List _generateIv(int length) {
    final rng = Random.secure();
    return Uint8List.fromList(
      List<int>.generate(length, (_) => rng.nextInt(256)),
    );
  }

  static bool _constantTimeEquals(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var result = 0;
    for (var i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result == 0;
  }

  static SecureRandom _secureRandom() {
    final random = FortunaRandom();
    final seed = Uint8List(32);
    final rng = Random.secure();
    for (var i = 0; i < 32; i++) {
      seed[i] = rng.nextInt(256);
    }
    random.seed(KeyParameter(seed));
    return random;
  }

  static Uint8List _bigIntToBytes(BigInt n, int length) {
    final bytes = <int>[];
    var v = n;
    while (v > BigInt.zero) {
      bytes.insert(0, (v & BigInt.from(0xff)).toInt());
      v >>= 8;
    }
    if (bytes.length >= length) {
      return Uint8List.fromList(bytes.sublist(bytes.length - length));
    }
    final padded = Uint8List(length);
    padded.setRange(length - bytes.length, length, bytes);
    return padded;
  }
}

/// Holds the state for a single BLE session's cryptographic context.
class BLESessionKeys {
  final Uint8List sessionKey;
  final ECPublicKey remotePublicKey;
  final ECPublicKey localPublicKey;
  final DateTime createdAt;

  BLESessionKeys({
    required this.sessionKey,
    required this.remotePublicKey,
    required this.localPublicKey,
    DateTime? createdAt,
  }) : createdAt = createdAt ?? DateTime.now();

  bool get isExpired =>
      DateTime.now().difference(createdAt).inMinutes > 5;

  void assertValid() {
    if (isExpired) throw StateError('BLE session expired');
  }
}
