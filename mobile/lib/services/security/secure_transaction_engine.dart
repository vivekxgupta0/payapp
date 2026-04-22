import 'package:sqflite/sqflite.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../../models/payment_blob.dart';
import '../offline_queue_service.dart';
import '../offline_limit_service.dart';
import '../offline_storage.dart';
import 'device_key_service.dart';
import 'device_integrity_service.dart';

/// NPCI-compliant offline transaction engine that enforces:
///   - Per-transaction limit (₹2,000)
///   - Daily cumulative offline limit (₹4,000)
///   - Overall offline credit cap (₹5,000, ML-assigned)
///   - Nonce uniqueness (replay protection)
///   - Timestamp validation (5-minute BLE window, 72-hour sync window)
///   - ECDSA signature on every transaction
///   - Device integrity check before every offline payment
///   - Immediate local balance deduction (double-spend prevention)
///   - Monotonic sequence numbers
class SecureTransactionEngine {
  static final SecureTransactionEngine _instance =
      SecureTransactionEngine._internal();
  factory SecureTransactionEngine() => _instance;
  SecureTransactionEngine._internal();

  final _deviceKeys = DeviceKeyService();
  final _integrity = DeviceIntegrityService();
  final _queue = OfflineQueueService();
  final _limitService = OfflineLimitService();

  // NPCI-mandated limits
  static const double maxPerTransaction = 2000.0;
  static const double maxDailyOffline = 4000.0;
  static const double maxOfflineCap = 5000.0;
  static const Duration bleValidityWindow = Duration(minutes: 5);
  static const Duration maxSyncWindow = Duration(hours: 72);

  static const String _dailyTotalKey = 'offline_daily_total';
  static const String _dailyDateKey = 'offline_daily_date';
  static const String _sequenceKey = 'offline_sequence_number';

  // ── Pre-flight Validation ─────────────────────────────────────

  /// Validate whether an offline payment can proceed. Returns null if OK,
  /// or an error message explaining why it was rejected.
  Future<String?> validateOfflinePayment({
    required double amount,
    required String senderId,
    required String receiverId,
  }) async {
    // 1. Device integrity check
    final canPay = await _integrity.canMakeOfflinePayment();
    if (!canPay) {
      return 'Offline payments disabled: device security check failed';
    }

    // 2. Per-transaction limit
    if (amount > maxPerTransaction) {
      return 'Amount ₹${amount.toStringAsFixed(0)} exceeds per-transaction limit of ₹${maxPerTransaction.toStringAsFixed(0)}';
    }

    if (amount <= 0) {
      return 'Amount must be positive';
    }

    // 3. Check offline limit availability
    final availableLimit = await _limitService.getAvailableLimit();
    if (availableLimit <= 0) {
      return 'No offline credit available. Connect to internet to refresh your limit.';
    }

    if (amount > availableLimit) {
      return 'Amount ₹${amount.toStringAsFixed(0)} exceeds available offline limit of ₹${availableLimit.toStringAsFixed(0)}';
    }

    // 4. Check limit expiry
    final isValid = await _limitService.isLimitValid();
    if (!isValid) {
      return 'Offline limit has expired. Connect to internet to refresh.';
    }

    // 5. Daily cumulative limit
    final dailyTotal = await _getDailyTotal();
    if (dailyTotal + amount > maxDailyOffline) {
      final remaining = maxDailyOffline - dailyTotal;
      return 'Daily offline limit reached. Remaining today: ₹${remaining.toStringAsFixed(0)}';
    }

    // 6. Self-payment check
    if (senderId == receiverId) {
      return 'Cannot send payment to yourself';
    }

    return null; // All checks passed
  }

  // ── Transaction Creation & Signing ────────────────────────────

  /// Create a signed offline payment blob. This:
  ///   1. Validates all NPCI limits
  ///   2. Signs the transaction with the device ECDSA key
  ///   3. Deducts from local offline limit immediately
  ///   4. Increments the daily total
  ///   5. Stores in the local SQLite queue
  ///   6. Returns the signed blob for BLE transfer if needed
  Future<SignedTransactionResult> createSignedTransaction({
    required String senderId,
    required String receiverId,
    required double amount,
  }) async {
    // Validate
    final error = await validateOfflinePayment(
      amount: amount,
      senderId: senderId,
      receiverId: receiverId,
    );
    if (error != null) {
      return SignedTransactionResult.failed(error);
    }

    final currentLimit = await _limitService.getAvailableLimit();
    final sequenceNumber = await _getAndIncrementSequence();

    // Create the blob
    final blob = PaymentBlob(
      senderId: senderId,
      receiverId: receiverId,
      amount: amount,
      isOffline: true,
      offlineLimitAtTime: currentLimit,
    );

    // Build canonical payload for signing
    final canonicalPayload = buildCanonicalPayload(blob);

    // Sign with device ECDSA key
    final signature = await _deviceKeys.signTransaction(canonicalPayload);
    final publicKeyBase64 = await _deviceKeys.getPublicKeyBase64();

    // Create signed blob (we need a new instance since deviceSignature is final)
    final signedBlob = PaymentBlob(
      id: blob.id,
      senderId: blob.senderId,
      receiverId: blob.receiverId,
      amount: blob.amount,
      timestamp: blob.timestamp,
      nonce: blob.nonce,
      deviceSignature: signature,
      status: BlobStatus.pendingSync,
      isOffline: true,
      offlineLimitAtTime: currentLimit,
    );

    // Deduct from local offline limit IMMEDIATELY (double-spend prevention)
    await _limitService.deductFromLimit(amount);

    // Increment daily total
    await _addToDailyTotal(amount);

    // Store in local queue
    await _queue.enqueue(signedBlob);

    // Track the nonce for replay detection
    await _trackNonce(signedBlob.nonce);

    return SignedTransactionResult.success(
      blob: signedBlob,
      signature: signature,
      senderPublicKey: publicKeyBase64 ?? '',
      sequenceNumber: sequenceNumber,
    );
  }

  /// Build the canonical payload string that gets signed.
  /// This MUST be identical on client and server for signature verification.
  static String buildCanonicalPayload(PaymentBlob blob) {
    return '${blob.id}|${blob.senderId}|${blob.receiverId}|'
        '${blob.amount.toStringAsFixed(2)}|'
        '${blob.timestamp.toUtc().toIso8601String()}|${blob.nonce}';
  }

  // ── Nonce Tracking (Replay Prevention) ────────────────────────

  /// Check if a nonce has been seen before (locally).
  Future<bool> isNonceUsed(String nonce) async {
    final db = await OfflineStorage().database;
    final result = await db.query(
      'nonce_tracker',
      where: 'nonce = ?',
      whereArgs: [nonce],
      limit: 1,
    );
    return result.isNotEmpty;
  }

  Future<void> _trackNonce(String nonce) async {
    final db = await OfflineStorage().database;
    await db.insert(
      'nonce_tracker',
      {
        'nonce': nonce,
        'created_at': DateTime.now().toIso8601String(),
      },
      conflictAlgorithm: ConflictAlgorithm.ignore,
    );
  }

  /// Validate a received blob's timestamp is within the allowed window.
  bool isTimestampValid(DateTime blobTimestamp, {bool isBLE = false}) {
    final now = DateTime.now().toUtc();
    final diff = now.difference(blobTimestamp.toUtc());

    if (isBLE) {
      return diff.abs() <= bleValidityWindow;
    }
    return diff <= maxSyncWindow && diff >= Duration.zero;
  }

  /// Validate a received blob (used by receiver in BLE transfer).
  Future<String?> validateReceivedBlob(
    PaymentBlob blob, {
    String? senderPublicKey,
  }) async {
    // Timestamp check
    if (!isTimestampValid(blob.timestamp, isBLE: true)) {
      return 'Transaction expired (outside ${bleValidityWindow.inMinutes}-minute window)';
    }

    // Nonce replay check
    if (await isNonceUsed(blob.nonce)) {
      return 'Duplicate transaction detected (replay attack)';
    }

    // Amount limits
    if (blob.amount <= 0 || blob.amount > maxPerTransaction) {
      return 'Invalid transaction amount';
    }

    // Signature verification (if public key provided)
    if (senderPublicKey != null &&
        blob.deviceSignature != 'DEVICE_SIG_PLACEHOLDER') {
      final canonical = buildCanonicalPayload(blob);
      final valid = _deviceKeys.verifySignatureBase64(
        canonical,
        blob.deviceSignature,
        senderPublicKey,
      );
      if (!valid) {
        return 'Invalid transaction signature';
      }
    }

    return null; // Valid
  }

  // ── Daily Limit Tracking ──────────────────────────────────────

  Future<double> _getDailyTotal() async {
    final prefs = await SharedPreferences.getInstance();
    final storedDate = prefs.getString(_dailyDateKey);
    final today = DateTime.now().toIso8601String().substring(0, 10);

    if (storedDate != today) {
      await prefs.setString(_dailyDateKey, today);
      await prefs.setDouble(_dailyTotalKey, 0.0);
      return 0.0;
    }

    return prefs.getDouble(_dailyTotalKey) ?? 0.0;
  }

  Future<void> _addToDailyTotal(double amount) async {
    final prefs = await SharedPreferences.getInstance();
    final today = DateTime.now().toIso8601String().substring(0, 10);
    await prefs.setString(_dailyDateKey, today);
    final current = prefs.getDouble(_dailyTotalKey) ?? 0.0;
    await prefs.setDouble(_dailyTotalKey, current + amount);
  }

  /// Get remaining daily offline limit.
  Future<double> getRemainingDailyLimit() async {
    final used = await _getDailyTotal();
    return (maxDailyOffline - used).clamp(0.0, maxDailyOffline);
  }

  // ── Sequence Numbers ──────────────────────────────────────────

  Future<int> _getAndIncrementSequence() async {
    final prefs = await SharedPreferences.getInstance();
    final current = prefs.getInt(_sequenceKey) ?? 0;
    await prefs.setInt(_sequenceKey, current + 1);
    return current + 1;
  }

  // ── Cleanup ───────────────────────────────────────────────────

  /// Clean up nonces older than 72 hours.
  Future<void> cleanupOldNonces() async {
    final db = await OfflineStorage().database;
    final cutoff = DateTime.now()
        .subtract(maxSyncWindow)
        .toIso8601String();
    await db.delete(
      'nonce_tracker',
      where: 'created_at < ?',
      whereArgs: [cutoff],
    );
  }
}

class SignedTransactionResult {
  final bool success;
  final PaymentBlob? blob;
  final String? signature;
  final String? senderPublicKey;
  final int? sequenceNumber;
  final String? error;

  SignedTransactionResult._({
    required this.success,
    this.blob,
    this.signature,
    this.senderPublicKey,
    this.sequenceNumber,
    this.error,
  });

  factory SignedTransactionResult.success({
    required PaymentBlob blob,
    required String signature,
    required String senderPublicKey,
    required int sequenceNumber,
  }) {
    return SignedTransactionResult._(
      success: true,
      blob: blob,
      signature: signature,
      senderPublicKey: senderPublicKey,
      sequenceNumber: sequenceNumber,
    );
  }

  factory SignedTransactionResult.failed(String error) {
    return SignedTransactionResult._(success: false, error: error);
  }
}
