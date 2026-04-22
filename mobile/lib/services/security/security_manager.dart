import 'package:flutter/foundation.dart';
import 'device_key_service.dart';
import 'device_integrity_service.dart';
import 'device_registration_service.dart';
import 'secure_transaction_engine.dart';
import 'crypto_service.dart';
import 'secure_ble_protocol.dart';

/// Central security manager that initializes and coordinates all
/// security services. Call [initialize] once at app startup after
/// the user has authenticated.
///
/// Provides a single entry point for security state queries.
class SecurityManager {
  static final SecurityManager _instance = SecurityManager._internal();
  factory SecurityManager() => _instance;
  SecurityManager._internal();

  final deviceKeys = DeviceKeyService();
  final integrity = DeviceIntegrityService();
  final registration = DeviceRegistrationService();
  final transactionEngine = SecureTransactionEngine();
  final crypto = CryptoService();
  final secureBLE = SecureBLEProtocol();

  bool _initialized = false;
  DeviceIntegrityResult? _lastIntegrityResult;

  bool get isInitialized => _initialized;
  DeviceIntegrityResult? get lastIntegrityResult => _lastIntegrityResult;
  bool get isDeviceSecure => _lastIntegrityResult?.isSecure ?? false;

  /// Initialize all security services. Call after user login.
  Future<SecurityInitResult> initialize() async {
    if (_initialized) {
      return SecurityInitResult(
        success: true,
        deviceId: deviceKeys.deviceId,
        isDeviceSecure: isDeviceSecure,
        isRegistered: await registration.isRegistered,
      );
    }

    try {
      // 1. Generate/load ECDSA device keys
      await deviceKeys.getPublicKeyBase64();

      // 2. Run device integrity check
      _lastIntegrityResult = await integrity.checkIntegrity();
      if (!_lastIntegrityResult!.isSecure) {
        debugPrint(
          'SECURITY WARNING: Device integrity check failed. '
          'Score: ${_lastIntegrityResult!.riskScore}, '
          'Findings: ${_lastIntegrityResult!.findings}',
        );
      }

      // 3. Register device with backend (requires network)
      bool registered = false;
      try {
        registered = await registration.ensureRegistered();
      } catch (_) {
        // Offline — will register when connectivity is restored
      }

      // 4. Clean up old nonces
      try {
        await transactionEngine.cleanupOldNonces();
      } catch (_) {}

      _initialized = true;

      return SecurityInitResult(
        success: true,
        deviceId: deviceKeys.deviceId,
        isDeviceSecure: _lastIntegrityResult!.isSecure,
        isRegistered: registered,
        integrityFindings: _lastIntegrityResult!.findings,
      );
    } catch (e) {
      debugPrint('Security initialization failed: $e');
      return SecurityInitResult(
        success: false,
        error: e.toString(),
      );
    }
  }

  /// Quick security status for UI display.
  Future<Map<String, dynamic>> getSecurityStatus() async {
    final isReg = await registration.isRegistered;
    final killSwitch = await integrity.isKillSwitchActive;
    final dailyRemaining = await transactionEngine.getRemainingDailyLimit();

    return {
      'initialized': _initialized,
      'device_secure': isDeviceSecure,
      'device_registered': isReg,
      'kill_switch_active': killSwitch,
      'offline_payments_enabled': isDeviceSecure && !killSwitch,
      'daily_limit_remaining': dailyRemaining,
      'integrity_score': _lastIntegrityResult?.riskScore ?? -1,
    };
  }
}

class SecurityInitResult {
  final bool success;
  final String? deviceId;
  final bool isDeviceSecure;
  final bool isRegistered;
  final List<String>? integrityFindings;
  final String? error;

  const SecurityInitResult({
    required this.success,
    this.deviceId,
    this.isDeviceSecure = false,
    this.isRegistered = false,
    this.integrityFindings,
    this.error,
  });
}
