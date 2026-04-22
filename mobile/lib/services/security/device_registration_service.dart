import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import '../api_service.dart';
import 'device_key_service.dart';
import 'device_integrity_service.dart';

/// Registers the device's ECDSA public key with the backend,
/// creating a device binding that enables signed offline transactions.
///
/// Called once after key generation and on each app startup to ensure
/// the binding is current.
class DeviceRegistrationService {
  static final DeviceRegistrationService _instance =
      DeviceRegistrationService._internal();
  factory DeviceRegistrationService() => _instance;
  DeviceRegistrationService._internal();

  final _deviceKeys = DeviceKeyService();
  final _integrity = DeviceIntegrityService();
  final _api = ApiService();
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );
  static const String _registeredKey = 'device_registered';

  /// Ensure device is registered with backend. Idempotent.
  Future<bool> ensureRegistered() async {
    try {
      final isGenerated = await _deviceKeys.isKeyGenerated;
      if (!isGenerated) {
        // Force key generation
        await _deviceKeys.getPublicKeyBase64();
      }

      final alreadyRegistered = await _storage.read(key: _registeredKey);
      if (alreadyRegistered == 'true') return true;

      return await registerDevice();
    } catch (e) {
      debugPrint('Device registration check failed: $e');
      return false;
    }
  }

  /// Register this device with the backend.
  Future<bool> registerDevice() async {
    try {
      final pubKeyBase64 = await _deviceKeys.getPublicKeyBase64();
      final pubKeyPem = await _deviceKeys.getPublicKeyPem();
      final deviceId = _deviceKeys.deviceId;

      if (pubKeyBase64 == null || deviceId == null) return false;

      // Run integrity check
      final integrityResult = await _integrity.checkIntegrity();

      String platform = 'unknown';
      String osVersion = '';
      if (!kIsWeb) {
        platform = Platform.isAndroid ? 'android' : Platform.isIOS ? 'ios' : 'other';
        osVersion = Platform.operatingSystemVersion;
      }

      final response = await _api.post('/api/device/register', {
        'device_id': deviceId,
        'public_key_pem': pubKeyPem ?? '',
        'public_key_base64': pubKeyBase64,
        'platform': platform,
        'os_version': osVersion,
        'integrity_score': integrityResult.isSecure ? 1.0 : integrityResult.riskScore,
      });

      if (response['status'] == 'bound' || response['status'] == 'updated') {
        await _storage.write(key: _registeredKey, value: 'true');
        return true;
      }

      return false;
    } catch (e) {
      debugPrint('Device registration failed: $e');
      return false;
    }
  }

  /// Force re-registration (e.g., after key rotation).
  Future<bool> forceReRegister() async {
    await _storage.delete(key: _registeredKey);
    return registerDevice();
  }

  /// Check if device is registered.
  Future<bool> get isRegistered async {
    final val = await _storage.read(key: _registeredKey);
    return val == 'true';
  }
}
