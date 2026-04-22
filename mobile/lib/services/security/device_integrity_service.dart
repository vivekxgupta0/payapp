import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Detects rooted/jailbroken devices, emulators, and debug builds.
/// If risk is detected, the offline payment kill switch is activated,
/// preventing any new offline transactions until the device passes
/// integrity checks again.
///
/// Risk signals:
///   - Root/jailbreak indicators (su binary, Cydia, Magisk)
///   - Emulator detection (build properties, known fingerprints)
///   - Debug mode / debugger attached
///   - Hooking framework detection (Frida, Xposed)
class DeviceIntegrityService {
  static final DeviceIntegrityService _instance =
      DeviceIntegrityService._internal();
  factory DeviceIntegrityService() => _instance;
  DeviceIntegrityService._internal();

  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );
  static const String _killSwitchKey = 'offline_kill_switch';
  static const String _lastCheckKey = 'last_integrity_check';

  static const _nativeChannel = MethodChannel('com.offlinepay/device_integrity');

  bool? _cachedIntegrityResult;
  DateTime? _lastCheck;

  /// Whether the offline kill switch is active (offline payments blocked).
  Future<bool> get isKillSwitchActive async {
    final val = await _storage.read(key: _killSwitchKey);
    return val == 'true';
  }

  /// Run full device integrity check. Returns a risk score 0.0 (safe)
  /// to 1.0 (compromised). Score >= 0.7 triggers the kill switch.
  Future<DeviceIntegrityResult> checkIntegrity() async {
    // Cache for 5 minutes to avoid battery drain on low-end devices
    if (_cachedIntegrityResult != null &&
        _lastCheck != null &&
        DateTime.now().difference(_lastCheck!).inMinutes < 5) {
      return DeviceIntegrityResult(
        riskScore: _cachedIntegrityResult! ? 0.0 : 0.9,
        isSecure: _cachedIntegrityResult!,
        findings: [],
      );
    }

    final findings = <String>[];
    var riskScore = 0.0;

    // 1. Debug mode check
    if (kDebugMode) {
      findings.add('DEBUG_MODE');
      riskScore += 0.1;
    }

    // 2. Platform-specific checks
    if (!kIsWeb) {
      if (Platform.isAndroid) {
        riskScore += await _checkAndroid(findings);
      } else if (Platform.isIOS) {
        riskScore += await _checkIOS(findings);
      }
    }

    // 3. Try native integrity check
    try {
      final nativeResult = await _nativeChannel.invokeMethod<Map>(
        'checkIntegrity',
      );
      if (nativeResult != null) {
        final nativeScore = (nativeResult['risk_score'] as num?)?.toDouble() ?? 0.0;
        riskScore += nativeScore;
        final nativeFindings = (nativeResult['findings'] as List?)
            ?.cast<String>() ?? [];
        findings.addAll(nativeFindings);
      }
    } on MissingPluginException {
      // Native plugin not available
    } catch (_) {}

    riskScore = riskScore.clamp(0.0, 1.0);
    final isSecure = riskScore < 0.7;

    // Activate/deactivate kill switch
    if (!isSecure) {
      await _storage.write(key: _killSwitchKey, value: 'true');
    } else {
      await _storage.delete(key: _killSwitchKey);
    }

    await _storage.write(
      key: _lastCheckKey,
      value: DateTime.now().toIso8601String(),
    );

    _cachedIntegrityResult = isSecure;
    _lastCheck = DateTime.now();

    return DeviceIntegrityResult(
      riskScore: riskScore,
      isSecure: isSecure,
      findings: findings,
    );
  }

  /// Quick check: can this device make offline payments right now?
  Future<bool> canMakeOfflinePayment() async {
    if (await isKillSwitchActive) return false;
    final result = await checkIntegrity();
    return result.isSecure;
  }

  /// Force-clear the kill switch (admin/support action only).
  Future<void> resetKillSwitch() async {
    await _storage.delete(key: _killSwitchKey);
    _cachedIntegrityResult = null;
    _lastCheck = null;
  }

  // ── Android Checks ────────────────────────────────────────────

  Future<double> _checkAndroid(List<String> findings) async {
    var score = 0.0;

    // Check for root indicators via file existence
    final rootPaths = [
      '/system/app/Superuser.apk',
      '/system/xbin/su',
      '/system/bin/su',
      '/sbin/su',
      '/data/local/xbin/su',
      '/data/local/bin/su',
      '/system/sd/xbin/su',
    ];

    for (final path in rootPaths) {
      try {
        if (await File(path).exists()) {
          findings.add('ROOT_BINARY_FOUND: $path');
          score += 0.4;
          break; // One is enough
        }
      } catch (_) {}
    }

    // Check for Magisk
    final magiskPaths = [
      '/sbin/.magisk',
      '/data/adb/magisk',
    ];
    for (final path in magiskPaths) {
      try {
        if (await File(path).exists()) {
          findings.add('MAGISK_DETECTED');
          score += 0.4;
          break;
        }
      } catch (_) {}
    }

    // Check for hooking frameworks
    final hookPaths = [
      '/data/local/tmp/frida-server',
      '/data/data/de.robv.android.xposed.installer',
    ];
    for (final path in hookPaths) {
      try {
        if (await File(path).exists()) {
          findings.add('HOOKING_FRAMEWORK_DETECTED: $path');
          score += 0.5;
          break;
        }
      } catch (_) {}
    }

    // Emulator detection via build properties
    try {
      final result = await Process.run('getprop', ['ro.hardware']);
      final hardware = result.stdout.toString().trim().toLowerCase();
      final emulatorHardware = [
        'goldfish', 'ranchu', 'vbox86', 'nox', 'ttvm_x86',
      ];
      if (emulatorHardware.any((e) => hardware.contains(e))) {
        findings.add('EMULATOR_DETECTED: $hardware');
        score += 0.5;
      }
    } catch (_) {}

    return score.clamp(0.0, 0.8);
  }

  // ── iOS Checks ────────────────────────────────────────────────

  Future<double> _checkIOS(List<String> findings) async {
    var score = 0.0;

    // Jailbreak indicators
    final jailbreakPaths = [
      '/Applications/Cydia.app',
      '/Library/MobileSubstrate/MobileSubstrate.dylib',
      '/bin/bash',
      '/usr/sbin/sshd',
      '/etc/apt',
      '/private/var/lib/apt/',
      '/usr/bin/ssh',
    ];

    for (final path in jailbreakPaths) {
      try {
        if (await File(path).exists()) {
          findings.add('JAILBREAK_INDICATOR: $path');
          score += 0.4;
          break;
        }
      } catch (_) {}
    }

    // Check if app can write outside sandbox (jailbreak indicator)
    try {
      final testFile = File('/private/jailbreak_test_${DateTime.now().millisecondsSinceEpoch}');
      await testFile.writeAsString('test');
      await testFile.delete();
      findings.add('SANDBOX_ESCAPE_POSSIBLE');
      score += 0.5;
    } catch (_) {
      // Expected: writing outside sandbox should fail on non-jailbroken device
    }

    return score.clamp(0.0, 0.8);
  }
}

class DeviceIntegrityResult {
  final double riskScore;
  final bool isSecure;
  final List<String> findings;

  const DeviceIntegrityResult({
    required this.riskScore,
    required this.isSecure,
    required this.findings,
  });

  Map<String, dynamic> toJson() => {
    'risk_score': riskScore,
    'is_secure': isSecure,
    'findings': findings,
  };
}
