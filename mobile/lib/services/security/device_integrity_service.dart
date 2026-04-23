import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:crypto/crypto.dart' as crypto_pkg;
import 'package:path_provider/path_provider.dart';

/// Comprehensive device integrity service covering:
///   - Root/jailbreak detection (MASVS-RESILIENCE-1)
///   - APK/IPA runtime integrity verification (MASVS-RESILIENCE-2)
///   - Anti-Frida, anti-Xposed, anti-hooking (MASVS-RESILIENCE-4)
///   - Emulator detection
///   - Debugger detection
///   - Kill switch for offline payments
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
  static const String _appHashKey = 'app_binary_hash';

  static const _nativeChannel =
      MethodChannel('com.offlinepay/device_integrity');

  bool? _cachedIntegrityResult;
  DateTime? _lastCheck;

  Future<bool> get isKillSwitchActive async {
    final val = await _storage.read(key: _killSwitchKey);
    return val == 'true';
  }

  /// Run full device integrity check. Score >= 0.7 triggers kill switch.
  Future<DeviceIntegrityResult> checkIntegrity() async {
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

    if (kDebugMode) {
      findings.add('DEBUG_MODE');
      riskScore += 0.1;
    }

    if (!kIsWeb) {
      if (Platform.isAndroid) {
        riskScore += await _checkAndroid(findings);
        riskScore += await _checkFridaAndroid(findings);
        riskScore += await _checkAppIntegrityAndroid(findings);
      } else if (Platform.isIOS) {
        riskScore += await _checkIOS(findings);
        riskScore += await _checkFridaIOS(findings);
        riskScore += await _checkAppIntegrityIOS(findings);
      }
    }

    // Native integrity check (Play Integrity API / DeviceCheck)
    try {
      final nativeResult =
          await _nativeChannel.invokeMethod<Map>('checkIntegrity');
      if (nativeResult != null) {
        final nativeScore =
            (nativeResult['risk_score'] as num?)?.toDouble() ?? 0.0;
        riskScore += nativeScore;
        final nativeFindings =
            (nativeResult['findings'] as List?)?.cast<String>() ?? [];
        findings.addAll(nativeFindings);
      }
    } on MissingPluginException {
      // Native plugin not available — acceptable for dev builds
    } catch (_) {}

    riskScore = riskScore.clamp(0.0, 1.0);
    final isSecure = riskScore < 0.7;

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

  Future<bool> canMakeOfflinePayment() async {
    if (await isKillSwitchActive) return false;
    final result = await checkIntegrity();
    return result.isSecure;
  }

  Future<void> resetKillSwitch() async {
    await _storage.delete(key: _killSwitchKey);
    _cachedIntegrityResult = null;
    _lastCheck = null;
  }

  // ── Android Root Detection ────────────────────────────────────

  Future<double> _checkAndroid(List<String> findings) async {
    var score = 0.0;

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
          break;
        }
      } catch (_) {}
    }

    final magiskPaths = ['/sbin/.magisk', '/data/adb/magisk'];
    for (final path in magiskPaths) {
      try {
        if (await File(path).exists()) {
          findings.add('MAGISK_DETECTED');
          score += 0.4;
          break;
        }
      } catch (_) {}
    }

    // Build property checks for emulator
    try {
      final result = await Process.run('getprop', ['ro.hardware']);
      final hardware = result.stdout.toString().trim().toLowerCase();
      const emulatorHardware = [
        'goldfish', 'ranchu', 'vbox86', 'nox', 'ttvm_x86'
      ];
      if (emulatorHardware.any((e) => hardware.contains(e))) {
        findings.add('EMULATOR_DETECTED: $hardware');
        score += 0.5;
      }
    } catch (_) {}

    // Test-keys detection (unsigned/debug firmware)
    try {
      final result = await Process.run('getprop', ['ro.build.tags']);
      final tags = result.stdout.toString().trim().toLowerCase();
      if (tags.contains('test-keys')) {
        findings.add('TEST_KEYS_BUILD');
        score += 0.3;
      }
    } catch (_) {}

    // BusyBox detection (common on rooted devices)
    for (final path in ['/system/xbin/busybox', '/system/bin/busybox']) {
      try {
        if (await File(path).exists()) {
          findings.add('BUSYBOX_FOUND: $path');
          score += 0.2;
          break;
        }
      } catch (_) {}
    }

    return score.clamp(0.0, 0.8);
  }

  // ── Android Anti-Frida / Anti-Hooking ─────────────────────────

  Future<double> _checkFridaAndroid(List<String> findings) async {
    var score = 0.0;

    // 1. Check for Frida server binaries
    final fridaPaths = [
      '/data/local/tmp/frida-server',
      '/data/local/tmp/re.frida.server',
      '/data/local/tmp/frida-agent',
      '/data/local/tmp/frida-gadget',
      '/data/local/tmp/frida-inject',
    ];
    for (final path in fridaPaths) {
      try {
        if (await File(path).exists()) {
          findings.add('FRIDA_BINARY: $path');
          score += 0.5;
          break;
        }
      } catch (_) {}
    }

    // 2. Check for Frida default listening port (27042)
    try {
      final socket = await Socket.connect('127.0.0.1', 27042,
          timeout: const Duration(milliseconds: 500));
      await socket.destroy();
      findings.add('FRIDA_PORT_27042_OPEN');
      score += 0.5;
    } catch (_) {
      // Port closed — expected on clean device
    }

    // 3. Check for Xposed framework
    final xposedPaths = [
      '/data/data/de.robv.android.xposed.installer',
      '/system/framework/XposedBridge.jar',
      '/system/lib/libxposed_art.so',
      '/data/data/org.meowcat.edxposed.manager',
      '/data/adb/lspd',
    ];
    for (final path in xposedPaths) {
      try {
        if (await File(path).exists()) {
          findings.add('XPOSED_DETECTED: $path');
          score += 0.5;
          break;
        }
      } catch (_) {}
    }

    // 4. Check for Substrate/hooking libraries loaded in memory
    try {
      final mapsFile = File('/proc/self/maps');
      if (await mapsFile.exists()) {
        final maps = await mapsFile.readAsString();
        const hookLibs = [
          'frida', 'substrate', 'xposed', 'cydia', 'libhook',
          'adbi', 'ddi', 'libinject',
        ];
        for (final lib in hookLibs) {
          if (maps.toLowerCase().contains(lib)) {
            findings.add('HOOK_LIB_IN_MEMORY: $lib');
            score += 0.5;
            break;
          }
        }
      }
    } catch (_) {}

    // 5. Check for debugger attachment via TracerPid
    try {
      final statusFile = File('/proc/self/status');
      if (await statusFile.exists()) {
        final status = await statusFile.readAsString();
        final tracerMatch = RegExp(r'TracerPid:\s*(\d+)').firstMatch(status);
        if (tracerMatch != null) {
          final pid = int.tryParse(tracerMatch.group(1) ?? '0') ?? 0;
          if (pid > 0) {
            findings.add('DEBUGGER_ATTACHED_PID_$pid');
            score += 0.5;
          }
        }
      }
    } catch (_) {}

    return score.clamp(0.0, 0.8);
  }

  // ── Android APK Integrity Check ───────────────────────────────

  Future<double> _checkAppIntegrityAndroid(List<String> findings) async {
    var score = 0.0;

    try {
      // Get our APK path via native channel
      String? apkPath;
      try {
        apkPath =
            await _nativeChannel.invokeMethod<String>('getApkPath');
      } on MissingPluginException {
        // Fallback: try common APK location
        final appDir = await getApplicationDocumentsDirectory();
        final basePath = appDir.path.split('/data/data/').first;
        apkPath = '$basePath/data/app/com.offlinepay/base.apk';
      }

      if (apkPath != null) {
        final apkFile = File(apkPath);
        if (await apkFile.exists()) {
          final bytes = await apkFile.readAsBytes();
          final hash = crypto_pkg.sha256.convert(bytes).toString();

          // First run: store the hash as baseline
          final storedHash = await _storage.read(key: _appHashKey);
          if (storedHash == null) {
            await _storage.write(key: _appHashKey, value: hash);
          } else if (storedHash != hash) {
            findings.add('APK_TAMPERED: hash mismatch');
            score += 0.6;
          }
        }
      }
    } catch (_) {
      // Non-fatal — integrity check is best-effort
    }

    // Verify app is not running in debug mode at the process level
    try {
      final debugProp =
          await Process.run('getprop', ['ro.debuggable']);
      if (debugProp.stdout.toString().trim() == '1') {
        // Only flag if this is a release build running on a debuggable system
        if (!kDebugMode) {
          findings.add('DEBUGGABLE_SYSTEM_IMAGE');
          score += 0.2;
        }
      }
    } catch (_) {}

    return score.clamp(0.0, 0.6);
  }

  // ── iOS Jailbreak Detection ───────────────────────────────────

  Future<double> _checkIOS(List<String> findings) async {
    var score = 0.0;

    final jailbreakPaths = [
      '/Applications/Cydia.app',
      '/Applications/Sileo.app',
      '/Applications/Zebra.app',
      '/Library/MobileSubstrate/MobileSubstrate.dylib',
      '/bin/bash',
      '/usr/sbin/sshd',
      '/etc/apt',
      '/private/var/lib/apt/',
      '/usr/bin/ssh',
      '/var/lib/cydia',
      '/private/var/stash',
      '/usr/libexec/cydia',
      '/usr/lib/TweakInject',
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

    // Sandbox escape test
    try {
      final testFile = File(
        '/private/jb_test_${DateTime.now().millisecondsSinceEpoch}',
      );
      await testFile.writeAsString('test');
      await testFile.delete();
      findings.add('SANDBOX_ESCAPE_POSSIBLE');
      score += 0.5;
    } catch (_) {
      // Expected on non-jailbroken device
    }

    // Check if fork() succeeds (should fail in iOS sandbox)
    try {
      final result = await Process.run('uname', ['-a']);
      if (result.exitCode == 0) {
        findings.add('FORK_SUCCEEDED');
        score += 0.3;
      }
    } catch (_) {
      // Expected failure on non-jailbroken device
    }

    return score.clamp(0.0, 0.8);
  }

  // ── iOS Anti-Frida / Anti-Hooking ─────────────────────────────

  Future<double> _checkFridaIOS(List<String> findings) async {
    var score = 0.0;

    // 1. Check Frida default port
    try {
      final socket = await Socket.connect('127.0.0.1', 27042,
          timeout: const Duration(milliseconds: 500));
      await socket.destroy();
      findings.add('FRIDA_PORT_27042_OPEN');
      score += 0.5;
    } catch (_) {}

    // 2. Check for Frida/Cycript/Substrate dylibs
    final hookDylibs = [
      '/usr/lib/frida/frida-agent.dylib',
      '/Library/MobileSubstrate/DynamicLibraries',
      '/usr/lib/libcycript.dylib',
      '/usr/lib/libfridaagent.dylib',
    ];
    for (final path in hookDylibs) {
      try {
        if (await File(path).exists()) {
          findings.add('HOOK_DYLIB: $path');
          score += 0.5;
          break;
        }
      } catch (_) {}
    }

    // 3. Check for suspicious environment variables
    final env = Platform.environment;
    const suspiciousVars = [
      'DYLD_INSERT_LIBRARIES',
      '_MSSafeMode',
      'SIMULATOR_DEVICE_NAME',
    ];
    for (final v in suspiciousVars) {
      if (env.containsKey(v)) {
        findings.add('SUSPICIOUS_ENV: $v');
        score += 0.4;
        break;
      }
    }

    // 4. Check for reverse engineering tools via URL schemes
    // (Requires native call in production — placeholder logic here)
    try {
      final result = await _nativeChannel.invokeMethod<bool>(
        'checkReverseEngineeringTools',
      );
      if (result == true) {
        findings.add('RE_TOOLS_DETECTED');
        score += 0.5;
      }
    } on MissingPluginException {
      // Native plugin not available
    } catch (_) {}

    return score.clamp(0.0, 0.8);
  }

  // ── iOS IPA Integrity Check ───────────────────────────────────

  Future<double> _checkAppIntegrityIOS(List<String> findings) async {
    var score = 0.0;

    try {
      // Check code signing via native channel
      bool? validSignature;
      try {
        validSignature = await _nativeChannel.invokeMethod<bool>(
          'verifyCodeSignature',
        );
      } on MissingPluginException {
        // Use fallback check
      }

      if (validSignature == false) {
        findings.add('IPA_SIGNATURE_INVALID');
        score += 0.6;
      }

      // Hash the main bundle executable
      final appDir = await getApplicationDocumentsDirectory();
      final bundlePath = appDir.parent.path;
      final executablePath = '$bundlePath/Runner';

      final execFile = File(executablePath);
      if (await execFile.exists()) {
        final bytes = await execFile.readAsBytes();
        final hash = crypto_pkg.sha256.convert(bytes).toString();

        final storedHash = await _storage.read(key: _appHashKey);
        if (storedHash == null) {
          await _storage.write(key: _appHashKey, value: hash);
        } else if (storedHash != hash) {
          findings.add('IPA_TAMPERED: binary hash mismatch');
          score += 0.6;
        }
      }
    } catch (_) {}

    // Check for get-task-allow entitlement (debug builds)
    try {
      final hasDebugEntitlement = await _nativeChannel.invokeMethod<bool>(
        'hasDebugEntitlement',
      );
      if (hasDebugEntitlement == true && !kDebugMode) {
        findings.add('DEBUG_ENTITLEMENT_IN_RELEASE');
        score += 0.3;
      }
    } on MissingPluginException {
      // Expected in dev
    } catch (_) {}

    return score.clamp(0.0, 0.6);
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
