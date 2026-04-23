import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import '../../config/constants.dart';

/// Enforces mandatory app updates by checking the backend for the
/// minimum required version on startup.
///
/// If the running app version is below the minimum, a blocking dialog
/// is shown that prevents further interaction until the user updates.
/// This covers MASVS-CODE-2: "The app has a mechanism for enforcing
/// app updates."
class AppUpdateService {
  static final AppUpdateService _instance = AppUpdateService._internal();
  factory AppUpdateService() => _instance;
  AppUpdateService._internal();

  static const String _currentVersion = '1.0.0';
  static const int _currentBuildNumber = 1;

  bool _updateRequired = false;
  String? _latestVersion;
  String? _updateUrl;
  String? _updateMessage;

  bool get isUpdateRequired => _updateRequired;
  String? get latestVersion => _latestVersion;

  /// Check the backend for the minimum required app version.
  /// Returns true if the current version is acceptable, false if update required.
  Future<bool> checkForUpdates() async {
    try {
      final response = await http
          .get(Uri.parse('${AppConstants.baseUrl}/api/app/version'))
          .timeout(const Duration(seconds: 10));

      if (response.statusCode != 200) return true;

      final data = jsonDecode(response.body) as Map<String, dynamic>;
      final minVersion = data['min_version'] as String? ?? '1.0.0';
      final minBuild = data['min_build_number'] as int? ?? 1;
      _latestVersion = data['latest_version'] as String? ?? _currentVersion;
      _updateUrl = data['update_url'] as String?;
      _updateMessage = data['update_message'] as String?;

      _updateRequired = _isVersionBelow(_currentVersion, minVersion) ||
          _currentBuildNumber < minBuild;

      return !_updateRequired;
    } catch (_) {
      // If we can't reach the server, don't block the user
      return true;
    }
  }

  /// Show a blocking update dialog that cannot be dismissed.
  void showBlockingUpdateDialog(BuildContext context) {
    if (!_updateRequired) return;

    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => PopScope(
        canPop: false,
        child: AlertDialog(
          title: const Row(
            children: [
              Icon(Icons.system_update, color: Colors.deepOrange),
              SizedBox(width: 8),
              Text('Update Required'),
            ],
          ),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                _updateMessage ??
                    'A critical security update is available. '
                        'Please update to continue using offline payments.',
              ),
              const SizedBox(height: 12),
              Text(
                'Current: v$_currentVersion  →  Required: v${_latestVersion ?? "latest"}',
                style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 13,
                  color: Colors.grey,
                ),
              ),
            ],
          ),
          actions: [
            FilledButton.icon(
              onPressed: () => _launchUpdate(),
              icon: const Icon(Icons.download),
              label: const Text('Update Now'),
            ),
          ],
        ),
      ),
    );
  }

  void _launchUpdate() {
    // In production, this opens the Play Store / App Store URL.
    // For the hackathon, this is a placeholder.
    debugPrint('Launching update: $_updateUrl');
  }

  /// Semantic version comparison: returns true if [current] < [minimum].
  static bool _isVersionBelow(String current, String minimum) {
    final cur = current.split('.').map(int.parse).toList();
    final min = minimum.split('.').map(int.parse).toList();

    for (var i = 0; i < 3; i++) {
      final c = i < cur.length ? cur[i] : 0;
      final m = i < min.length ? min[i] : 0;
      if (c < m) return true;
      if (c > m) return false;
    }
    return false;
  }
}
