import 'package:flutter/foundation.dart';

class AppConstants {
  // Backend API URL
  // Override at build time:  flutter run --dart-define=API_URL=https://your-app.onrender.com
  static const String _envUrl = String.fromEnvironment('API_URL', defaultValue: '');

  static String get baseUrl {
    if (_envUrl.isNotEmpty) return _envUrl;
    if (kIsWeb) return 'http://127.0.0.1:8000';
    if (defaultTargetPlatform == TargetPlatform.android) return 'https://offlinepay-api.onrender.com';
    return 'https://offlinepay-api.onrender.com'; // production
  }

  // Storage keys
  static const String tokenKey = 'auth_token';
  static const String userKey = 'user_data';
  static const String publicKeyKey = 'server_public_key';
  static const String offlineTokensKey = 'offline_tokens';

  // Database
  static const String dbName = 'offline_pay.db';
  static const int dbVersion = 4;

  // Token settings
  static const int maxOfflineTokens = 10;
  static const Duration tokenCheckInterval = Duration(minutes: 5);

  // Sync settings
  static const Duration syncInterval = Duration(seconds: 30);
  static const int maxSyncRetries = 3;
}
