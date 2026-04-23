#!/bin/bash
# Release build with full MASVS-RESILIENCE-3 obfuscation enabled.
#
# Flutter's --obfuscate flag renames all Dart symbols to random strings,
# making static analysis and reverse engineering significantly harder.
# --split-debug-info stores the debug symbol mapping separately for
# crash report de-symbolication without shipping symbols in the APK/IPA.
#
# Usage:
#   ./scripts/build_release.sh android   # Build obfuscated APK
#   ./scripts/build_release.sh ios       # Build obfuscated IPA
#   ./scripts/build_release.sh both      # Build both

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DEBUG_INFO_DIR="$PROJECT_DIR/build/debug-info"

mkdir -p "$DEBUG_INFO_DIR"

TARGET="${1:-both}"

build_android() {
    echo "=== Building obfuscated Android APK ==="
    cd "$PROJECT_DIR"
    flutter build apk \
        --release \
        --obfuscate \
        --split-debug-info="$DEBUG_INFO_DIR/android" \
        --dart-define=API_URL=https://offlinepay-api.onrender.com \
        --shrink \
        --tree-shake-icons
    echo "APK: $PROJECT_DIR/build/app/outputs/flutter-apk/app-release.apk"
    echo "Debug symbols: $DEBUG_INFO_DIR/android/"
}

build_ios() {
    echo "=== Building obfuscated iOS IPA ==="
    cd "$PROJECT_DIR"
    flutter build ipa \
        --release \
        --obfuscate \
        --split-debug-info="$DEBUG_INFO_DIR/ios" \
        --dart-define=API_URL=https://offlinepay-api.onrender.com
    echo "IPA: $PROJECT_DIR/build/ios/ipa/"
    echo "Debug symbols: $DEBUG_INFO_DIR/ios/"
}

case "$TARGET" in
    android) build_android ;;
    ios)     build_ios ;;
    both)    build_android; build_ios ;;
    *)       echo "Usage: $0 {android|ios|both}"; exit 1 ;;
esac

echo ""
echo "=== Build complete ==="
echo "IMPORTANT: Store $DEBUG_INFO_DIR securely — needed for crash symbolication."
echo "NEVER ship debug-info/ with the app."
