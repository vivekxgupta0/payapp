import 'dart:async';
import 'dart:convert';
import 'package:flutter/services.dart';
import 'package:flutter_blue_plus/flutter_blue_plus.dart';
import 'package:uuid/uuid.dart';
import '../models/payment_blob.dart';
import 'offline_queue_service.dart';

/// BLE service for Case 3: both sender and receiver are offline.
///
/// SENDER ROLE (central via flutter_blue_plus):
///   Scan for the receiver's advertised BLE UUID → connect → write PaymentBlob JSON.
///
/// RECEIVER ROLE (peripheral via iOS native MethodChannel):
///   Generate a session UUID → call native CBPeripheralManager to advertise →
///   receive blob JSON via EventChannel → store in local SQLite queue.
///
/// The session UUID is embedded in the receiver's QR code so the sender can
/// find the exact device. Both parties keep the blob and sync to the backend
/// independently when they regain connectivity.
class BLEService {
  static final BLEService _instance = BLEService._internal();
  factory BLEService() => _instance;
  BLEService._internal();

  /// Fixed GATT characteristic UUID (write) — both sides must use the same.
  static const String kBlobWriteCharUuid =
      '6E4AA9B1-0000-0000-0000-000000000000';

  static const _methodCh =
      MethodChannel('com.offlinepay/ble_peripheral');
  static const _eventCh =
      EventChannel('com.offlinepay/ble_peripheral_events');

  final _queue = OfflineQueueService();
  StreamSubscription? _eventSub;
  bool _isAdvertising = false;
  bool _isSending = false;
  String? _activeSessionUuid;

  final _receivedBlobCtrl = StreamController<PaymentBlob>.broadcast();

  /// Stream of blobs received over BLE (receiver role).
  Stream<PaymentBlob> get onBlobReceived => _receivedBlobCtrl.stream;

  bool get isAdvertising => _isAdvertising;
  bool get isSending => _isSending;

  /// The BLE session UUID currently being advertised; null if not advertising.
  String? get activeSessionUuid => _activeSessionUuid;

  // ── Receiver Role ─────────────────────────────────────────────────────────

  /// Generate a fresh session UUID, tell native iOS to advertise it, and
  /// begin listening for inbound blob data via the event channel.
  /// Returns the session UUID to embed in the receiver's QR code.
  Future<String> startReceiving() async {
    await stopReceiving();
    final sessionUuid = const Uuid().v4().toUpperCase();
    _activeSessionUuid = sessionUuid;

    try {
      await _methodCh.invokeMethod<void>('startAdvertising', {
        'serviceUuid': sessionUuid,
        'writeCharUuid': kBlobWriteCharUuid,
      });
      _isAdvertising = true;
      _eventSub = _eventCh
          .receiveBroadcastStream()
          .listen(_handleReceivedData, onError: (_) {});
    } catch (e) {
      _isAdvertising = false;
      _activeSessionUuid = null;
      rethrow;
    }
    return sessionUuid;
  }

  /// Stop advertising and clean up the event subscription.
  Future<void> stopReceiving() async {
    _eventSub?.cancel();
    _eventSub = null;
    if (_isAdvertising) {
      try {
        await _methodCh.invokeMethod<void>('stopAdvertising');
      } catch (_) {}
      _isAdvertising = false;
    }
    _activeSessionUuid = null;
  }

  void _handleReceivedData(dynamic raw) {
    try {
      final jsonMap = jsonDecode(raw as String) as Map<String, dynamic>;
      final blob = PaymentBlob.fromJson(jsonMap);
      // Store in the receiver's local queue — SyncEngine will submit it
      // to the backend when this device comes online.
      _queue.enqueue(blob);
      _receivedBlobCtrl.add(blob);
    } catch (_) {}
  }

  // ── Sender Role ───────────────────────────────────────────────────────────

  /// Scan for a BLE peripheral advertising [sessionUuid], connect, and write
  /// [blob] as JSON bytes.  Returns true on success.
  ///
  /// [onStatus] is called at each step so the UI can show progress.
  ///
  /// The blob must already exist in the sender's local queue before calling
  /// this method; the queue ensures it is synced to the backend even if BLE
  /// transfer fails.
  Future<bool> sendBlobViaBLE(
    PaymentBlob blob,
    String sessionUuid, {
    void Function(String step)? onStatus,
  }) async {
    if (_isSending) return false;
    _isSending = true;

    void status(String s) => onStatus?.call(s);

    try {
      final adapterState = await FlutterBluePlus.adapterState.first;
      if (adapterState != BluetoothAdapterState.on) {
        status('Bluetooth is off — please enable it and try again');
        _isSending = false;
        return false;
      }

      status('Scanning for merchant device…');

      // Scan WITHOUT a service-UUID filter.
      // iOS CBPeripheralManager can place 128-bit custom UUIDs in the
      // "overflow" area of the advertisement packet, making them invisible
      // to CoreBluetooth's withServices filter. We scan broadly and match
      // the target device client-side.
      final found = Completer<BluetoothDevice?>();
      final targetUuid = sessionUuid.toUpperCase();

      await FlutterBluePlus.startScan(
        timeout: const Duration(seconds: 20),
      );

      final scanSub = FlutterBluePlus.scanResults.listen((results) {
        if (found.isCompleted) return;
        for (final r in results) {
          // Match by service UUID (primary check)
          final uuids = r.advertisementData.serviceUuids
              .map((u) => u.toString().toUpperCase())
              .toList();
          if (uuids.contains(targetUuid)) {
            found.complete(r.device);
            return;
          }
          // Fallback: match by local name "OfflinePay" if UUID is in overflow
          if (r.advertisementData.localName == 'OfflinePay') {
            found.complete(r.device);
            return;
          }
        }
      });

      // Complete with null when scan stops (timeout).
      FlutterBluePlus.isScanning.where((s) => !s).first.then((_) {
        if (!found.isCompleted) found.complete(null);
      });

      final device = await found.future;
      scanSub.cancel();
      if (FlutterBluePlus.isScanningNow) {
        await FlutterBluePlus.stopScan();
      }

      if (device == null) {
        status('Merchant device not found — make sure their app is open on the "My QR" screen and Bluetooth is on');
        _isSending = false;
        return false;
      }

      status('Found merchant device — connecting…');

      // Connect.
      await device.connect(timeout: const Duration(seconds: 10));

      try {
        status('Connected — discovering services…');

        // Request larger MTU to reduce chunking for typical blob payloads.
        await device.requestMtu(512);

        final services = await device.discoverServices();
        final writeGuid = Guid(kBlobWriteCharUuid);
        BluetoothCharacteristic? writeChar;

        for (final svc in services) {
          for (final c in svc.characteristics) {
            if (c.uuid == writeGuid) {
              writeChar = c;
              break;
            }
          }
          if (writeChar != null) break;
        }

        if (writeChar == null) {
          status('Could not find payment characteristic on merchant device');
          await device.disconnect();
          _isSending = false;
          return false;
        }

        status('Transferring payment data…');

        // Encode blob as JSON bytes and write in ≤512-byte chunks.
        final bytes =
            Uint8List.fromList(utf8.encode(jsonEncode(blob.toJson())));
        const chunkSize = 512;
        for (int i = 0; i < bytes.length; i += chunkSize) {
          final end =
              (i + chunkSize < bytes.length) ? i + chunkSize : bytes.length;
          await writeChar.write(
            bytes.sublist(i, end),
            withoutResponse: false,
          );
        }

        await device.disconnect();
        status('Payment sent via Bluetooth!');
        _isSending = false;
        return true;
      } catch (e) {
        status('Transfer failed: $e');
        try {
          await device.disconnect();
        } catch (_) {}
        _isSending = false;
        return false;
      }
    } catch (e) {
      status('BLE error: $e');
      _isSending = false;
      return false;
    }
  }

  void dispose() {
    stopReceiving();
    _receivedBlobCtrl.close();
  }
}
