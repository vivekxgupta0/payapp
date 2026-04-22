import 'dart:async';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:image_picker/image_picker.dart';
import 'package:intl/intl.dart';
import '../../providers/auth_provider.dart';
import '../../providers/wallet_provider.dart';
import '../../providers/transaction_provider.dart';
import '../../models/transaction.dart';
import '../../models/payment_blob.dart';
import '../../services/qr_transfer.dart';
import '../../services/offline_limit_service.dart';
import '../../services/offline_queue_service.dart';
import '../../services/connectivity_service.dart';
import '../../services/api_service.dart';
import '../../services/ble_service.dart';
import '../../config/theme.dart';
import '../payment_receipt_screen.dart';

class PayScreen extends StatefulWidget {
  const PayScreen({super.key});

  @override
  State<PayScreen> createState() => _PayScreenState();
}

class _PayScreenState extends State<PayScreen> {
  final _amountCtrl = TextEditingController();
  final _scanAmountCtrl = TextEditingController();

  String? _qrData;
  bool _isProcessing = false;
  String? _error;

  MobileScannerController? _scannerCtrl;
  bool _isScanning = false;
  bool _isBLETransferring = false;
  ReceiverQRData? _scannedReceiver;

  final _limitService = OfflineLimitService();
  final _queueService = OfflineQueueService();
  final _connectivityService = ConnectivityService();
  final _bleService = BLEService();

  @override
  void dispose() {
    _amountCtrl.dispose();
    _scanAmountCtrl.dispose();
    _scannerCtrl?.dispose();
    super.dispose();
  }

  // ── Scan helpers ─────────────────────────────────────────────

  void _startScan() {
    _scannerCtrl = MobileScannerController(
      detectionSpeed: DetectionSpeed.normal,
      facing: CameraFacing.back,
    );
    setState(() {
      _isScanning = true;
      _scannedReceiver = null;
      _error = null;
    });
  }

  void _stopScan() {
    _scannerCtrl?.dispose();
    _scannerCtrl = null;
    setState(() => _isScanning = false);
  }

  Future<void> _scanFromGallery() async {
    final picker = ImagePicker();
    final picked = await picker.pickImage(source: ImageSource.gallery);
    if (picked == null) return;

    final ctrl = MobileScannerController();
    final completer = Completer<BarcodeCapture?>();
    final sub = ctrl.barcodes.listen((c) {
      if (!completer.isCompleted) completer.complete(c);
    });

    final found = await ctrl.analyzeImage(picked.path);
    BarcodeCapture? capture;
    if (found) {
      capture = await completer.future
          .timeout(const Duration(seconds: 2), onTimeout: () => null);
    }
    await sub.cancel();
    ctrl.dispose();

    if (!found || capture == null) {
      setState(() => _error = 'No QR code found in that image.');
      return;
    }

    final raw = capture.barcodes.firstOrNull?.rawValue;
    if (raw == null) {
      setState(() => _error = 'Could not read QR code.');
      return;
    }

    final receiver = QrTransferService.parseReceiveQR(raw);
    setState(() {
      _scannedReceiver = receiver;
      _error = receiver == null ? 'Invalid QR — ask the recipient to show their Paytm QR.' : null;
    });
    if (receiver != null) _showAmountDialog(receiver);
  }

  void _onQRDetected(BarcodeCapture capture) {
    final raw = capture.barcodes.firstOrNull?.rawValue;
    if (raw == null) return;
    _stopScan();

    final receiver = QrTransferService.parseReceiveQR(raw);
    if (receiver == null) {
      setState(() => _error = 'Invalid QR — ask the recipient to show their Paytm QR.');
      return;
    }
    setState(() => _scannedReceiver = receiver);
    _showAmountDialog(receiver);
  }

  Future<void> _showAmountDialog(ReceiverQRData receiver) async {
    _scanAmountCtrl.clear();
    final wallet = context.read<WalletProvider>();
    final isOnline = wallet.isOnline;
    final limit = await _limitService.getAvailableLimit();

    await showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (ctx) => Container(
        decoration: const BoxDecoration(
          color: Colors.white,
          borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
        ),
        padding: EdgeInsets.only(
          left: 24,
          right: 24,
          top: 24,
          bottom: MediaQuery.of(ctx).viewInsets.bottom + 32,
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Handle
            Center(
              child: Container(
                width: 40,
                height: 4,
                decoration: BoxDecoration(
                  color: Colors.grey.shade300,
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
            ),
            const SizedBox(height: 20),

            // Recipient
            Row(
              children: [
                CircleAvatar(
                  radius: 22,
                  backgroundColor: AppTheme.primaryColor.withOpacity(0.1),
                  child: Text(
                    receiver.receiverName.isNotEmpty
                        ? receiver.receiverName[0].toUpperCase()
                        : '?',
                    style: const TextStyle(
                      color: AppTheme.primaryColor,
                      fontWeight: FontWeight.bold,
                      fontSize: 18,
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('Paying to',
                        style: TextStyle(fontSize: 12, color: Colors.grey)),
                    Text(
                      receiver.receiverName,
                      style: const TextStyle(
                        fontSize: 17,
                        fontWeight: FontWeight.w700,
                        color: AppTheme.primaryColor,
                      ),
                    ),
                  ],
                ),
                const Spacer(),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                  decoration: BoxDecoration(
                    color: isOnline
                        ? AppTheme.successColor.withOpacity(0.1)
                        : AppTheme.offlineColor.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(20),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(
                        isOnline ? Icons.wifi : Icons.wifi_off,
                        size: 12,
                        color: isOnline ? AppTheme.successColor : AppTheme.offlineColor,
                      ),
                      const SizedBox(width: 4),
                      Text(
                        isOnline ? 'Online' : '₹${limit.toStringAsFixed(0)} limit',
                        style: TextStyle(
                          fontSize: 11,
                          fontWeight: FontWeight.w600,
                          color: isOnline ? AppTheme.successColor : AppTheme.offlineColor,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 24),

            // Amount input
            TextFormField(
              controller: _scanAmountCtrl,
              autofocus: true,
              keyboardType: const TextInputType.numberWithOptions(decimal: true),
              style: const TextStyle(
                fontSize: 36,
                fontWeight: FontWeight.w800,
                color: AppTheme.primaryColor,
              ),
              decoration: InputDecoration(
                prefixText: '₹ ',
                prefixStyle: const TextStyle(
                  fontSize: 36,
                  fontWeight: FontWeight.w800,
                  color: AppTheme.primaryColor,
                ),
                hintText: '0',
                hintStyle: TextStyle(
                  fontSize: 36,
                  fontWeight: FontWeight.w800,
                  color: Colors.grey.shade300,
                ),
                filled: true,
                fillColor: AppTheme.lightBlue,
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(14),
                  borderSide: BorderSide.none,
                ),
                enabledBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(14),
                  borderSide: BorderSide.none,
                ),
                focusedBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(14),
                  borderSide: const BorderSide(color: AppTheme.primaryColor, width: 2),
                ),
                contentPadding: const EdgeInsets.symmetric(horizontal: 20, vertical: 18),
              ),
            ),

            // Quick amounts
            const SizedBox(height: 12),
            Row(
              children: [100, 200, 500, 1000].map((v) {
                return Padding(
                  padding: const EdgeInsets.only(right: 8),
                  child: GestureDetector(
                    onTap: () => _scanAmountCtrl.text = v.toString(),
                    child: Container(
                      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
                      decoration: BoxDecoration(
                        color: AppTheme.lightBlue,
                        borderRadius: BorderRadius.circular(20),
                        border: Border.all(
                            color: AppTheme.primaryColor.withOpacity(0.2)),
                      ),
                      child: Text(
                        '₹$v',
                        style: const TextStyle(
                          fontSize: 13,
                          fontWeight: FontWeight.w600,
                          color: AppTheme.primaryColor,
                        ),
                      ),
                    ),
                  ),
                );
              }).toList(),
            ),
            const SizedBox(height: 24),

            SizedBox(
              height: 54,
              child: ElevatedButton(
                onPressed: () {
                  Navigator.pop(ctx);
                  _processOfflinePayment(receiver);
                },
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppTheme.primaryColor,
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(14),
                  ),
                ),
                child: const Text(
                  'Pay Now',
                  style: TextStyle(
                    fontSize: 17,
                    fontWeight: FontWeight.w700,
                    color: Colors.white,
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ── Payment logic ────────────────────────────────────────────

  Future<void> _processOfflinePayment(ReceiverQRData receiver) async {
    final amountStr = _scanAmountCtrl.text.trim();
    final amount = double.tryParse(amountStr);

    if (amount == null || amount <= 0) {
      setState(() => _error = 'Enter a valid amount');
      return;
    }

    setState(() {
      _isProcessing = true;
      _error = null;
    });

    final auth = context.read<AuthProvider>();
    final senderId = auth.user?.id ?? '';
    final isOnline = await _connectivityService.checkNow();

    if (isOnline) {
      await _processOnlinePayment(senderId, receiver, amount);
      return;
    }

    // Offline path
    final availableLimit = await _limitService.getAvailableLimit();
    if (amount > availableLimit) {
      setState(() {
        _error =
            'Offline limit insufficient.\nAvailable: ₹${availableLimit.toStringAsFixed(2)}  ·  Requested: ₹${amount.toStringAsFixed(2)}';
        _isProcessing = false;
      });
      return;
    }

    final blob = PaymentBlob(
      senderId: senderId,
      receiverId: receiver.receiverId,
      amount: amount,
      isOffline: true,
      offlineLimitAtTime: availableLimit,
    );

    await _queueService.enqueue(blob);
    await _limitService.deductFromLimit(amount);

    final pendingBlobs = await _queueService.getPendingBlobs();
    await _limitService.applyLocalRiskPenalty(pendingBlobs.length);

    // Refresh WalletProvider so displayed limit updates immediately
    if (mounted) await context.read<WalletProvider>().loadCachedTokens();

    bool? bleSuccess;
    if (receiver.bleUuid != null) {
      setState(() => _isBLETransferring = true);
      bleSuccess = await _runBLEWithProgress(blob, receiver.bleUuid!);
      setState(() => _isBLETransferring = false);
    }

    final receiptStatus =
        bleSuccess == true ? ReceiptStatus.sentViaBluetooth : ReceiptStatus.pendingSync;

    setState(() {
      _isProcessing = false;
      _scannedReceiver = null;
    });

    if (mounted) {
      Navigator.push(
        context,
        MaterialPageRoute(
          builder: (_) => PaymentReceiptScreen(
            amount: amount,
            recipientName: receiver.receiverName,
            paymentId: blob.id,
            status: receiptStatus,
            isOnline: false,
            timestamp: DateTime.now(),
          ),
        ),
      );
    }
  }

  /// Shows a dialog with live BLE transfer steps and returns the result.
  Future<bool> _runBLEWithProgress(PaymentBlob blob, String bleUuid) async {
    String _step = 'Initialising Bluetooth…';
    StateSetter? _dialogSetState;

    // Show progress dialog immediately
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setS) {
          _dialogSetState = setS;
          return AlertDialog(
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
            title: const Row(
              children: [
                Icon(Icons.bluetooth_searching, color: AppTheme.primaryColor),
                SizedBox(width: 10),
                Text('Sending via Bluetooth'),
              ],
            ),
            content: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const CircularProgressIndicator(),
                const SizedBox(height: 16),
                Text(
                  _step,
                  textAlign: TextAlign.center,
                  style: const TextStyle(fontSize: 14),
                ),
              ],
            ),
          );
        },
      ),
    );

    final result = await _bleService.sendBlobViaBLE(
      blob,
      bleUuid,
      onStatus: (s) {
        _step = s;
        _dialogSetState?.call(() {});
      },
    );

    // Give the user a moment to read the final status
    await Future.delayed(const Duration(milliseconds: 800));
    if (mounted && Navigator.canPop(context)) Navigator.pop(context);

    return result;
  }

  Future<void> _processOnlinePayment(
    String senderId,
    ReceiverQRData receiver,
    double amount,
  ) async {
    try {
      final blob = PaymentBlob(
        senderId: senderId,
        receiverId: receiver.receiverId,
        amount: amount,
        isOffline: false,
        offlineLimitAtTime: 0,
        status: BlobStatus.synced,
      );

      await Future.wait([
        _queueService.enqueue(blob),
        _callOnlinePaymentApi(
          receiverId: receiver.receiverId,
          receiverName: receiver.receiverName,
          amount: amount,
          nonce: blob.nonce,
        ),
      ]);

      if (mounted) await context.read<AuthProvider>().refreshUser();

      setState(() {
        _isProcessing = false;
        _scannedReceiver = null;
      });

      if (mounted) {
        Navigator.push(
          context,
          MaterialPageRoute(
            builder: (_) => PaymentReceiptScreen(
              amount: amount,
              recipientName: receiver.receiverName,
              paymentId: blob.id,
              status: ReceiptStatus.settled,
              isOnline: true,
              timestamp: DateTime.now(),
            ),
          ),
        );
      }
    } catch (e) {
      setState(() {
        _error = e.toString();
        _isProcessing = false;
      });
    }
  }

  Future<void> _callOnlinePaymentApi({
    required String receiverId,
    required String receiverName,
    required double amount,
    required String nonce,
  }) async {
    final api = ApiService();
    await api.post('/api/payments/online', {
      'receiver_id': receiverId,
      'receiver_name': receiverName,
      'amount': amount,
      'nonce': nonce,
    });
  }

  // ── Token QR generation (legacy flow) ───────────────────────

  Future<void> _generateTokenQR() async {
    setState(() {
      _error = null;
      _qrData = null;
    });

    final amountStr = _amountCtrl.text.trim();
    if (amountStr.isEmpty) {
      setState(() => _error = 'Please enter an amount');
      return;
    }

    final amount = double.tryParse(amountStr);
    if (amount == null || amount <= 0) {
      setState(() => _error = 'Enter a valid amount');
      return;
    }

    if (amount > 5000) {
      setState(() => _error = 'Maximum offline payment is ₹5,000');
      return;
    }

    setState(() => _isProcessing = true);

    try {
      final wallet = context.read<WalletProvider>();
      final auth = context.read<AuthProvider>();

      final token = await wallet.findTokenForPayment(amount);
      if (token == null) {
        setState(() {
          _error =
              'No tokens available for ₹${amount.toStringAsFixed(0)}. Connect to internet to get tokens.';
          _isProcessing = false;
        });
        return;
      }

      final qrPayload = QrTransferService.generatePaymentQR(
        token: token,
        paymentAmount: amount,
        senderName: auth.user?.fullName ?? 'User',
      );

      setState(() {
        _qrData = qrPayload;
        _isProcessing = false;
      });
    } catch (e) {
      setState(() {
        _error = 'Error: $e';
        _isProcessing = false;
      });
    }
  }

  Future<void> _confirmTokenPayment() async {
    if (_qrData == null) return;

    final wallet = context.read<WalletProvider>();
    final txProvider = context.read<TransactionProvider>();
    final auth = context.read<AuthProvider>();

    final paymentData = QrTransferService.parsePaymentQR(_qrData!);
    if (paymentData == null) return;

    await wallet.consumeToken(paymentData['token_id']);

    final tx = OfflineTransaction(
      tokenId: paymentData['token_id'],
      senderId: auth.user?.id ?? '',
      receiverName: 'Merchant',
      amount: (paymentData['amount'] as num).toDouble(),
      nonce: paymentData['nonce'],
      signature: paymentData['signature'],
      status: 'pending_offline',
    );
    await txProvider.addTransaction(tx);

    setState(() {
      _qrData = null;
      _amountCtrl.clear();
    });

    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: const Text('Payment recorded (offline)'),
          backgroundColor: AppTheme.successColor,
          behavior: SnackBarBehavior.floating,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
        ),
      );
    }
  }

  // ── Build ────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    final wallet = context.watch<WalletProvider>();

    return Scaffold(
      backgroundColor: AppTheme.surfaceColor,
      appBar: AppBar(
        title: const Text('Pay'),
        automaticallyImplyLeading: false,
        actions: [
          Padding(
            padding: const EdgeInsets.only(right: 12),
            child: Center(
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 300),
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 5),
                decoration: BoxDecoration(
                  color: wallet.isOnline
                      ? AppTheme.successColor.withOpacity(0.1)
                      : AppTheme.offlineColor.withOpacity(0.12),
                  borderRadius: BorderRadius.circular(20),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(
                      wallet.isOnline ? Icons.wifi : Icons.wifi_off,
                      size: 13,
                      color: wallet.isOnline
                          ? AppTheme.successColor
                          : AppTheme.offlineColor,
                    ),
                    const SizedBox(width: 4),
                    Text(
                      wallet.isOnline ? 'Online' : 'Offline',
                      style: TextStyle(
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
                        color: wallet.isOnline
                            ? AppTheme.successColor
                            : AppTheme.offlineColor,
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // ── Offline limit card ───────────────────────────
            _OfflineLimitCard(
              isOnline: wallet.isOnline,
              remaining: wallet.offlineLimitRemaining,
              total: wallet.offlineLimit,
            ),
            const SizedBox(height: 16),

            // ── Scan & Pay ───────────────────────────────────
            Container(
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(16),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Icon(Icons.qr_code_scanner,
                          color: AppTheme.primaryColor, size: 20),
                      const SizedBox(width: 8),
                      const Text(
                        'Scan & Pay',
                        style: TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.w700,
                          color: AppTheme.primaryColor,
                        ),
                      ),
                      const Spacer(),
                      Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 8, vertical: 3),
                        decoration: BoxDecoration(
                          color: AppTheme.lightBlue,
                          borderRadius: BorderRadius.circular(6),
                        ),
                        child: Text(
                          wallet.isOnline
                              ? 'Instant settle'
                              : 'Uses offline limit',
                          style: const TextStyle(
                            fontSize: 10,
                            fontWeight: FontWeight.w600,
                            color: AppTheme.primaryColor,
                          ),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 16),

                  // Scanner view
                  if (_isScanning) ...[
                    ClipRRect(
                      borderRadius: BorderRadius.circular(12),
                      child: SizedBox(
                        height: 260,
                        child: _scannerCtrl != null
                            ? MobileScanner(
                                controller: _scannerCtrl!,
                                onDetect: _onQRDetected,
                              )
                            : const Center(child: CircularProgressIndicator()),
                      ),
                    ),
                    const SizedBox(height: 12),
                    OutlinedButton(
                      onPressed: _stopScan,
                      style: OutlinedButton.styleFrom(
                        foregroundColor: AppTheme.primaryColor,
                        side: const BorderSide(color: AppTheme.primaryColor),
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(10),
                        ),
                      ),
                      child: const Text('Cancel Scan'),
                    ),
                  ] else ...[
                    // Scanned receiver chip
                    if (_scannedReceiver != null) ...[
                      Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 14, vertical: 10),
                        decoration: BoxDecoration(
                          color: AppTheme.lightBlue,
                          borderRadius: BorderRadius.circular(10),
                        ),
                        child: Row(
                          children: [
                            const Icon(Icons.check_circle,
                                color: AppTheme.successColor, size: 16),
                            const SizedBox(width: 8),
                            Text(
                              'Paying: ${_scannedReceiver!.receiverName}',
                              style: const TextStyle(
                                fontWeight: FontWeight.w600,
                                color: AppTheme.primaryColor,
                                fontSize: 13,
                              ),
                            ),
                            const Spacer(),
                            GestureDetector(
                              onTap: () =>
                                  setState(() => _scannedReceiver = null),
                              child: const Icon(Icons.close,
                                  size: 16, color: Colors.grey),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(height: 12),
                    ],

                    // BLE progress
                    if (_isBLETransferring) ...[
                      Container(
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: AppTheme.primaryColor.withOpacity(0.05),
                          borderRadius: BorderRadius.circular(10),
                          border: Border.all(
                              color: AppTheme.primaryColor.withOpacity(0.2)),
                        ),
                        child: const Row(
                          children: [
                            SizedBox(
                              width: 16,
                              height: 16,
                              child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                  color: AppTheme.primaryColor),
                            ),
                            SizedBox(width: 10),
                            Text(
                              'Connecting via Bluetooth…',
                              style: TextStyle(
                                  fontSize: 13, color: AppTheme.primaryColor),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(height: 12),
                    ] else if (_isProcessing) ...[
                      const Center(
                          child: Padding(
                        padding: EdgeInsets.symmetric(vertical: 8),
                        child: CircularProgressIndicator(),
                      )),
                    ],

                    // Scan buttons
                    Row(
                      children: [
                        Expanded(
                          flex: 3,
                          child: SizedBox(
                            height: 48,
                            child: ElevatedButton.icon(
                              onPressed: _isProcessing ? null : _startScan,
                              icon: const Icon(Icons.qr_code_scanner, size: 18),
                              label: const Text('Scan QR to Pay'),
                            ),
                          ),
                        ),
                        const SizedBox(width: 10),
                        SizedBox(
                          height: 48,
                          child: OutlinedButton(
                            onPressed: _isProcessing ? null : _scanFromGallery,
                            style: OutlinedButton.styleFrom(
                              foregroundColor: AppTheme.primaryColor,
                              side: const BorderSide(
                                  color: AppTheme.primaryColor),
                              shape: RoundedRectangleBorder(
                                  borderRadius: BorderRadius.circular(12)),
                              padding: const EdgeInsets.symmetric(horizontal: 14),
                            ),
                            child: const Icon(Icons.photo_library, size: 18),
                          ),
                        ),
                      ],
                    ),
                  ],
                ],
              ),
            ),

            // Error
            if (_error != null) ...[
              const SizedBox(height: 12),
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: AppTheme.errorColor.withOpacity(0.08),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(
                      color: AppTheme.errorColor.withOpacity(0.2)),
                ),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Icon(Icons.error_outline,
                        color: AppTheme.errorColor, size: 18),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        _error!,
                        style: const TextStyle(
                            color: AppTheme.errorColor, fontSize: 13),
                      ),
                    ),
                    GestureDetector(
                      onTap: () => setState(() => _error = null),
                      child: const Icon(Icons.close,
                          size: 16, color: AppTheme.errorColor),
                    ),
                  ],
                ),
              ),
            ],

            // ── Token QR (legacy / merchant-facing) ──────────
            const SizedBox(height: 16),
            _TokenQRSection(
              amountCtrl: _amountCtrl,
              qrData: _qrData,
              isProcessing: _isProcessing,
              onGenerate: _generateTokenQR,
              onConfirm: _confirmTokenPayment,
              onCancel: () => setState(() {
                _qrData = null;
                _amountCtrl.clear();
              }),
            ),
            const SizedBox(height: 32),
          ],
        ),
      ),
    );
  }
}

// ── Offline limit card ─────────────────────────────────────────────────────

class _OfflineLimitCard extends StatelessWidget {
  final bool isOnline;
  final double remaining;
  final double total;

  const _OfflineLimitCard({
    required this.isOnline,
    required this.remaining,
    required this.total,
  });

  @override
  Widget build(BuildContext context) {
    final fraction = total > 0 ? (remaining / total).clamp(0.0, 1.0) : 0.0;
    final barColor = fraction > 0.5
        ? AppTheme.successColor
        : fraction > 0.2
            ? AppTheme.warningColor
            : AppTheme.errorColor;

    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(16),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(
                isOnline ? Icons.wifi : Icons.wifi_off,
                size: 16,
                color: isOnline ? AppTheme.successColor : AppTheme.offlineColor,
              ),
              const SizedBox(width: 6),
              Text(
                isOnline ? 'Online — bank payments enabled' : 'Offline Mode',
                style: TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                  color: isOnline ? AppTheme.successColor : AppTheme.offlineColor,
                ),
              ),
            ],
          ),
          const SizedBox(height: 14),
          Row(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'Offline Credit Limit',
                    style: TextStyle(fontSize: 12, color: Colors.grey),
                  ),
                  const SizedBox(height: 2),
                  RichText(
                    text: TextSpan(
                      children: [
                        TextSpan(
                          text: '₹${remaining.toStringAsFixed(0)}',
                          style: const TextStyle(
                            fontSize: 28,
                            fontWeight: FontWeight.w800,
                            color: AppTheme.primaryColor,
                          ),
                        ),
                        TextSpan(
                          text: ' / ₹${total.toStringAsFixed(0)}',
                          style: TextStyle(
                            fontSize: 14,
                            color: Colors.grey.shade500,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
              const Spacer(),
              Column(
                crossAxisAlignment: CrossAxisAlignment.end,
                children: [
                  Text(
                    '${(fraction * 100).round()}%',
                    style: TextStyle(
                      fontSize: 22,
                      fontWeight: FontWeight.w800,
                      color: barColor,
                    ),
                  ),
                  const Text('remaining',
                      style: TextStyle(fontSize: 11, color: Colors.grey)),
                ],
              ),
            ],
          ),
          const SizedBox(height: 10),
          ClipRRect(
            borderRadius: BorderRadius.circular(4),
            child: LinearProgressIndicator(
              value: fraction,
              minHeight: 6,
              backgroundColor: Colors.grey.shade100,
              valueColor: AlwaysStoppedAnimation<Color>(barColor),
            ),
          ),
        ],
      ),
    );
  }
}

// ── Token QR section ──────────────────────────────────────────────────────

class _TokenQRSection extends StatelessWidget {
  final TextEditingController amountCtrl;
  final String? qrData;
  final bool isProcessing;
  final VoidCallback onGenerate;
  final VoidCallback onConfirm;
  final VoidCallback onCancel;

  const _TokenQRSection({
    required this.amountCtrl,
    required this.qrData,
    required this.isProcessing,
    required this.onGenerate,
    required this.onConfirm,
    required this.onCancel,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(16),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.qr_code, color: AppTheme.primaryColor, size: 20),
              const SizedBox(width: 8),
              const Text(
                'Generate Token QR',
                style: TextStyle(
                  fontSize: 16,
                  fontWeight: FontWeight.w700,
                  color: AppTheme.primaryColor,
                ),
              ),
              const Spacer(),
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: AppTheme.lightBlue,
                  borderRadius: BorderRadius.circular(6),
                ),
                child: const Text(
                  'Merchant scans you',
                  style: TextStyle(
                    fontSize: 10,
                    fontWeight: FontWeight.w600,
                    color: AppTheme.primaryColor,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 4),
          Text(
            'Show this QR to a merchant — they scan it to accept your payment.',
            style: TextStyle(fontSize: 12, color: Colors.grey.shade500),
          ),
          const SizedBox(height: 16),

          if (qrData == null) ...[
            TextFormField(
              controller: amountCtrl,
              keyboardType:
                  const TextInputType.numberWithOptions(decimal: true),
              style: const TextStyle(
                fontSize: 24,
                fontWeight: FontWeight.w700,
              ),
              decoration: const InputDecoration(
                prefixText: '₹ ',
                prefixStyle: TextStyle(
                    fontSize: 24, fontWeight: FontWeight.w700),
                hintText: '0',
              ),
            ),
            const SizedBox(height: 14),
            Row(
              children: [50, 100, 200, 500].map((v) {
                return Padding(
                  padding: const EdgeInsets.only(right: 8),
                  child: GestureDetector(
                    onTap: () => amountCtrl.text = v.toString(),
                    child: Container(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 12, vertical: 5),
                      decoration: BoxDecoration(
                        color: AppTheme.lightBlue,
                        borderRadius: BorderRadius.circular(16),
                      ),
                      child: Text('₹$v',
                          style: const TextStyle(
                              fontSize: 12,
                              fontWeight: FontWeight.w600,
                              color: AppTheme.primaryColor)),
                    ),
                  ),
                );
              }).toList(),
            ),
            const SizedBox(height: 16),
            SizedBox(
              width: double.infinity,
              height: 48,
              child: ElevatedButton.icon(
                onPressed: isProcessing ? null : onGenerate,
                icon: isProcessing
                    ? const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                          color: Colors.white,
                        ),
                      )
                    : const Icon(Icons.qr_code, size: 18),
                label: Text(isProcessing ? 'Generating…' : 'Generate QR'),
              ),
            ),
          ] else ...[
            Center(
              child: Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: AppTheme.lightBlue,
                  borderRadius: BorderRadius.circular(16),
                ),
                child: QrImageView(
                  data: qrData!,
                  version: QrVersions.auto,
                  size: 200,
                  backgroundColor: Colors.white,
                  eyeStyle: const QrEyeStyle(
                    eyeShape: QrEyeShape.circle,
                    color: AppTheme.primaryColor,
                  ),
                  dataModuleStyle: const QrDataModuleStyle(
                    dataModuleShape: QrDataModuleShape.circle,
                    color: AppTheme.primaryColor,
                  ),
                ),
              ),
            ),
            const SizedBox(height: 8),
            const Center(
              child: Text(
                'Show this to the merchant to scan',
                style: TextStyle(fontSize: 12, color: Colors.grey),
              ),
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton(
                    onPressed: onCancel,
                    style: OutlinedButton.styleFrom(
                      foregroundColor: AppTheme.primaryColor,
                      side: const BorderSide(color: AppTheme.primaryColor),
                      shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(10)),
                    ),
                    child: const Text('Cancel'),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  flex: 2,
                  child: ElevatedButton.icon(
                    onPressed: onConfirm,
                    icon: const Icon(Icons.check, size: 18),
                    label: const Text('Merchant Scanned'),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: AppTheme.successColor,
                      shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(10)),
                    ),
                  ),
                ),
              ],
            ),
          ],
        ],
      ),
    );
  }
}
